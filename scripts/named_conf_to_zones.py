#!/usr/bin/env python3
"""Extract the zones from named.conf: either a "<zone> <file>" list for
check_ptr_records.py and zone_to_bind_vars.py's --zones-file, or (with
--bind-zones) the bind_dns role's bind_zones YAML itself — the whole
migration for a slave/edge server, whose zones are just named.conf settings.

    ./named_conf_to_zones.py /etc/named.conf -o zones.txt
    ./named_conf_to_zones.py /etc/named.conf --bind-zones -o bind_zones.yml

Real named.conf files almost always spread one zone statement's directives
(type, file, allow-transfer, ...) across several lines, in no fixed order,
often with other { } blocks (ACLs, also-notify lists) nested inside — a
fixed-line-window grep/awk one-liner only catches `file` when it happens to
land within N lines of `zone "...` {`, and silently produces nothing for
every zone where it doesn't. This does the same job named itself does:
strip comments, follow `include "...";` statements, and track brace depth
to find each zone statement's actual boundaries regardless of formatting.
"""

import argparse
import json
import os
import posixpath
import re
import sys

# Matches a quoted string (keep, with backslash-escape awareness) OR a
# comment (drop) OR nothing else — a single left-to-right pass correctly
# leaves comment-looking text inside quoted strings (e.g. a path) alone,
# since the string alternative wins whenever a quote starts a match.
_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"' r"|//[^\n]*" r"|#[^\n]*" r"|/\*.*?\*/", re.DOTALL
)

# Keywords are matched with (?<![\w-]) in front rather than \b: \b also
# matches right after a hyphen, so \bdirectory would match inside
# managed-keys-directory/key-directory/geoip-directory and pick up the wrong
# path if one of those came before directory in options { }.
_KW = r"(?<![\w-])"
_INCLUDE_RE = re.compile(_KW + r'include\s+"([^"]*)"\s*;')
# Zone names are "astrings" in BIND's grammar — quoting them is optional, so
# `zone example.com { ... };` is just as valid as `zone "example.com" { ... };`.
_ZONE_START_RE = re.compile(
    _KW + r'zone\s+(?:"([^"]*)"|([^\s"{};]+))(?:\s+(?:in|chaos|ch|hesiod|hs))?\s*\{', re.IGNORECASE
)
_OPTIONS_START_RE = re.compile(_KW + r"options\s*\{", re.IGNORECASE)
_TYPE_RE = re.compile(_KW + r"type\s+([A-Za-z][\w-]*)\s*;", re.IGNORECASE)
_FILE_RE = re.compile(_KW + r'file\s+"([^"]*)"\s*;', re.IGNORECASE)
_DIRECTORY_RE = re.compile(_KW + r'directory\s+"([^"]*)"\s*;', re.IGNORECASE)

DEFAULT_ZONE_TYPES = {"master", "slave"}
# What --bind-zones migrates: every zone type the bind_dns role models.
BIND_ZONES_TYPES = {"master", "slave", "forward"}
# BIND 9.16+ spells master/slave primary/secondary; both mean the same.
TYPE_SYNONYMS = {"primary": "master", "secondary": "slave"}


def strip_comments(text):
    def repl(m):
        s = m.group(0)
        if s.startswith('"'):
            return s
        return "\n" * s.count("\n")  # preserve line count for readable error messages

    return _COMMENT_OR_STRING_RE.sub(repl, text)


def load_config(path, warn, seen=None):
    """Read path, strip comments, and recursively splice in include "...";
    targets (resolved relative to the including file's own directory,
    matching named's own include-resolution behavior). Returns one flat,
    comment-free string with every include expanded in place.
    """
    abspath = os.path.abspath(path)
    seen = seen or set()
    if abspath in seen:
        raise SystemExit(f"error: circular include detected involving {path}")
    seen = seen | {abspath}

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as exc:
        raise SystemExit(f"error: couldn't read {path}: {exc}")

    cleaned = strip_comments(text)
    base_dir = os.path.dirname(abspath)

    def expand(m):
        inc_path = m.group(1)
        if not os.path.isabs(inc_path):
            inc_path = os.path.join(base_dir, inc_path)
        if not os.path.isfile(inc_path):
            warn(f"{path}: include {inc_path!r} not found — skipping it, its zones will be missing")
            return ""
        return load_config(inc_path, warn, seen)

    return _INCLUDE_RE.sub(expand, cleaned)


def find_balanced_block(text, open_brace_pos):
    """Given the index of an opening '{', return the index just past its
    matching '}' (simple depth counting — comments are already stripped
    and strings can't contain unescaped braces, so this is safe)."""
    depth = 0
    i = open_brace_pos
    n = len(text)
    while i < n:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def find_options_directory(text):
    m = _OPTIONS_START_RE.search(text)
    if not m:
        return None
    end = find_balanced_block(text, m.end() - 1)
    if end is None:
        return None
    body = text[m.end() : end - 1]
    dm = _DIRECTORY_RE.search(body)
    return dm.group(1) if dm else None


def find_zones(text):
    """Yield (zone_name, type, file) for every zone "..." { ... }; block in
    text, wherever it appears (including inside a view { } block — this
    script only extracts the list, it doesn't interpret views)."""
    for m in _ZONE_START_RE.finditer(text):
        zone_name = m.group(1) if m.group(1) is not None else m.group(2)
        open_pos = m.end() - 1
        end = find_balanced_block(text, open_pos)
        if end is None:
            raise SystemExit(f"error: zone \"{zone_name}\" block never closes (unbalanced braces)")
        body = text[open_pos + 1 : end - 1]
        type_m = _TYPE_RE.search(body)
        file_m = _FILE_RE.search(body)
        ztype = type_m.group(1).lower() if type_m else None
        ztype = TYPE_SYNONYMS.get(ztype, ztype)
        zfile = file_m.group(1) if file_m else None
        yield zone_name, ztype, zfile


def resolve_zone_path(zfile, directory, zone_dir_override):
    # posixpath, not os.path: these are paths on the (Linux) BIND host
    # described by named.conf, not paths on whatever platform this script
    # happens to run on — joining them with os.path would mix separator
    # styles if this is ever run somewhere other than Linux.
    base = zone_dir_override or directory
    if posixpath.isabs(zfile) or not base:
        return zfile
    return posixpath.join(base, zfile)


# ---------------------------------------------------------------------------
# --bind-zones: named.conf zone statements -> the role's bind_zones YAML
# ---------------------------------------------------------------------------
BUILTIN_ACLS = {"any", "none", "localhost", "localnets"}
# RHEL's stock named.rfc1912.zones (and named.conf's localhost zones): local
# boilerplate every RHEL server already has, not zones to migrate.
STOCK_ZONES = {"localhost", "localhost.localdomain", "1.0.0.127.in-addr.arpa", "0.in-addr.arpa",
               "1." + "0." * 31 + "ip6.arpa"}
_ADDR_RE = re.compile(r"^!?(?:[0-9]{1,3}(?:\.[0-9]{1,3}){0,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)(?:/\d+)?$")


def split_statements(body):
    """Split a block's text into its top-level statements (each without the
    trailing ';'), keeping nested { } blocks and quoted strings intact."""
    out, depth, start, i, n = [], 0, 0, 0, len(body)
    while i < n:
        c = body[i]
        if c == '"':
            j = i + 1
            while j < n and body[j] != '"':
                j += 2 if body[j] == "\\" else 1
            i = j
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == ";" and depth == 0:
            stmt = body[start:i].strip()
            if stmt:
                out.append(stmt)
            start = i + 1
        i += 1
    tail = body[start:].strip()
    if tail:
        out.append(tail)
    return out


def parse_statement(stmt):
    """'keyword args... [{ items }]' -> (keyword, args, items or None).
    args are the words before the block (or the whole value when there is no
    block); items are the block's own statements, whitespace-normalized."""
    brace = stmt.find("{")
    if brace < 0:
        words = stmt.split()
        return words[0].lower(), words[1:], None
    head = stmt[:brace].split()
    inner = stmt[brace + 1:stmt.rindex("}")]
    return head[0].lower(), head[1:], [" ".join(s.split()) for s in split_statements(inner)]


def unquote(word):
    return word[1:-1] if len(word) >= 2 and word[0] == word[-1] == '"' else word


def with_port(items, args):
    """Apply a block-level 'port N' (masters port 5353 { ... };) to each entry
    that doesn't name its own port."""
    if "port" not in args or args.index("port") + 1 >= len(args):
        return items
    port = args[args.index("port") + 1]
    out = []
    for item in items:
        if " port " in f" {item} ":
            out.append(item)
            continue
        addr, _, rest = item.partition(" ")
        out.append(f"{addr} port {port}" + (f" {rest}" if rest else ""))
    return out


def collect_top_level(text):
    """Top-level definitions the zones refer to: acl and masters/primaries
    lists, options' allow-transfer, and every zone (with the view it's in)."""
    acls, masters_lists, zones = {}, {}, []
    options = {"allow-transfer": None, "recursion": "yes"}   # recursion defaults to yes in BIND

    def walk(statements, view=None):
        for stmt in statements:
            kw, args, items = parse_statement(stmt)
            if kw == "acl" and args and items is not None:
                acls[unquote(args[0])] = items
            elif kw in ("masters", "primaries") and args and items is not None and args[0] != "port":
                masters_lists[unquote(args[0])] = with_port(items, args[1:])
            elif kw == "options" and items is not None:
                for sub in items:
                    skw, sargs, sitems = parse_statement(sub)
                    if skw == "allow-transfer" and sitems is not None:
                        options["allow-transfer"] = sitems
                    elif skw == "recursion" and sargs:
                        options["recursion"] = sargs[0].lower()
            elif kw == "view" and items is not None:
                walk(items, view=unquote(args[0]) if args else "?")
            elif kw == "zone" and args and items is not None:
                zones.append((unquote(args[0]), items, view))

    walk(split_statements(text))
    return acls, masters_lists, zones, options


def expand_masters(items, masters_lists, warn, zone, depth=0):
    """Replace references to named masters/primaries lists with their entries."""
    out = []
    for item in items:
        first = unquote(item.split(" ", 1)[0])
        if not _ADDR_RE.match(first) and first in masters_lists and depth < 8:
            out += expand_masters(masters_lists[first], masters_lists, warn, zone, depth + 1)
        else:
            if not _ADDR_RE.match(first):
                warn(f'zone "{zone}": masters entry {item!r} is neither an address nor a known masters list — kept as-is')
            out.append(item)
    return out


def referenced_acls(items, acls, found=None):
    """Names of the named.conf ACLs an address match list uses, recursively."""
    found = set() if found is None else found
    for item in items:
        word = unquote(item.lstrip("!").split(" ", 1)[0])
        if item.lstrip("!").startswith("key ") or _ADDR_RE.match(word) or word in BUILTIN_ACLS:
            continue
        if word in acls and word not in found:
            found.add(word)
            referenced_acls(acls[word], acls, found)
    return found


def tsig_keys(items):
    return sorted({m.group(1) for i in items for m in re.finditer(r'(?<![\w-])key\s+"?([^\s";]+)"?', i)})


def convert_zones(text, wanted_types, warn, keep_stock=False):
    """Return (zones, acl_defs, tsig_keys): bind_zones entries as (dict,
    comment lines) pairs, the named.conf ACLs they reference, and the TSIG
    keys they mention."""
    acls, masters_lists, zone_stmts, options = collect_top_level(text)
    global_xfer = options["allow-transfer"]
    out, acls_needed, keys_needed, skipped, stock = [], set(), set(), {}, []
    xfer_lists = {}   # tuple(elements) -> generated ACL name

    def transfer_acl(elements, zone):
        """The role's allow_transfer_acl takes one ACL name (or any/none). A
        single element is used as-is; a longer list becomes a generated ACL."""
        acls_needed.update(referenced_acls(elements, acls))
        if len(elements) == 1 and not elements[0].startswith(("key ", "!")):
            return unquote(elements[0])
        key = tuple(elements)
        if key not in xfer_lists:
            xfer_lists[key] = f"xfer_{len(xfer_lists) + 1}"
        return xfer_lists[key]

    seen = set()
    for name, items, view in zone_stmts:
        opts = {}
        for stmt in items:
            kw, args, sub = parse_statement(stmt)
            opts[kw] = (args, sub)
        ztype = (opts.get("type", ([None], None))[0] or [None])[0]
        ztype = TYPE_SYNONYMS.get(ztype.lower(), ztype.lower()) if ztype else None
        if ztype not in wanted_types:
            skipped.setdefault(ztype or "(no type)", []).append(name)
            continue
        if name.lower().rstrip(".") in STOCK_ZONES and not keep_stock:
            stock.append(name)
            continue
        if name in seen:
            warn(f'zone "{name}" is defined more than once (views?) — only the first is migrated')
            continue
        seen.add(name)

        entry, notes = {"name": name, "type": ztype}, []
        if view:
            notes.append(f"from view {view!r}: the bind_dns role has no views")
        handled = {"type", "file"}

        if ztype == "slave":
            m_args, m_items = opts.get("masters") or opts.get("primaries") or ([], None)
            handled |= {"masters", "primaries"}
            if not m_items:
                warn(f'zone "{name}": slave zone without masters — migrated with an empty list, fill it in')
                m_items = []
            entry["masters"] = expand_masters(with_port(m_items, m_args), masters_lists, warn, name)
            keys_needed.update(tsig_keys(entry["masters"]))
        elif ztype == "forward":
            handled |= {"forwarders", "forward"}
            f_args, f_items = opts.get("forwarders", ([], []))
            entry["forwarders"] = with_port(f_items or [], f_args)
            # BIND's default for a forward zone is "first"; the role's is "only".
            entry["forward_policy"] = (opts.get("forward", (["first"], None))[0] or ["first"])[0].lower()
            if options["recursion"] == "no":
                notes.append("the source has recursion off, so this zone never forwarded anything there; the "
                             "role only accepts forward zones on hosts with recursion on")
        elif ztype == "master" and "file" in opts:
            fname = posixpath.basename(unquote(opts["file"][0][0]))
            entry["file"] = fname
            notes.append(f"zone data: copy {unquote(opts['file'][0][0])} into bind_zones_dir as {fname}, "
                         "or convert it with zone_to_bind_vars.py")

        if ztype in ("master", "slave"):
            handled.add("allow-transfer")
            elements = opts["allow-transfer"][1] if "allow-transfer" in opts else global_xfer
            if elements is None:
                entry["allow_transfer_acl"] = "any"
                notes.append("allow-transfer not set on the source, so BIND allowed transfers to anyone — "
                             "tighten allow_transfer_acl")
            else:
                entry["allow_transfer_acl"] = transfer_acl(elements, name)
                keys_needed.update(tsig_keys(elements))
            if "also-notify" in opts:
                handled.add("also-notify")
                a_args, a_items = opts["also-notify"]
                entry["also_notify"] = expand_masters(with_port(a_items or [], a_args), masters_lists, warn, name)
            if "notify" in opts:
                handled.add("notify")
                value = (opts["notify"][0] or [""])[0].lower()
                if value in ("yes", "no"):
                    entry["notify"] = value == "yes"
                else:
                    notes.append(f"notify {value}: the role only sets notify yes/no — left at its default")
        if "zone-statistics" in opts:
            handled.add("zone-statistics")
            value = (opts["zone-statistics"][0] or [""])[0].lower()
            if value in ("yes", "full", "no", "none"):
                entry["zone_statistics"] = value in ("yes", "full")

        rest = [stmt for stmt in items if parse_statement(stmt)[0] not in handled]
        if rest:
            notes.append("not migrated: " + "; ".join(" ".join(s.split()) for s in rest))
        out.append((entry, notes))

    if stock:
        warn(f"{len(stock)} RHEL stock zone(s) skipped ({', '.join(stock)}): every RHEL server already has "
             "them. --include-stock-zones keeps them")
    for ztype, names in sorted(skipped.items()):
        warn(f"{len(names)} zone(s) of type {ztype} skipped (the bind_dns role models master, slave and forward): "
             + ", ".join(names[:5]) + (" ..." if len(names) > 5 else ""))
    acl_defs = {n: acls[n] for n in sorted(acls_needed)}
    for elements, acl_name in xfer_lists.items():
        acl_defs[acl_name] = list(elements)
    if keys_needed:
        warn("TSIG key(s) " + ", ".join(sorted(keys_needed)) + " are used by masters/allow-transfer but the bind_dns "
             "role doesn't define TSIG keys — add the key { } statements to the new servers yourself, or named "
             "won't load the config")
    return out, acl_defs, sorted(keys_needed)


def y(value):
    """One YAML scalar or flow sequence. JSON is valid YAML, and quoting every
    string keeps names like 'on' or '0.10.in-addr.arpa' from being retyped."""
    return json.dumps(value)


ZONE_KEYS = ("name", "type", "file", "masters", "forwarders", "forward_policy", "allow_transfer_acl",
             "also_notify", "notify", "zone_statistics")
# Keyword-like values that read better bare; everything else is quoted.
BARE_KEYS = {"type", "forward_policy", "allow_transfer_acl"}


def zones_yaml(zones, indent="  "):
    lines = []
    for entry, notes in zones:
        for note in notes:
            lines.append(f"{indent}# {note}")
        prefix = "- "
        for key in ZONE_KEYS:
            if key not in entry:
                continue
            value = entry[key]
            bare = key in BARE_KEYS and re.match(r"^[A-Za-z][A-Za-z0-9_-]*$", value) and \
                value.lower() not in ("yes", "no", "on", "off", "true", "false", "null")
            lines.append(f"{indent}{prefix}{key}: {value if bare else y(value)}")
            prefix = "  "
    return lines


def acls_yaml(acl_defs, keys):
    if not acl_defs:
        return []
    lines = ["# ACLs the zones above reference, from the source named.conf (xfer_N: generated for",
             "# allow-transfer lists of more than one element). Merge into bind_acls alongside the",
             "# role's own trusted / transfer_hosts / recursion_clients / dns64_clients entries.",
             "bind_acls:"]
    if keys:
        lines.insert(3, "# They mention TSIG key(s) " + ", ".join(keys) + ": define those on the new servers.")
    for name, elements in acl_defs.items():
        lines.append(f"  {y(name)}: {y(elements)}")
    return lines


def write_bind_zones(zones, acl_defs, keys, args, source):
    header = [f"# Generated by named_conf_to_zones.py --bind-zones from {source}.",
              "# Review before use: comments mark anything that couldn't be carried over."]
    if args.split_output:
        os.makedirs(args.split_output, exist_ok=True)
        for entry, notes in zones:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", entry["name"].strip(".") or "root")
            # A one-zone list: bind_zones_vars_dir reads a zone dict or a list of them.
            body = zones_yaml([(entry, notes)], indent="")
            with open(os.path.join(args.split_output, safe + ".yml"), "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(header + ["---"] + body) + "\n")
        if acl_defs:
            with open(os.path.join(args.split_output, "bind_acls.yml.txt"), "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(header + acls_yaml(acl_defs, keys)) + "\n")
        return f"{len(zones)} zone file(s) in {args.split_output}" + (" (+ bind_acls.yml.txt)" if acl_defs else "")
    text = "\n".join(header + ["---"] + acls_yaml(acl_defs, keys) + ["bind_zones:"] + zones_yaml(zones)) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        return f"{len(zones)} zone(s) to {args.output}"
    sys.stdout.write(text)
    return None


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  ./named_conf_to_zones.py /etc/named.conf -o zones.txt
  ./named_conf_to_zones.py /etc/named.conf --zone-dir /var/named -o zones.txt
  ./check_ptr_records.py --zones-file zones.txt
  ./zone_to_bind_vars.py --zones-file zones.txt -o bind_zones.yml
""",
    )
    parser.add_argument("named_conf", nargs="?", default="/etc/named.conf", help="path to named.conf (default: /etc/named.conf)")
    parser.add_argument("-o", "--output", metavar="PATH",
                        help="write the <zone> <file> list (or, with --bind-zones, the YAML) here instead of stdout")
    parser.add_argument(
        "--zone-dir", metavar="DIR",
        help="base directory for zone file paths that aren't absolute, overriding the options { directory ...; } "
        "found in named.conf (or CWD, if that's not found either)",
    )
    parser.add_argument(
        "--zone-types", metavar="TYPE,TYPE,...",
        help=f"comma-separated zone types to include (default: {','.join(sorted(DEFAULT_ZONE_TYPES))}, or "
        f"{','.join(sorted(BIND_ZONES_TYPES))} with --bind-zones). primary/secondary count as master/slave. "
        "The zones.txt list has no use for forward/hint/stub/redirect zones: they have no zone data file",
    )
    parser.add_argument(
        "--bind-zones", action="store_true",
        help="write the bind_dns role's bind_zones YAML (plus the bind_acls the zones reference) instead of a "
        "zones.txt list: slave zones with their masters, forward zones with their forwarders and policy, master "
        "zones' settings, and allow-transfer/also-notify/notify/zone-statistics",
    )
    parser.add_argument(
        "--split-output", metavar="DIR",
        help="with --bind-zones: one file per zone in DIR, the layout bind_zones_vars_dir reads, instead of one "
        "file (referenced ACLs go to DIR/bind_acls.yml.txt — .txt so bind_zones_vars_dir doesn't read it)",
    )
    parser.add_argument(
        "--include-stock-zones", action="store_true",
        help="with --bind-zones: also migrate RHEL's stock localhost/loopback zones (named.rfc1912.zones), "
        "which are skipped by default",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress informational messages on stderr")
    parser.add_argument(
        "--debug", action="store_true",
        help="also write the fully expanded, comment-stripped config (every include spliced in) to named.conf.expanded, for inspection",
    )
    args = parser.parse_args()
    if args.split_output and not args.bind_zones:
        parser.error("--split-output needs --bind-zones")
    if args.split_output and args.output:
        parser.error("-o/--output and --split-output are mutually exclusive")

    def warn(msg):
        if not args.quiet:
            print(f"warning: {msg}", file=sys.stderr)

    default_types = BIND_ZONES_TYPES if args.bind_zones else DEFAULT_ZONE_TYPES
    wanted_types = {TYPE_SYNONYMS.get(t.strip().lower(), t.strip().lower())
                    for t in (args.zone_types or ",".join(default_types)).split(",") if t.strip()}

    text = load_config(args.named_conf, warn)

    if args.debug:
        debug_path = "named.conf.expanded"
        with open(debug_path, "w", encoding="utf-8") as f:
            f.write(text)
        if not args.quiet:
            print(f"wrote fully expanded config to {debug_path}", file=sys.stderr)

    if args.bind_zones:
        zones, acl_defs, keys = convert_zones(text, wanted_types & BIND_ZONES_TYPES, warn, args.include_stock_zones)
        if not zones:
            raise SystemExit(f"error: no master, slave or forward zones found in {args.named_conf} (after following includes)")
        done = write_bind_zones(zones, acl_defs, keys, args, args.named_conf)
        if done and not args.quiet:
            print(f"wrote {done}", file=sys.stderr)
        return

    directory = find_options_directory(text)
    if not directory and not args.zone_dir and not args.quiet:
        print(
            "warning: no options { directory \"...\"; } found and --zone-dir not given — "
            "relative zone file paths will be left as-is, relative to wherever you run the "
            "downstream scripts from",
            file=sys.stderr,
        )
    elif directory and not args.quiet:
        effective = args.zone_dir or directory
        note = "" if effective == "/var/named" else " — pass this as --zone-root to check_ptr_records.py/zone_to_bind_vars.py if it's not /var/named (their default)"
        print(f"detected options {{ directory \"{effective}\"; }}{note}", file=sys.stderr)

    seen_pairs = set()
    seen_names = {}
    lines = []
    skipped_types = 0

    for zone_name, ztype, zfile in find_zones(text):
        if ztype not in wanted_types:
            if ztype not in (None,):
                skipped_types += 1
            continue
        if not zfile:
            warn(f'zone "{zone_name}": type {ztype} has no file "..."; statement — skipped')
            continue

        resolved = resolve_zone_path(zfile, directory, args.zone_dir)
        pair = (zone_name, resolved)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        if zone_name in seen_names and seen_names[zone_name] != resolved:
            warn(
                f'zone "{zone_name}" appears more than once with different file paths '
                f"({seen_names[zone_name]!r} and {resolved!r}) — likely a split-horizon/views config, "
                "which this role doesn't model; both are listed, pick the right one by hand"
            )
        seen_names[zone_name] = resolved

        lines.append(f"{zone_name} {resolved}")

    if not lines:
        raise SystemExit(
            f"error: no zones found in {args.named_conf} (after following includes) with "
            f"type in {sorted(wanted_types)} and a file \"...\"; statement. Check --zone-types "
            "if this host uses zone types other than master/slave, or verify the file actually "
            "contains zone { } statements (not just includes this tool couldn't resolve)."
        )

    output_text = "\n".join(lines) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(output_text)
        if not args.quiet:
            print(f"wrote {len(lines)} zone(s) to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output_text)

    if skipped_types and not args.quiet:
        print(f"({skipped_types} zone(s) skipped — type not in {sorted(wanted_types)})", file=sys.stderr)


if __name__ == "__main__":
    main()
