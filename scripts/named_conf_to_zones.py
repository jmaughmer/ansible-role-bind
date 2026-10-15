#!/usr/bin/env python3
"""Extract a "<zone> <file>" list from named.conf, for check_ptr_records.py
and zone_to_bind_vars.py's --zones-file.

    ./named_conf_to_zones.py /etc/named.conf -o zones.txt

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
    parser.add_argument("-o", "--output", metavar="PATH", help="write the <zone> <file> list here instead of stdout")
    parser.add_argument(
        "--zone-dir", metavar="DIR",
        help="base directory for zone file paths that aren't absolute, overriding the options { directory ...; } "
        "found in named.conf (or CWD, if that's not found either)",
    )
    parser.add_argument(
        "--zone-types", default=",".join(sorted(DEFAULT_ZONE_TYPES)), metavar="TYPE,TYPE,...",
        help=f"comma-separated zone types to include (default: {','.join(sorted(DEFAULT_ZONE_TYPES))}) — "
        "forward/hint/stub/redirect zones have no meaningful zone data file and are always skipped",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress informational messages on stderr")
    parser.add_argument(
        "--debug", action="store_true",
        help="also write the fully expanded, comment-stripped config (every include spliced in) to named.conf.expanded, for inspection",
    )
    args = parser.parse_args()

    def warn(msg):
        if not args.quiet:
            print(f"warning: {msg}", file=sys.stderr)

    wanted_types = {t.strip().lower() for t in args.zone_types.split(",") if t.strip()}

    text = load_config(args.named_conf, warn)

    if args.debug:
        debug_path = "named.conf.expanded"
        with open(debug_path, "w", encoding="utf-8") as f:
            f.write(text)
        if not args.quiet:
            print(f"wrote fully expanded config to {debug_path}", file=sys.stderr)

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
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        if not args.quiet:
            print(f"wrote {len(lines)} zone(s) to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output_text)

    if skipped_types and not args.quiet:
        print(f"({skipped_types} zone(s) skipped — type not in {sorted(wanted_types)})", file=sys.stderr)


if __name__ == "__main__":
    main()
