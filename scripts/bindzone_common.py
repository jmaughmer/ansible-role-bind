"""Shared helpers for the zone-migration scripts in this directory.

Not a standalone tool — imported by zone_to_bind_vars.py and
check_ptr_records.py so both parse zone data identically. See
scripts/README.md for what those two scripts actually do.
"""

import shutil
import subprocess
import sys


class ZoneParseError(Exception):
    pass


def die(msg):
    """Print msg to stderr and exit with status 2, the documented status for
    usage and zone-loading errors. (raise SystemExit("...") would exit 1 —
    the same status check_ptr_records.py uses for "inconsistencies found".)"""
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def find_named_checkzone(explicit_path):
    path = explicit_path or shutil.which("named-checkzone")
    if not path:
        die(
            "error: named-checkzone not found on PATH.\n"
            "       Install it (dnf install bind-utils, or bind9.16-utils on a\n"
            "       RHEL 8 host already running bind9.16) or pass --named-checkzone\n"
            "       /path/to/named-checkzone explicitly."
        )
    return path


def dump_zone_canonical(named_checkzone, zone_name, zone_file, zone_root=None):
    """Run named-checkzone -D and return its stdout as a list of lines.

    -D dumps the loaded zone in canonical format; -s full keeps every line
    self-contained (explicit owner/ttl/class on every record, no blank-owner
    inheritance or wrapped parens) — the style the BIND docs describe as
    "most suitable for processing automatically by a separate script".
    -o - writes that dump to stdout. This is also what actually resolves
    $GENERATE/multi-line records/escaping: named-checkzone uses the same
    zone-loading code named itself does, so whatever loads cleanly for named
    parses identically here.

    $INCLUDE is a separate concern: unlike named, named-checkzone never
    reads named.conf, so it has no options { directory ...; } to chdir to
    on its own — a relative $INCLUDE path inside the zone file is resolved
    against named-checkzone's own current working directory, which by
    default is wherever this script happened to be run from, not the BIND
    server's zone directory. zone_root threads through to -w, named-
    checkzone's own flag for this exact situation ("chdir to directory, so
    that relative filenames in master file $INCLUDE directives work" — the
    manpage's wording, not just this script's), so it doesn't matter what
    directory the script itself was invoked from.
    """
    cmd = [named_checkzone, "-D", "-s", "full"]
    if zone_root:
        cmd += ["-w", zone_root]
    cmd += ["-o", "-", zone_name, zone_file]
    try:
        # stdout=/stderr=PIPE, not capture_output=True (3.7+) — RHEL 8's
        # system /usr/bin/python3 is 3.6.
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    except OSError as exc:
        die(f"error: couldn't run {named_checkzone!r}: {exc}")

    if result.returncode != 0:
        die(
            f"error: named-checkzone failed loading zone '{zone_name}' from {zone_file}:\n"
            + "\n".join(f"  {line}" for line in result.stderr.splitlines())
        )

    # Records only: also drop any $ORIGIN/$TTL directive, which the full
    # style shouldn't print but which isn't a record to parse if it does.
    lines = [ln for ln in result.stdout.splitlines() if ln.strip() and not ln.lstrip().startswith((";", "$"))]
    if not lines:
        die(
            f"error: named-checkzone produced no records for zone '{zone_name}' — "
            "double check the zone name matches the file's own $ORIGIN/apex."
        )
    return lines, result.stdout


def parse_canonical_line(line, lineno):
    # maxsplit=4 so rdata (the 5th field onward) is kept intact, including
    # internal whitespace inside quoted TXT strings — re-joining split
    # tokens with a single space would silently mangle those.
    parts = line.split(None, 4)
    if len(parts) < 5:
        raise ZoneParseError(f"line {lineno}: expected 'owner ttl class type rdata', got: {line!r}")
    owner, ttl, cls, rtype, rdata = parts
    if cls.upper() != "IN":
        raise ZoneParseError(
            f"line {lineno}: class {cls!r} isn't IN — this tool only supports Internet-class "
            f"zones (the bind_dns role hardcodes IN): {line!r}"
        )
    if not ttl.isdigit():
        raise ZoneParseError(f"line {lineno}: expected a numeric TTL, got {ttl!r}: {line!r}")
    return owner, int(ttl), rtype.upper(), rdata


def relativize(owner, zone_name):
    """Turn a fully-qualified owner name into one relative to the zone apex.

    named-checkzone's canonical dump always fully qualifies owners (trailing
    dot), regardless of how many $ORIGIN changes or $INCLUDEd files were
    involved in the source — so this string operation is all that's needed
    here; no origin tracking of our own.
    """
    origin = zone_name.rstrip(".") + "."
    if owner == origin:
        return "@"
    suffix = "." + origin
    if owner.endswith(suffix):
        return owner[: -len(suffix)]
    # Owner isn't under this zone's origin at all (unusual, but not
    # impossible — e.g. a stray $ORIGIN in an $INCLUDEd file). Keep it as an
    # absolute name (valid zone-file syntax) rather than guess, and let the
    # caller warn.
    return owner


def add_common_arguments(parser):
    """zone/file positionals, -z, --zones-file, --named-checkzone, -q — shared CLI surface."""
    parser.add_argument("zone", nargs="?", help="zone name (single-zone shorthand)")
    parser.add_argument("file", nargs="?", help="path to that zone's master file (single-zone shorthand)")
    parser.add_argument(
        "-z", "--zone-file", action="append", default=[], metavar="ZONE=FILE",
        help="a zone name and file path, e.g. example.com=/var/named/example.com.zone (repeatable)",
    )
    parser.add_argument(
        "--zones-file", metavar="PATH",
        help="text file with one '<zone> <path>' pair per line (# comments and blank lines ignored)",
    )
    parser.add_argument("--named-checkzone", metavar="PATH", help="path to named-checkzone if not on PATH")
    parser.add_argument(
        "--zone-root", default="/var/named", metavar="DIR",
        help=(
            "directory named-checkzone chdirs to (-w) before loading each zone, so relative $INCLUDE "
            "paths inside zone files resolve the same way they do for the real named process — i.e. "
            "this should match named.conf's options { directory ...; } (default: /var/named, the "
            "standard RHEL location; named_conf_to_zones.py prints the actual configured value if it "
            "differs). Pass '' to disable and use named-checkzone's own cwd instead (the old behavior)."
        ),
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress informational messages on stderr")


def collect_zone_pairs(args, parser):
    """Merge the positional shorthand, repeated -z, and --zones-file into one (zone, file) list."""
    pairs = []
    if args.zone and args.file:
        pairs.append((args.zone, args.file))
    elif args.zone or args.file:
        parser.error("both zone and file are required when using the positional shorthand")

    for entry in args.zone_file:
        if "=" not in entry:
            parser.error(f"-z/--zone-file expects ZONE=FILE, got: {entry!r}")
        zone, _, path = entry.partition("=")
        pairs.append((zone, path))

    if args.zones_file:
        with open(args.zones_file, encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    parser.error(f"{args.zones_file}:{lineno}: expected '<zone> <path>', got: {line!r}")
                pairs.append((parts[0], parts[1]))

    if not pairs:
        parser.error("no zones given — use ZONE FILE, -z ZONE=FILE, or --zones-file")

    return pairs


def make_warn(quiet):
    def warn(msg):
        if not quiet:
            print(f"warning: {msg}", file=sys.stderr)

    return warn
