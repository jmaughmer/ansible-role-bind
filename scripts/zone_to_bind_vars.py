#!/usr/bin/env python3
"""Convert existing BIND master zone files into bind_dns role `bind_zones` YAML.

See scripts/README.md for full documentation. Quick start:

    ./zone_to_bind_vars.py example.com /var/named/example.com.zone

Requires named-checkzone (bind-utils / bind9.16-utils) on PATH — used to
resolve $INCLUDE/$GENERATE/multi-line records/escaping exactly the way
named itself does, instead of re-implementing an RFC1035 parser here.
"""

import argparse
import glob
import os
import re
import sys

from bindzone_common import (
    ZoneParseError,
    add_common_arguments,
    collect_zone_pairs,
    die,
    dump_zone_canonical,
    find_named_checkzone,
    make_warn,
    parse_canonical_line,
    relativize,
)

# https://www.iana.org/assignments/dns-sec-alg-numbers/ — used only to turn
# a numeric DNSKEY algorithm into the mnemonic name dnssec-policy expects
# (e.g. bind_dnssec_policies.*.keys[].algorithm: ecdsap256sha256).
DNSSEC_ALGORITHMS = {
    1: "rsamd5",
    2: "dh",
    3: "dsa",
    5: "rsasha1",
    6: "dsa-nsec3-sha1",
    7: "rsasha1-nsec3-sha1",
    8: "rsasha256",
    10: "rsasha512",
    12: "ecc-gost",
    13: "ecdsap256sha256",
    14: "ecdsap384sha384",
    15: "ed25519",
    16: "ed448",
}

# Record types that BIND's dnssec-policy + inline-signing regenerates and
# manages itself once this role turns DNSSEC signing on. Reproducing these
# from an old manually-signed zone would just be immediately overwritten
# (or, worse, fought over) by named, so they're dropped from the emitted
# `records:` list rather than carried across.
DNSSEC_MANAGED_TYPES = {"DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "CDS", "CDNSKEY"}

KEY_FILENAME_RE = re.compile(r"^K(?P<name>.+)\.\+(?P<alg>\d{3})\+(?P<keyid>\d{5})\.key$")


def yaml_str(value):
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def parse_zone(named_checkzone, zone_name, zone_file, warn, zone_root=None):
    lines, raw_dump = dump_zone_canonical(named_checkzone, zone_name, zone_file, zone_root)

    soa = None
    apex_nameservers = []
    records = []
    inline_dnskeys = []
    excluded_count = 0

    for lineno, line in enumerate(lines, start=1):
        try:
            owner, ttl, rtype, rdata = parse_canonical_line(line, lineno)
        except ZoneParseError as exc:
            die(
                f"error: couldn't parse named-checkzone output for zone '{zone_name}' ({exc}).\n"
                "       Re-run with --debug to save the raw dump and inspect it — the parser\n"
                "       expects named-checkzone's '-s full' canonical style; if your build\n"
                "       emits something else, this is where to compare against."
            )

        relname = relativize(owner, zone_name)
        if relname == owner and owner != zone_name.rstrip(".") + ".":
            warn(f"{zone_name}: owner {owner!r} is not inside this zone's origin — kept as an absolute name")

        if rtype == "SOA":
            if soa is not None:
                warn(f"{zone_name}: multiple SOA records found; using the first")
                continue
            soa = (ttl, rdata)
            continue

        if rtype == "NS" and relname == "@":
            apex_nameservers.append(rdata.rstrip(".") if rdata.endswith(".") else rdata)
            continue

        if rtype == "DNSKEY":
            inline_dnskeys.append(rdata)
            excluded_count += 1
            continue

        if rtype in DNSSEC_MANAGED_TYPES:
            excluded_count += 1
            continue

        records.append({"name": relname, "type": rtype, "value": rdata, "ttl": ttl})

    if soa is None:
        die(f"error: no SOA record found for zone '{zone_name}' — is this really a zone file?")
    if not apex_nameservers:
        warn(f"{zone_name}: no apex NS records found — nameservers: will be empty; check the zone file")

    soa_ttl, soa_rdata = soa
    soa_fields = soa_rdata.split()
    if len(soa_fields) != 7:
        die(
            f"error: zone '{zone_name}' SOA rdata has {len(soa_fields)} fields, expected 7 "
            f"(mname rname serial refresh retry expire minimum): {soa_rdata!r}"
        )
    mname, rname, serial, refresh, retry, expire, minimum = soa_fields

    # Records whose own TTL differs from the zone's default get an
    # auto-generated `comment:` flagging it — the generic records: shape
    # this role uses has no per-record TTL override, so that detail would
    # otherwise be silently flattened away during migration.
    for rec in records:
        if rec["ttl"] != soa_ttl:
            rec["comment"] = f"TTL {rec['ttl']}s differs from zone default {soa_ttl}s — review"
        del rec["ttl"]

    zone = {
        "name": zone_name,
        "primary_ns": mname.rstrip("."),
        "admin_email": rname.rstrip("."),
        "ttl": soa_ttl,
        "serial": int(serial),
        "refresh": int(refresh),
        "retry": int(retry),
        "expire": int(expire),
        "negative_ttl": int(minimum),
        "nameservers": apex_nameservers,
        "records": records,
    }
    return zone, inline_dnskeys, excluded_count, raw_dump


def parse_key_file(path):
    m = KEY_FILENAME_RE.match(os.path.basename(path))
    keyid = m.group("keyid") if m else None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        return {"path": path, "keyid": keyid, "error": str(exc)}

    for line in content.splitlines():
        if " DNSKEY " in line.upper() and not line.lstrip().startswith(";"):
            parts = line.split()
            try:
                idx = [p.upper() for p in parts].index("DNSKEY")
                flags = int(parts[idx + 1])
                algorithm = int(parts[idx + 3])
            except (ValueError, IndexError):
                continue
            role = "ksk" if flags == 257 else "zsk" if flags == 256 else f"flags={flags}"
            return {
                "path": path,
                "keyid": keyid,
                "role": role,
                "algorithm_num": algorithm,
                "algorithm_name": DNSSEC_ALGORITHMS.get(algorithm, f"algorithm-{algorithm}"),
            }
    return {"path": path, "keyid": keyid, "error": "no DNSKEY line found in file"}


def find_key_files(zone_name, search_dirs):
    found = []
    pattern_stem = "K" + glob.escape(zone_name.rstrip(".")) + ".+*.key"
    for d in search_dirs:
        if not d or not os.path.isdir(d):
            continue
        for path in sorted(glob.glob(os.path.join(d, pattern_stem))):
            found.append(parse_key_file(path))
    return found


def parse_inline_dnskeys(rdata_list):
    parsed = []
    for rdata in rdata_list:
        parts = rdata.split()
        if len(parts) < 3:
            continue
        try:
            flags, protocol, algorithm = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError:
            continue
        role = "ksk" if flags == 257 else "zsk" if flags == 256 else f"flags={flags}"
        parsed.append(
            {
                "role": role,
                "algorithm_num": algorithm,
                "algorithm_name": DNSSEC_ALGORITHMS.get(algorithm, f"algorithm-{algorithm}"),
            }
        )
    return parsed


DNSSEC_INTRO_COMMENT = """\
# ---------------------------------------------------------------------------
# DNSSEC: converting from manually-managed keys to BIND 9.16 dnssec-policy
# ---------------------------------------------------------------------------
# One or more of the zones below had an existing KSK/ZSK on disk or signed
# into the zone file — meaning the old server managed DNSSEC by hand
# (dnssec-keygen + dnssec-signzone, or `auto-dnssec maintain;`), not with
# the automatic dnssec-policy/inline-signing this role uses. Per-zone
# findings and a suggested bind_dnssec_policies starting point are noted
# above each affected zone below. Two ways to bring a zone across:
#
#   1. Fresh keys (simpler). Set dnssec: true + bind_dnssec_enable_signing:
#      true and let this role's dnssec-policy generate brand new keys.
#      named will NOT reuse the old ones automatically. This means a new DS
#      record for the parent zone/registrar — publish it, wait for the old
#      one to expire from caches (past its DS TTL) before removing the old
#      key material, and expect a short validation gap if you don't
#      sequence that carefully. Simplest option if this zone doesn't
#      currently have DS records published (i.e. isn't actually validated
#      today), or a brief signing gap is acceptable.
#
#   2. Reuse the existing keys (continuity, no new DS record needed). Copy
#      the *.key/*.private files found below into this role's
#      bind_dnssec_keys_dir (/var/named/keys by default) BEFORE the first
#      run that enables dnssec-policy on this zone, keeping their exact
#      filenames (K<zone>.+<alg>+<keyid>.{key,private}). BIND 9.16's KASP
#      engine can adopt pre-existing, correctly-named keys instead of
#      generating new ones. Old dnssec-keygen output has no .state file;
#      test this on a staging/non-production zone first to confirm your
#      BIND version adopts it the way you expect before relying on it for
#      a zone with a live DS record.
#
# Either way, remove any `auto-dnssec`, `update-policy`, or manual
# dnssec-signzone automation (cron jobs, etc.) for these zones from the old
# server — dnssec-policy + inline-signing replaces all of that.
# ---------------------------------------------------------------------------
"""


def zone_dnssec_comment(zone_name, key_findings):
    if not key_findings:
        return None
    lines = [f"  # DNSSEC key material found for {zone_name}:"]
    seen_roles = set()
    for kf in key_findings:
        if "error" in kf:
            lines.append(f"  #   - {kf.get('path', '(inline)')}: {kf['error']}")
            continue
        loc = kf.get("path", "inline in zone file")
        keyid = f", keyid {kf['keyid']}" if kf.get("keyid") else ""
        lines.append(f"  #   - {kf['role'].upper()} algorithm {kf['algorithm_name']} ({loc}{keyid})")
        if kf.get("role") in ("ksk", "zsk"):
            seen_roles.add((kf["role"], kf["algorithm_name"]))

    if seen_roles:
        algs = {alg for _, alg in seen_roles}
        alg = sorted(algs)[0] if len(algs) == 1 else "ecdsap256sha256"
        if len(algs) > 1:
            lines.append(f"  #   NOTE: mixed algorithms found ({', '.join(sorted(algs))}) — pick one below.")
        lines.append(f"  # Suggested starting policy (adjust lifetimes to your actual rollover cadence):")
        lines.append(f"  #   bind_dnssec_policies:")
        lines.append(f"  #     {zone_name.replace('.', '_')}_migrated:")
        lines.append(f"  #       keys:")
        lines.append(f'  #         - {{ role: ksk, lifetime: P1Y, algorithm: {alg} }}')
        lines.append(f'  #         - {{ role: zsk, lifetime: P30D, algorithm: {alg} }}')
    return "\n".join(lines)


def safe_zone_filename(zone_name, used_names):
    stripped = zone_name.rstrip(".")
    base = re.sub(r"[^A-Za-z0-9.\-_]", "_", stripped) or "root-zone"
    name = base
    n = 2
    while name in used_names:
        name = f"{base}-{n}"
        n += 1
    used_names.add(name)
    return name + ".yml"


def dedent_two(text):
    # emit_zone()'s output is built to sit indented under a top-level
    # bind_zones: key (every line starts with at least two spaces, the
    # DNSSEC comment block included) — strip that common prefix so a
    # --split-output file reads as a normal standalone YAML document
    # (bind_zones_vars_dir's loader accepts it either way, indented or
    # not, but unindented is what a human would actually write by hand).
    return "\n".join(line[2:] if line.startswith("  ") else line for line in text.split("\n"))


def emit_record(rec):
    fields = [f"name: {yaml_str(rec['name'])}", f"type: {yaml_str(rec['type'])}", f"value: {yaml_str(rec['value'])}"]
    if "comment" in rec:
        fields.append(f"comment: {yaml_str(rec['comment'])}")
    return "      - { " + ", ".join(fields) + " }"


def emit_zone(zone, transfer_acl, also_notify, key_findings):
    out = []
    comment = zone_dnssec_comment(zone["name"], key_findings)
    if comment:
        out.append(comment)
    out.append(f"  - name: {yaml_str(zone['name'])}")
    out.append("    type: master")
    out.append(f"    allow_transfer_acl: {transfer_acl}")
    if also_notify:
        out.append("    also_notify:")
        for ip in also_notify:
            out.append(f"      - {ip}")
    if key_findings:
        out.append("    # dnssec: true   # uncomment once bind_dnssec_enable_signing / a policy is set up — see notes above")
    out.append(f"    primary_ns: {yaml_str(zone['primary_ns'])}")
    out.append(f"    admin_email: {yaml_str(zone['admin_email'])}")
    out.append(f"    ttl: {zone['ttl']}")
    out.append(f"    serial: {zone['serial']}")
    out.append(f"    refresh: {zone['refresh']}")
    out.append(f"    retry: {zone['retry']}")
    out.append(f"    expire: {zone['expire']}")
    out.append(f"    negative_ttl: {zone['negative_ttl']}")
    if zone["nameservers"]:
        out.append("    nameservers:")
        for ns in zone["nameservers"]:
            out.append(f"      - {yaml_str(ns)}")
    else:
        out.append("    nameservers: []")
    if zone["records"]:
        out.append("    records:")
        for rec in zone["records"]:
            out.append(emit_record(rec))
    else:
        out.append("    records: []")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # one zone
  %(prog)s example.com /var/named/example.com.zone

  # several zones in one run, written to a file instead of stdout
  %(prog)s -z example.com=/var/named/example.com.zone \\
           -z 1.0.10.in-addr.arpa=/var/named/1.0.10.rev \\
           -o host_vars/dns-master-01/bind_zones.yml

  # batch from a text file, one "<zone> <path>" pair per line
  %(prog)s --zones-file zones.txt -o bind_zones.yml

  # hundreds of zones: one small file per zone instead of one big blob —
  # see the bind_dns role's bind_zones_vars_dir
  %(prog)s --zones-file zones.txt --split-output host_vars/dns-master-01/zones.d
""",
    )
    add_common_arguments(parser)
    parser.add_argument("-o", "--output", metavar="PATH", help="write YAML here instead of stdout")
    parser.add_argument(
        "--split-output", metavar="DIR",
        help=(
            "write one file per zone into DIR instead of a single combined file/stdout — pairs with "
            "the bind_dns role's bind_zones_vars_dir, which loads a directory shaped exactly like "
            "this. Mutually exclusive with -o/--output. Re-running overwrites same-named files but "
            "doesn't remove ones from a previous run that no longer correspond to a current zone — "
            "clean those up yourself if a zone was renamed or dropped from --zones-file."
        ),
    )
    parser.add_argument(
        "--key-dir", action="append", default=[], metavar="DIR",
        help="extra directory to search for K<zone>.+*.key files, beyond each zone file's own directory (repeatable)",
    )
    parser.add_argument(
        "--transfer-acl", default="transfer_hosts", metavar="NAME",
        help="allow_transfer_acl value for every zone emitted (default: transfer_hosts)",
    )
    parser.add_argument(
        "--also-notify", nargs="*", default=[], metavar="IP",
        help="also_notify IPs applied to every zone emitted (not derivable from the zone file itself)",
    )
    parser.add_argument("--debug", action="store_true", help="also write each zone's raw named-checkzone dump to <zone>.raw for inspection")
    args = parser.parse_args()

    if args.output and args.split_output:
        parser.error("-o/--output and --split-output are mutually exclusive — pick one")

    pairs = collect_zone_pairs(args, parser)
    warn = make_warn(args.quiet)
    named_checkzone = find_named_checkzone(args.named_checkzone)

    if args.split_output:
        os.makedirs(args.split_output, exist_ok=True)
    used_filenames = set()

    zone_blocks = []
    any_key_findings = False
    total_excluded = 0

    for zone_name, zone_file in pairs:
        if not args.quiet:
            print(f"processing {zone_name} ({zone_file}) ...", file=sys.stderr)
        zone, inline_dnskeys, excluded_count, raw_dump = parse_zone(named_checkzone, zone_name, zone_file, warn, args.zone_root)
        total_excluded += excluded_count

        if args.debug:
            raw_path = f"{zone_name}.raw"
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write(raw_dump)
            print(f"  wrote raw named-checkzone dump to {raw_path}", file=sys.stderr)

        search_dirs = [os.path.dirname(os.path.abspath(zone_file))] + args.key_dir
        key_findings = find_key_files(zone_name, search_dirs)
        key_findings.extend(parse_inline_dnskeys(inline_dnskeys))
        if key_findings:
            any_key_findings = True
            if not args.quiet:
                print(f"  found {len(key_findings)} DNSSEC key(s) for {zone_name} — see migration comment in output", file=sys.stderr)

        if excluded_count and not args.quiet:
            print(f"  excluded {excluded_count} DNSSEC-managed record(s) (DNSKEY/RRSIG/NSEC*/CDS/CDNSKEY)", file=sys.stderr)

        block = emit_zone(zone, args.transfer_acl, args.also_notify, key_findings)
        zone_blocks.append(block)

        if args.split_output:
            filename = safe_zone_filename(zone_name, used_filenames)
            with open(os.path.join(args.split_output, filename), "w", encoding="utf-8") as f:
                f.write(dedent_two(block) + "\n")

    if args.split_output:
        if not args.quiet:
            print(f"wrote {len(zone_blocks)} zone file(s) to {args.split_output}/", file=sys.stderr)
        if any_key_findings:
            notes_path = os.path.join(args.split_output, "README-dnssec-migration.txt")
            # .txt, not .yml/.yaml: bind_zones_vars_dir's loader globs both
            # of those extensions and would otherwise try to load this
            # comment-only file as zone data.
            with open(notes_path, "w", encoding="utf-8") as f:
                f.write(DNSSEC_INTRO_COMMENT)
            if not args.quiet:
                print(f"wrote DNSSEC migration notes to {notes_path}", file=sys.stderr)
    else:
        out_lines = []
        if any_key_findings:
            out_lines.append(DNSSEC_INTRO_COMMENT)
        out_lines.append("bind_zones:")
        out_lines.append("\n\n".join(zone_blocks))
        output_text = "\n".join(out_lines) + "\n"

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text)
            if not args.quiet:
                print(f"wrote {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(output_text)

    if not args.quiet:
        print(
            f"done: {len(pairs)} zone(s), {total_excluded} DNSSEC-managed record(s) excluded in total.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
