#!/usr/bin/env python3
"""Cross-check A/AAAA records against PTR records across a set of BIND zones.

Run this *before* zone_to_bind_vars.py, on the same forward and reverse
zone files (including ones with $INCLUDE), to catch forward/reverse DNS
mismatches while they're still easy to fix — before they get carried
across into the new role's bind_zones data.

    ./check_ptr_records.py --zones-file zones.txt

Requires named-checkzone (bind-utils / bind9.16-utils) on PATH — see
scripts/README.md.
"""

import argparse
import ipaddress
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
)

DEFAULT_IGNORE_PATTERN = r"^\d{6}\."


def is_reverse_zone(zone_name):
    zn = zone_name.rstrip(".").lower()
    return zn == "in-addr.arpa" or zn.endswith(".in-addr.arpa") or zn == "ip6.arpa" or zn.endswith(".ip6.arpa")


def decode_ipv4_ptr(owner_nodot):
    suffix = ".in-addr.arpa"
    if not owner_nodot.endswith(suffix):
        return None
    prefix = owner_nodot[: -len(suffix)]
    labels = prefix.split(".") if prefix else []
    if len(labels) < 4:
        return None
    # Standard in-addr.arpa PTR owner: <addr>.<o3>.<o2>.<o1>.in-addr.arpa —
    # labels appear in reverse octet order. An RFC 2317 classless-delegation
    # zone inserts an extra "subnet-id" label between <addr> and the three
    # network octets (e.g. <addr>.<subnet-id>.<o3>.<o2>.<o1>.in-addr.arpa);
    # taking the first label and the *last three* — rather than assuming
    # exactly four — decodes both cases the same way without needing to
    # detect which one this is.
    addr, o3, o2, o1 = labels[0], labels[-3], labels[-2], labels[-1]
    try:
        return ipaddress.IPv4Address(f"{o1}.{o2}.{o3}.{addr}")
    except ValueError:
        return None


def decode_ipv6_ptr(owner_nodot):
    suffix = ".ip6.arpa"
    if not owner_nodot.endswith(suffix):
        return None
    prefix = owner_nodot[: -len(suffix)]
    labels = prefix.split(".") if prefix else []
    # A full host PTR always has exactly 32 nibble labels (one per hex
    # digit of a /128). Fewer means this owner is a delegation/prefix
    # record, not an individual host's PTR — not something to decode here.
    if len(labels) != 32 or not all(len(lbl) == 1 and lbl in "0123456789abcdef" for lbl in labels):
        return None
    hex_str = "".join(reversed(labels))
    hextets = [hex_str[i : i + 4] for i in range(0, 32, 4)]
    try:
        return ipaddress.IPv6Address(":".join(hextets))
    except ValueError:
        return None


def decode_ptr_owner(owner):
    owner_nodot = owner.rstrip(".").lower()
    if owner_nodot.endswith(".in-addr.arpa"):
        return decode_ipv4_ptr(owner_nodot)
    if owner_nodot.endswith(".ip6.arpa"):
        return decode_ipv6_ptr(owner_nodot)
    return None


def collect_records(named_checkzone, pairs, warn, info, debug, zone_root=None):
    """Scan every given zone for A/AAAA and PTR records, regardless of
    whether the zone's own name looks like a forward or reverse zone — a
    record is classified by its own type, not by which file it came from,
    since nothing stops (accidental or otherwise) cross-placed records.
    """
    forward = {}  # ip -> [(zone_name, name, rtype), ...]
    reverse = {}  # ip -> [(zone_name, ptr_owner, target), ...]

    for zone_name, zone_file in pairs:
        kind = "reverse" if is_reverse_zone(zone_name) else "forward"
        info(f"processing {kind} zone {zone_name} ({zone_file}) ...")
        lines, raw_dump = dump_zone_canonical(named_checkzone, zone_name, zone_file, zone_root)

        if debug:
            raw_path = f"{zone_name}.raw"
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write(raw_dump)
            info(f"  wrote raw named-checkzone dump to {raw_path}")

        for lineno, line in enumerate(lines, start=1):
            try:
                owner, ttl, rtype, rdata = parse_canonical_line(line, lineno)
            except ZoneParseError as exc:
                die(
                    f"error: couldn't parse named-checkzone output for zone '{zone_name}' ({exc}).\n"
                    "       Re-run with --debug to save the raw dump and inspect it."
                )

            if rtype in ("A", "AAAA"):
                try:
                    ip = ipaddress.ip_address(rdata.strip())
                except ValueError:
                    warn(f"{zone_name}: couldn't parse {rtype} rdata as an IP address: {rdata!r}")
                    continue
                forward.setdefault(ip, []).append((zone_name, owner.rstrip("."), rtype))

            elif rtype == "PTR":
                ip = decode_ptr_owner(owner)
                if ip is None:
                    warn(f"{zone_name}: PTR owner {owner!r} doesn't decode to a single host address — skipped")
                    continue
                reverse.setdefault(ip, []).append((zone_name, owner.rstrip("."), rdata.rstrip(".")))

    return forward, reverse


def check_missing_ptr(forward, reverse, ignore_re):
    findings = []
    ignored_count = 0
    for ip, entries in forward.items():
        relevant = []
        for zone_name, name, rtype in entries:
            if ignore_re and ignore_re.match(name):
                ignored_count += 1
                continue
            relevant.append((zone_name, name, rtype))
        if relevant and ip not in reverse:
            for zone_name, name, rtype in relevant:
                findings.append({"zone": zone_name, "name": name, "type": rtype, "ip": str(ip)})
    return findings, ignored_count


def check_missing_forward(forward, reverse, ignore_re):
    findings = []
    ignored_count = 0
    for ip, entries in reverse.items():
        relevant = []
        for zone_name, ptr_owner, target in entries:
            if ignore_re and ignore_re.match(target):
                ignored_count += 1
                continue
            relevant.append((zone_name, ptr_owner, target))
        if relevant and ip not in forward:
            for zone_name, ptr_owner, target in relevant:
                findings.append({"zone": zone_name, "ptr_owner": ptr_owner, "target": target, "ip": str(ip)})
    return findings, ignored_count


def check_mismatches(forward, reverse):
    findings = []
    for ip, fwd_entries in forward.items():
        if ip not in reverse:
            continue
        fwd_names = {name.lower() for _, name, _ in fwd_entries}
        ptr_targets = {target.lower() for _, _, target in reverse[ip]}
        if not (fwd_names & ptr_targets):
            findings.append(
                {"ip": str(ip), "forward_names": sorted(fwd_names), "ptr_targets": sorted(ptr_targets)}
            )
    return findings


def print_report(missing_ptr, missing_forward, mismatches, ignored_forward_count, ignored_reverse_count, out):
    if missing_ptr:
        print("== Forward records with no PTR ==", file=out)
        for f in sorted(missing_ptr, key=lambda x: (x["zone"], x["name"])):
            print(f"  {f['zone']}: {f['name']} ({f['type']}, {f['ip']}) has no PTR record", file=out)
        print(file=out)

    if missing_forward:
        print("== PTR records with no forward A/AAAA ==", file=out)
        for f in sorted(missing_forward, key=lambda x: (x["zone"], x["ptr_owner"])):
            print(
                f"  {f['zone']}: {f['ptr_owner']} -> {f['target']} ({f['ip']}) "
                f"has no A/AAAA record for {f['target']}",
                file=out,
            )
        print(file=out)

    if mismatches:
        print("== Name mismatches (informational — often legitimate, e.g. shared/virtual-hosted IPs) ==", file=out)
        # (version, address) — never (address,) alone: IPv4Address and
        # IPv6Address don't support comparison against each other at all
        # (ipaddress raises TypeError on <), and a zone set mixing both
        # families is completely normal. Sorting by version first means
        # cross-family comparisons never happen — tuple comparison only
        # looks at the address element once the version element is equal.
        for m in sorted(mismatches, key=lambda x: (ipaddress.ip_address(x["ip"]).version, ipaddress.ip_address(x["ip"]))):
            print(
                f"  {m['ip']}: forward name(s) {', '.join(m['forward_names'])} "
                f"vs PTR target(s) {', '.join(m['ptr_targets'])}",
                file=out,
            )
        print(file=out)

    if not (missing_ptr or missing_forward or mismatches):
        print("No forward/reverse DNS inconsistencies found.", file=out)
        print(file=out)

    print(
        f"Summary: {len(missing_ptr)} missing PTR, {len(missing_forward)} missing forward, "
        f"{len(mismatches)} name mismatch(es), {ignored_forward_count} A/AAAA record(s) and "
        f"{ignored_reverse_count} PTR record(s) ignored (matched --ignore-pattern)",
        file=out,
    )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # every zone in one go, from a "<zone> <path>" list (forward and reverse mixed)
  %(prog)s --zones-file zones.txt

  # a couple of zones directly, report written to a file
  %(prog)s -z example.com=/var/named/example.com.zone \\
           -z 1.0.10.in-addr.arpa=/var/named/1.0.10.rev \\
           -o ptr-report.txt

  # this subnet's reverse zone uses a different placeholder-name convention
  %(prog)s --zones-file zones.txt --ignore-pattern '^dhcp-\\d+\\.'

  # check every PTR strictly, including any placeholder-looking ones
  %(prog)s --zones-file zones.txt --no-ignore-pattern

exit status: 0 if nothing but ignored/informational findings turned up,
1 if any forward-with-no-PTR or PTR-with-no-forward records were found
(also on --strict name mismatches), 2 on a usage or zone-loading error.
""",
    )
    add_common_arguments(parser)
    parser.add_argument("-o", "--output", metavar="PATH", help="write the report here instead of stdout")
    parser.add_argument(
        "--ignore-pattern", default=DEFAULT_IGNORE_PATTERN, metavar="REGEX",
        help=(
            "regex (case-insensitive, matched at the start of the name) identifying auto-generated/"
            "placeholder names to skip — applied to a PTR record's target when checking for a matching "
            "forward record, and equally to an A/AAAA record's own name when checking for a matching "
            "PTR, so neither direction flags the other half of the same placeholder-named pair — e.g. "
            f"the default {DEFAULT_IGNORE_PATTERN!r} matches names like '001050.example.com' (a "
            "zero-padded octet3+octet4 code for 10.1.1.50 within 10.1.1.0/24). Adjust to your own site's "
            "convention, or see --no-ignore-pattern."
        ),
    )
    parser.add_argument(
        "--no-ignore-pattern", action="store_true",
        help="disable --ignore-pattern entirely and check every record, including placeholder-looking ones",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="also exit non-zero on name mismatches (forward/PTR both exist but point at different names)",
    )
    parser.add_argument("--debug", action="store_true", help="also write each zone's raw named-checkzone dump to <zone>.raw for inspection")
    args = parser.parse_args()

    pairs = collect_zone_pairs(args, parser)
    warn = make_warn(args.quiet)

    def info(msg):
        if not args.quiet:
            print(msg, file=sys.stderr)

    named_checkzone = find_named_checkzone(args.named_checkzone)

    ignore_re = None
    if not args.no_ignore_pattern:
        try:
            ignore_re = re.compile(args.ignore_pattern, re.IGNORECASE)
        except re.error as exc:
            parser.error(f"--ignore-pattern is not a valid regular expression: {exc}")

    forward, reverse = collect_records(named_checkzone, pairs, warn, info, args.debug, args.zone_root)

    missing_ptr, ignored_forward_count = check_missing_ptr(forward, reverse, ignore_re)
    missing_forward, ignored_reverse_count = check_missing_forward(forward, reverse, ignore_re)
    mismatches = check_mismatches(forward, reverse)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            print_report(missing_ptr, missing_forward, mismatches, ignored_forward_count, ignored_reverse_count, out=f)
        if not args.quiet:
            print(f"wrote {args.output}", file=sys.stderr)
    else:
        print_report(missing_ptr, missing_forward, mismatches, ignored_forward_count, ignored_reverse_count, out=sys.stdout)

    real_findings = len(missing_ptr) + len(missing_forward) + (len(mismatches) if args.strict else 0)
    sys.exit(1 if real_findings else 0)


if __name__ == "__main__":
    main()
