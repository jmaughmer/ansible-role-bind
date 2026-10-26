# Migration scripts

Three scripts to help move an existing hand-run BIND 9.11 deployment onto
the [`bind_dns`](../README.md) Ansible role, meant to be run in this order:

1. **`named_conf_to_zones.py`** — reads `named.conf` (following its own
   `include "...";` statements) and produces the `<zone> <file>` list
   (`zones.txt`) the other two scripts consume. With `--bind-zones` it
   writes the `bind_zones` YAML itself instead. That's the whole migration
   for a **slave or edge server**: its zones are `named.conf` settings, and
   their data comes from the master. See
   [Migrating a slave or edge server](#migrating-a-slave-or-edge-server---bind-zones).
2. **`check_ptr_records.py`** — sanity-checks forward (`A`/`AAAA`) and
   reverse (`PTR`) DNS across all your zones *before* anything gets
   migrated, so existing inconsistencies are caught while they're still
   easy to fix rather than carried across as "the new setup is broken."
3. **`zone_to_bind_vars.py`** — converts each zone file into the `bind_zones`
   YAML this role consumes.

The latter two read real BIND zone *files* — including ones that pull in
extra content via `$INCLUDE` — by shelling out to
`named-checkzone -D -s full -o -` rather than re-implementing an RFC1035
zone-file parser. This is what actually resolves `$INCLUDE`, `$GENERATE`,
multi-line parenthesized records, `$ORIGIN` changes, and escaping exactly
the way `named` itself does: `named-checkzone` uses the same zone-loading
code, so whatever loads cleanly for `named` parses identically here. The
`-s full` canonical style BIND ships is explicitly documented as "most
suitable for processing automatically by a separate script" — every record
line comes out fully self-contained (explicit absolute owner name,
explicit TTL, explicit class) — which both scripts' parsers are built
around. That shared dump/parse logic lives in `bindzone_common.py`,
imported by both — not a standalone tool itself.

`named_conf_to_zones.py` reads `named.conf` *config* directly instead
(zone statements aren't zone data, so `named-checkzone` doesn't apply) —
see its own section below for how that parsing works.

### $INCLUDE inside a zone file needs `--zone-root`

A zone file's own `$INCLUDE` directive can use a relative path — e.g.
`$INCLUDE "master/example.com/inc.denver.static"`, resolved against
`/var/named` (or whatever `options { directory ...; }` says) the same way
a bare `file "example.com.zone";` in `named.conf` is. `named`, running as
the real server, gets that resolution for free — it `chdir()`s to
`directory` once at startup. `named-checkzone` never reads `named.conf` at
all, so it has no `directory` of its own to chdir to; left alone, it
resolves a relative `$INCLUDE` against whatever directory *it* happened to
be launched from — normally wherever you ran this script from, which is
essentially never the right place, and produces exactly the "file not
found" error these two scripts are shelling out to `named-checkzone` in
the first place to avoid.

`check_ptr_records.py` and `zone_to_bind_vars.py` fix this by always
passing `named-checkzone`'s own `-w directory` flag (its documented purpose,
verbatim: "instructs named to chdir to directory, so that relative
filenames in master file $INCLUDE directives work"), via `--zone-root`
(default `/var/named`, the standard RHEL location — override it if
`named.conf`'s `options { directory ...; }` says something else;
`named_conf_to_zones.py` prints the value it found if that's the case).
Pass `--zone-root ''` to turn this off and fall back to `named-checkzone`'s
own current directory, if you ever need the old behavior.

## Requirements

- Python 3.6+ (standard library only — nothing to `pip install`). Kept
  compatible with 3.6 deliberately, since that's RHEL 8's system
  `/usr/bin/python3` — the same box these scripts are meant to run on (see
  below). Avoid 3.7+-only stdlib additions (`subprocess.run(capture_output=
  ...)` is the one that's bitten this before — use `stdout=`/`stderr=
  subprocess.PIPE` instead) if you're changing these scripts.
- `named-checkzone`, on `PATH` or via `--named-checkzone /path/to/it`, for
  `check_ptr_records.py`/`zone_to_bind_vars.py` only. It ships in
  `bind-utils` (or `bind9.16-utils` if that's what the source host is
  running). Since the point is to parse zone data exactly as the source
  server would load it, **run all three of these on the BIND 9.11 host
  itself** (or an exact copy of its config and zone directory tree,
  `include`/`$INCLUDE`d files and all) — not some unrelated machine that
  merely happens to have `bind-utils` installed too.
- All four files (`bindzone_common.py` plus the three scripts) need to stay
  together in the same directory — the scripts import the shared module
  from alongside themselves.

```bash
chmod +x named_conf_to_zones.py check_ptr_records.py zone_to_bind_vars.py

./named_conf_to_zones.py /etc/named.conf -o zones.txt
./check_ptr_records.py --zones-file zones.txt
./zone_to_bind_vars.py --zones-file zones.txt -o bind_zones.yml
```

`check_ptr_records.py` and `zone_to_bind_vars.py` take the same zone-list
flags, so the one `zones.txt` from step 1 works for both. Instead of
`--zones-file`, either also accepts one zone as two positional arguments
(`example.com /var/named/example.com.zone`) or several via repeated
`-z ZONE=FILE` — useful for a one-off zone without generating a full
`zones.txt`. `zones.txt` itself is just `<zone name> <file path>` pairs,
one per line, `#` comments allowed, so it's easy to hand-edit — trim it to
a subset of zones, fix a path `named_conf_to_zones.py` couldn't resolve,
add one it missed — before feeding it to the other two. A single
`zones.txt` can freely mix forward and reverse zones; each script figures
out what it needs from zone content, not from the zone's name.

Full flag reference for any of the three: `--help`.

### Migrating a slave or edge server (`--bind-zones`)

A slave's zone data comes from its master by zone transfer, so there are
no zone files to convert and `check_ptr_records.py`/`zone_to_bind_vars.py`
aren't needed. Run only this, on the server being migrated:

```bash
# one file, paste-ready as (or merged into) host_vars
./named_conf_to_zones.py /etc/named.conf --bind-zones -o bind_zones.yml

# hundreds of zones: one file per zone, for the role's bind_zones_vars_dir
./named_conf_to_zones.py /etc/named.conf --bind-zones \
  --split-output host_vars/dns-edge-01.example.internal/zones.d
```

What it carries over, per zone:

| `named.conf` | `bind_zones` entry |
|---|---|
| `type slave` / `secondary` | `type: slave` |
| `masters { ... }` / `primaries { ... }` | `masters:` list. References to named `masters`/`primaries` lists are expanded, and a block-level `port N` is applied to each entry. Per-entry `port` and `key` are kept as written. |
| `type forward` + `forwarders { ... }` | `type: forward`, `forwarders:` |
| `forward first|only` | `forward_policy:`. A forward zone without one gets `first`, which is BIND's default and not the role's (`only`). |
| `type master` / `primary` + `file "..."` | `type: master`, `file:` (the file name). A comment says to copy the zone file into the role's `bind_zones_dir`, or to convert it with `zone_to_bind_vars.py`. |
| `allow-transfer { ... }` | `allow_transfer_acl:` |
| `also-notify { ... }`, `notify yes|no` | `also_notify:`, `notify:` (master and slave zones) |
| `zone-statistics yes|no` | `zone_statistics:` |

How the transfer settings carry over:

- **The zone's own `allow-transfer` wins;** without one, the global
  `options { allow-transfer }` applies. If neither is set, BIND allowed
  transfers to anyone, so the zone gets `allow_transfer_acl: any` with a
  comment saying to tighten it.
- **One ACL per zone:** the role's `allow_transfer_acl` takes one ACL name
  (or `any`/`none`). A single-element list is used as-is. A longer list
  becomes a generated ACL, `xfer_1`, `xfer_2` and so on, with identical
  lists sharing one ACL.
- **Referenced ACLs come along:** every `named.conf` ACL the zones
  reference, including ACLs nested in other ACLs, is written as
  `bind_acls`, together with the generated ones. Merge them with the
  role's own `trusted`/`transfer_hosts`/`recursion_clients`/`dns64_clients`
  entries. With `--split-output` they go to `DIR/bind_acls.yml.txt`. It's
  `.txt` so `bind_zones_vars_dir`, which reads every `.yml` file as zone
  data, ignores it.

What it doesn't carry over, and says so:

- **Other zone options** (`allow-update`, `max-refresh-time`,
  `notify-source`, `notify explicit`, ...) are listed in a `# not
  migrated:` comment above the zone. The role has no setting for them.
- **TSIG keys:** a `key name` in masters or `allow-transfer` is kept, but
  the role doesn't define TSIG keys. The script warns. Add the `key { };`
  statements on the new servers yourself, or named won't load the config.
- **Views:** a zone inside a `view { }` gets a comment. The role has no
  views, and only the first definition of a zone name is used.
- **Zone types the role doesn't model** (`hint`, `stub`, `static-stub`,
  `redirect`, ...) are skipped with a warning.
- **RHEL's stock zones** (`localhost`, `1.0.0.127.in-addr.arpa` and the
  other `named.rfc1912.zones` entries) are skipped, since every RHEL server
  already has them. `--include-stock-zones` keeps them.
- **Forward zones on a server with recursion off** never forwarded
  anything there, and get a comment saying so. The role only accepts
  forward zones on hosts with recursion on.

The output is plain YAML with every zone name quoted, so names like `on`
or `0.10.in-addr.arpa` stay strings. It needs no Python packages beyond
the standard library. Review the comments before using it.

---

## named_conf_to_zones.py

Reads `named.conf` and prints a `<zone name> <file path>` line for every
`zone { }` statement whose `type` is `master` or `slave` (configurable via
`--zone-types`; `primary`/`secondary` count as the same) and that has a
`file "...";`. With `--bind-zones` it writes the role's `bind_zones` YAML
instead: see
[Migrating a slave or edge server](#migrating-a-slave-or-edge-server---bind-zones). Zone names are picked up
whether or not they're quoted — `zone example.com { ... };` is as valid to
BIND as `zone "example.com" { ... };`. `forward`/`hint`/`stub`/
`redirect` zones are skipped — they don't have a meaningful zone data file
for the other two scripts to read.

```bash
./named_conf_to_zones.py /etc/named.conf -o zones.txt
```

Unlike a `grep`/`awk`/fixed-line-window approach, this actually parses the
config: it strips comments (`//`, `#`, `/* */`, without being fooled by
one of those sequences appearing inside a quoted string), recursively
expands `include "...";` statements (resolved relative to the file that
contains them, same as `named` itself), and tracks brace depth to find
each zone statement's real boundaries — so it doesn't matter whether a
zone's `type`/`file`/`allow-transfer`/etc. are all on one line, each on
their own line in any order, or have other `{ }` blocks (ACLs,
`also-notify` lists, `masters { }`) nested in between. That line-per-
directive layout, plus config split across multiple files via `include`,
is normal for a real production `named.conf` — a fixed-line-window
grep/awk approach only catches `file "...";` when it happens to land
within that window of the `zone "..." {` line, and silently produces
nothing whenever it doesn't (e.g. any zone stanza where `type` — or
anything else — comes before `file`).

A relative `file` path is resolved against `options { directory "...";
}` if present in the config (also followed through includes), or against
`--zone-dir` if you'd rather specify it explicitly (`--zone-dir` wins if
both are given). If neither is available, the path is left as-is with a
warning — check the output before trusting it downstream.

If the same zone name appears more than once with *different* file paths
(a split-horizon `view { }` config, most likely — something the
`bind_dns` role doesn't model; see its README's design notes), both are
written to `zones.txt` with a warning, so you can pick the right one by
hand rather than have the script guess.

---

## check_ptr_records.py

For every `A`/`AAAA` record across the forward zones given, checks that a
`PTR` record exists for that IP somewhere in the reverse zones given —
and vice versa: every `PTR` record's IP should have a matching `A`/`AAAA`
record. Reports three kinds of finding:

- **Missing PTR** — a forward record with no reverse record for its IP at
  all.
- **Missing forward** — a PTR record whose IP has no `A`/`AAAA` record.
- **Name mismatch** (informational only — doesn't affect the exit code
  unless `--strict`) — both exist, but the PTR points at a different name
  than any `A`/`AAAA` record for that IP. Often legitimate (an IP shared by
  several virtual-hosted names can only have one PTR target), so this is
  reported separately from the two "missing" categories rather than folded
  in with them.

```bash
./check_ptr_records.py --zones-file zones.txt
```

```
== Forward records with no PTR ==
  example.com: newhost.example.com (A, 10.1.1.75) has no PTR record

== PTR records with no forward A/AAAA ==
  1.1.10.in-addr.arpa: 60.1.1.10.in-addr.arpa -> ghost.example.com (10.1.1.60) has no A/AAAA record for ghost.example.com

== Name mismatches (informational — often legitimate, e.g. shared/virtual-hosted IPs) ==
  10.1.1.20: forward name(s) www.example.com vs PTR target(s) app.example.com

Summary: 1 missing PTR, 1 missing forward, 1 name mismatch(es), 2 A/AAAA record(s) and 3 PTR record(s) ignored (matched --ignore-pattern)
```

Exit status: `0` if nothing but ignored/informational findings turned up,
`1` if any missing-PTR or missing-forward records were found (also on
name mismatches if `--strict`), `2` on a usage or zone-loading error — so
it's usable as a pre-migration gate (`check_ptr_records.py ... || echo
"clean up DNS hygiene first"`).

### Ignoring auto-generated placeholder names

Some zones carry records that don't point at a "real" maintained hostname,
but at an auto-generated placeholder — e.g. an allocation-tracking scheme
that zero-pads octets 3 and 4 into a 6-digit code:
`50.1.1.10.in-addr.arpa. PTR 001050.example.com.` for `10.1.1.50` within
`10.1.1.0/24` (octet 3 = `001`, octet 4 = `050`), possibly alongside a
forward `001050.example.com. A 10.1.1.50` too. Neither side of a
placeholder-named pair like that is expected to have a "real" counterpart
maintained by hand, and flagging every one of them would just be noise.
`--ignore-pattern` (default `^\d{6}\.`, matched case-insensitively against
the start of the name) applies to **both directions**, independently:

- A PTR record whose *target* matches the pattern is skipped when checking
  for a matching forward record (a "missing forward" finding).
- An `A`/`AAAA` record whose own *name* matches the pattern is skipped when
  checking for a matching PTR record (a "missing PTR" finding).

Either way, the match only suppresses that record from being flagged as
*missing* on its own side — it does **not** stop it from counting as
*present* for the other side's check. A real `A` record that happens to
share an IP with a placeholder-named PTR is still considered to have a
PTR, and vice versa; the two directions of the ignore check never affect
each other's existence checks, only their own "is this missing" check.

The default pattern is only a starting point for the exact convention
described above — check the two `ignored` counts in the summary line
against what you expect (they're reported separately — A/AAAA records
ignored on the forward side, PTR records ignored on the reverse side — so
a mismatch between the two can itself be a clue something's off), adjust
`--ignore-pattern` to your own site's naming convention(s) if it doesn't
look right (`--ignore-pattern '^dhcp-\d+\.'`, for instance), or pass
`--no-ignore-pattern` to check every record with no exceptions.

---

## zone_to_bind_vars.py

Converts a zone file into the `bind_zones` role variable. Given the
canonical dump described above, it:

- Extracts the SOA fields, apex `NS` records (→ `nameservers:`), and every
  other record (→ `records:`), converting fully-qualified owner names back
  to zone-relative ones (`www.example.com.` → `www`, the apex itself → `@`).
  Delegation `NS` records for a subdomain *within* this zone (and their
  glue) are correctly left in `records:` rather than folded into
  `nameservers:`, since only the zone's own apex NS set means that.
- Drops `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `CDS`, and
  `CDNSKEY` records — the `bind_dns` role's `dnssec-policy` +
  `inline-signing` regenerates and manages all of these itself; carrying
  them across from an old signed zone would just be immediately fought over
  or overwritten.
- Flags any record whose own TTL differs from the zone's default with an
  auto-generated `comment:` field (the role's generic `records:` shape has
  no per-record TTL override, so that detail would otherwise be silently
  flattened to the zone's `$TTL` without a trace).
- Looks for existing KSK/ZSK key material — both `DNSKEY` records found
  inline in the zone (i.e. the file loaded was itself the *signed* output)
  and `K<zone>.+<alg>+<keyid>.key` files sitting next to the zone file (or
  in `--key-dir`) — and, if found, writes a migration comment block above
  that zone explaining how to move from manual key management to this
  role's automatic `dnssec-policy` (see **DNSSEC key migration** below).

```bash
# one zone, printed to the terminal
./zone_to_bind_vars.py example.com /var/named/example.com.zone

# several zones in one run, written straight to a host_vars file
./zone_to_bind_vars.py \
  -z example.com=/var/named/example.com.zone \
  -z 1.0.10.in-addr.arpa=/var/named/1.0.10.rev \
  -o host_vars/dns-master-01.example.internal/bind_zones.yml

# hundreds of zones: one file per zone instead of one big one to merge by hand
./zone_to_bind_vars.py --zones-file zones.txt \
  --split-output host_vars/dns-master-01.example.internal/zones.d
```

### Output

By default the script emits a `bind_zones:` YAML key with one list entry
per zone — paste-ready as (or merged into) a host's `host_vars`. If you're
combining output from multiple runs this way, remember YAML mappings can't
repeat a key, so merge the `bind_zones:` **lists** by hand rather than
concatenating the files as-is.

For more than a handful of zones, skip that merge step entirely with
`--split-output DIR` — writes one file per zone into `DIR` (named after
the zone, sanitized for the filesystem) instead of one combined
file/stdout, in exactly the shape the `bind_dns` role's
`bind_zones_vars_dir` reads (see the main README's **Managing many
zones**). `-o`/`--output` and `--split-output` are mutually exclusive.
Each zone's own DNSSEC migration comment (if any) stays with that zone's
file; the general explainer that's otherwise printed once at the top goes
to `DIR/README-dnssec-migration.txt` instead (`.txt`, not `.yml`/`.yaml`,
specifically so `bind_zones_vars_dir`'s loader — which reads every
`.yml`/`.yaml` file in the directory as zone data — doesn't try to parse
it as a zone). Re-running overwrites same-named files but doesn't delete
ones from a previous run that no longer correspond to a current zone (a
zone renamed or dropped from `--zones-file`) — clean those up yourself.

`allow_transfer_acl` (default `transfer_hosts`) and `also_notify` aren't
present in zone *data* — they're `named.conf` zone-clause settings — so
they're applied uniformly to every zone in a run via `--transfer-acl` and
`--also-notify`, not derived automatically. Adjust per zone afterward if
they actually differ.

Every zone comes out as `type: master`. If the zone you're migrating is
actually a **slave** in the new setup, you don't need this script for it at
all: a `type: slave` entry needs no `records:`, just `masters:`.
`named_conf_to_zones.py --bind-zones` writes those entries straight from
the slave's `named.conf`.

### DNSSEC key migration

`bind_dns`'s `dnssec-policy` + `inline-signing` (BIND 9.16+'s automatic
KASP key management) is a different model from BIND 9.11-era manual
`dnssec-keygen` + `dnssec-signzone` (or `auto-dnssec maintain;`, which is
also gone in favor of `dnssec-policy`). When this script finds existing key
material for a zone, it prints a comment block — right above that zone's
entry in the output — summarizing exactly what it found (role, algorithm,
key file path or "inline in zone file") and a starting-point
`bind_dnssec_policies` snippet using the detected algorithm. A general
explainer of the two ways to bring a zone's DNSSEC state across (also
included, once, at the top of any output that has at least one such
finding) is worth restating here:

1. **Fresh keys.** Set `dnssec: true` plus `bind_dnssec_enable_signing:
   true` and let the role's `dnssec-policy` generate brand-new keys — named
   does **not** reuse the old ones automatically. This means a new DS
   record at the registrar/parent zone: publish it, let the old one age out
   of caches (past its DS record's TTL) before pulling the old key
   material, or accept a short validation gap if you don't sequence that.
   Simplest choice if the zone doesn't currently have DS records published
   (i.e. isn't actually being validated today).
2. **Reuse the existing keys.** Copy the `.key`/`.private` files this
   script found into the role's `bind_dnssec_keys_dir`
   (`/var/named/keys` by default) — keeping their exact filenames — *before*
   the first run that turns `dnssec-policy` on for that zone. BIND 9.16's
   KASP engine can adopt pre-existing, correctly-named keys instead of
   generating fresh ones, avoiding a DS record change. Old
   `dnssec-keygen` output won't have the `.state` file BIND's automatic
   management normally maintains — test this against a staging or
   non-production zone first to confirm your BIND version adopts it the
   way you expect before trusting it on a zone with a live DS record.

Either way, remove whatever was driving the old signing on the source
server for that zone — `auto-dnssec`, an `update-policy` used for
signing automation, or a cron job running `dnssec-signzone` — before
handing the zone to this role; `dnssec-policy` + `inline-signing` replaces
all of that, and having both active at once isn't a supported combination.

---

## Verifying the parse

All three scripts take `--debug`, writing out whatever they fed their own
parser so you can check it against what you expected before trusting the
result: `named_conf_to_zones.py` writes `named.conf.expanded` (every
`include` spliced in, comments stripped); `check_ptr_records.py`/
`zone_to_bind_vars.py` each write `<zone>.raw` per zone (the raw
`named-checkzone` dump).

## Known limitations

- **`zones.txt` carries only zone names and files.** In its default mode,
  `named_conf_to_zones.py` doesn't pass `allow-transfer`/`also-notify` on
  to `zone_to_bind_vars.py`, which still takes its own `--transfer-acl`/
  `--also-notify` flags (uniform per run) and always emits `type: master`
  (see **Output** above). `--bind-zones` does read those settings, and
  writes complete entries, but its master entries carry no `records:`.
  For a master that should keep its records in YAML, use
  `zone_to_bind_vars.py` for the data and take the transfer settings from
  the `--bind-zones` output.
- **One default TTL per zone** (`zone_to_bind_vars.py`) — a source record's
  own TTL, if it differs from the zone default, survives only as an
  advisory `comment:`, not an actual per-record override (the role's
  `records:` shape doesn't have one). Search the output for `differs from
  zone default` after running.
- **DS/keytag not computed** (`zone_to_bind_vars.py`) — for DNSSEC keys
  found *inline* in a signed zone file (as opposed to standalone `.key`
  files), the migration comment shows role and algorithm but not a key
  tag, since computing one means implementing the RFC 4034 key tag
  checksum rather than just reading a filename. Standalone `.key` files
  already encode their key ID in the filename, so this only affects the
  "signed zone with no key files alongside it" case.
- **`check_ptr_records.py` only compares within the zones you give it** —
  if a forward zone's IPs are actually covered by a reverse zone you didn't
  include in the run (wrong `--zones-file`, a reverse zone hosted
  elsewhere, etc.), every one of those IPs will misleadingly show up as
  "missing PTR." Double-check `zones.txt` covers every relevant reverse
  zone before trusting a "missing" finding.
- **`check_ptr_records.py`/`zone_to_bind_vars.py` weren't tested against a
  live `named-checkzone`** — both were built and verified against BIND's
  documented canonical-dump behavior and synthetic dumps matching that
  format (including the exact `001050.example.com` / `10.1.1.0/24` example
  from the placeholder-PTR convention above), but not against a real
  `bind-utils` binary (none was available in the environment they were
  written in). Run with `--debug` on a real zone first and sanity-check the
  output before trusting either script for a production migration.
  `named_conf_to_zones.py` doesn't carry this caveat — it has no external
  tool dependency, so it was tested directly (including the multi-line,
  directive-per-line, include-split layout that's normal for a real
  `named.conf` and specifically motivated writing it in the first place).
