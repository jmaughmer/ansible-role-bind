# bind_dns

Ansible role that installs and configures ISC BIND (`named`) on RHEL 8+ and
clones (RHEL/CentOS Stream/Rocky/AlmaLinux/OracleLinux 8–10), for two kinds
of hosts:

- **Authoritative** master or slave zone servers — recursion off, they only
  answer for zones they host.
- **Dedicated recursive caching resolvers** — no zones of their own
  (forward zones for conditional forwarding aside), recursion on.

One role, one variable (`bind_dns_role`) picks which shape a given host is;
everything else (DNSSEC, ACLs, DNS64, logging, statistics, GeoIP,
forwarders) applies to both and is controlled independently.

## Requirements

- RHEL 8 or newer (or a clone at the same major version) — uses `dnf`,
  `firewalld`, and SELinux booleans/fcontexts.
- Collections: `ansible.posix`, `community.general` (see `meta/main.yml`).
- **RHEL 8 hosts and ansible-core 2.17+:** ansible-core 2.17 dropped support
  for managing hosts whose Python is 3.6 — RHEL 8's default
  `/usr/bin/python3`. Either manage RHEL 8 hosts with ansible-core 2.16, or
  install a newer Python on them first (e.g. `dnf install python3.11` from
  AppStream; Ansible's interpreter discovery picks it up automatically).
  With the second route, check SELinux-enforcing hosts separately: the
  SELinux modules this role uses need Python SELinux bindings, which RHEL 8
  ships for its 3.6 platform Python. The Molecule tests install Python 3.11
  on EL8 containers this way, but containers run with SELinux off, so they
  don't cover that combination.
- For DNSSEC signing (`bind_dnssec_enable_signing: true`): BIND 9.16+.
  RHEL 9+'s base `bind` package already is; on RHEL 8 (base `bind` is 9.11)
  the role automatically switches to the `bind9.16` AppStream package
  instead — see **RHEL 8 and bind9.16** below. Either way, the role also
  installs `bind-dnssec-utils`/`bind9.16-dnssec-utils` for `dnssec-dsfromkey`
  (see **DNSSEC key management** below).
- For GeoIP: a MaxMind GeoIP2/GeoLite2 account if you want the role to fetch
  databases via `geoipupdate` (`bind_geoipupdate_install: true`).
- For chroot (`bind_chroot_enabled: true`): the `bind-chroot` (or, on RHEL 8
  with `bind_use_bind9_16`, `bind9.16-chroot`) package, installed
  automatically, and its `named-chroot` systemd unit.

## What it configures

| Feature | Variables |
|---|---|
| Master/slave/recursive role | `bind_dns_role`, `bind_zones` |
| DNSSEC validation + signing | `bind_dnssec_validation`, `bind_dnssec_enable_signing`, `bind_dnssec_policy` |
| System crypto policy (disabled DNSSEC algorithms) | `bind_crypto_policy_enabled`, `bind_crypto_policy_file` |
| DNSSEC KSK/ZSK key policy | `bind_dnssec_policies` (algorithm, lifetime/rollover, key size per role) |
| DNSSEC key status + DS record retrieval | `bind_dnssec_manage_keys`, `bind_dnssec_ds_output_dir` |
| Zone transfer ACLs | `bind_acls`, `bind_allow_transfer_acl`, per-zone `allow_transfer_acl` |
| DNS64 | `bind_dns64_enabled`, `bind_dns64_prefix`, `bind_dns64_clients_acl`, `bind_dns64_options` |
| Recursion + its ACL | `bind_recursion_enabled`, `bind_allow_recursion_acl` |
| Recursive forwarding | `bind_forwarders`, `bind_forward_policy` |
| Log files (per category, consolidated, or both) | `bind_log_consolidated`, `bind_log_individual_files`, `bind_log_consolidated_size`/`_versions`, `bind_log_consolidated_exclude`, `bind_log_categories`, `bind_log_dir` |
| DNS answer logging (dnstap) | `bind_dnstap_enabled`, `bind_dnstap_types`, `bind_dnstap_file` |
| dnstap export to Elasticsearch | `bind_dnstap_export_enabled`, `bind_dnstap_export_interval`, `bind_dnstap_ndjson_file` |
| Zone statistics | `bind_zone_statistics`, `bind_statistics_channels_enabled` |
| Performance tuning | `bind_minimal_responses`, `bind_ixfr_from_differences`, `bind_querylog`, `bind_recursive_clients`, `bind_transfers_*`, `bind_rate_limit`, … |
| GeoIP (GeoIP2/MaxMind) | `bind_geoip_enabled`, `bind_geoip_directory`, `bind_geoipupdate_*` |
| Forwarders | `bind_forwarders`, `bind_forward_policy` |
| Conditional forwarding | `bind_zones` with `type: forward`, `bind_dnssec_validate_except` |
| Chroot install | `bind_chroot_enabled`, `bind_chroot_extra_paths` |
| rndc key (generated, or your own from Vault) | `bind_rndc_key_secret`, `bind_rndc_key_name`, `bind_rndc_key_algorithm` |
| RHEL 8 BIND 9.16 (DNSSEC) | `bind_use_bind9_16` |
| Reverse zones (master/slave) | `bind_zones` — same `type: master`/`slave` shape as forward zones |
| Managing many zones | `bind_zones_vars_dir` (one small file per zone, instead of one big list) |

Full variable list with defaults and comments: [`defaults/main.yml`](defaults/main.yml).

## Deployment scenarios

[`examples/`](examples/) has a complete inventory, playbook and
host_vars for six servers:

| Host | What it shows |
|---|---|
| [`dns-master-01`](examples/host_vars/dns-master-01.example.internal.yml) | Master: DNSSEC signing with a custom key policy, role-managed forward and reverse zones, chroot, zones from per-zone files |
| [`dns-slave-01`](examples/host_vars/dns-slave-01.example.internal.yml) | Slave of dns-master-01 |
| [`dns-edge-01`](examples/host_vars/dns-edge-01.example.internal.yml) | Internet-facing slave: response rate limiting, chroot, zone-transfer tuning, query log off |
| [`dns-cache-01`](examples/host_vars/dns-cache-01.example.internal.yml) | Caching-only resolver: no zones and no forwarders, full recursion from the root servers with DNSSEC validation |
| [`dns-recursive-01`](examples/host_vars/dns-recursive-01.example.internal.yml) | Resolver with upstream forwarders, DNS64 and a GeoIP-scoped client ACL |
| [`dns-resolver-02`](examples/host_vars/dns-resolver-02.example.internal.yml) | Resolver forwarding an Active Directory domain and its reverse zone to the domain controllers, with dnstap capture and the Elasticsearch export |

The snippets below are the minimum for each kind of host.

### Master

```yaml
bind_dns_role: authoritative
bind_acls:
  transfer_hosts: [10.0.1.11]   # your slave(s)
bind_zones:
  - name: example.com
    type: master
    allow_transfer_acl: transfer_hosts
    also_notify: [10.0.1.11]
    dnssec: true                # only with bind_dnssec_enable_signing: true, BIND 9.16+
```

### Slave

```yaml
bind_dns_role: authoritative
bind_zones:
  - name: example.com
    type: slave
    masters: [10.0.1.10]
```

### Caching-only resolver

```yaml
bind_dns_role: recursive        # flips bind_recursion_enabled to true by default
bind_acls:
  recursion_clients: [127.0.0.1, "::1", 10.0.0.0/8]
bind_zones: []                  # no local zones
```

With no forwarders, named resolves everything itself from the root
servers, so the host needs outbound UDP and TCP port 53 to the internet.
DNSSEC validation is on by default (`bind_dnssec_validation: auto`).

### Resolver with forwarders and DNS64

```yaml
bind_dns_role: recursive
bind_acls:
  recursion_clients: [10.0.0.0/8]
  dns64_clients: [10.0.0.0/8]
bind_forwarders: [8.8.8.8, 1.1.1.1]
bind_forward_policy: first      # fall back to full recursion if they don't answer
bind_dns64_enabled: true
bind_zones: []
```

With `bind_forward_policy: first`, named asks the forwarders first and,
if they don't answer, resolves the name itself from the root servers. Set
it to `only` to use the forwarders and nothing else. Then named never
looks anything up from the root hints, and clients get SERVFAIL while the
forwarders are unreachable. Use `only` on servers that must not or can't
query the internet's DNS directly. The role requires at least one
forwarder with `only`: without one, named would silently fall back to
full recursion.

DNS64 synthesis goes to the clients in `bind_dns64_clients_acl`. By
default that's the `dns64_clients` ACL. It also takes a list, mixing ACL
names, addresses or CIDRs, negations and `geoip` elements:

```yaml
bind_dns64_clients_acl: [dns64_clients, 192.0.2.0/24, "!10.9.0.0/16"]
```

### Conditional forwarding

A `type: forward` zone sends queries for one domain to specific servers,
e.g. an Active Directory domain to its domain controllers, while
everything else is resolved normally:

```yaml
bind_dns_role: recursive
bind_zones:
  - name: corp.internal
    type: forward
    forward_policy: only
    forwarders: [10.20.1.10, 10.20.1.11]
bind_dnssec_validate_except: [corp.internal]
```

A private domain like this is unsigned, and the public DNSSEC chain proves
it doesn't exist. Without `bind_dnssec_validate_except`, named would
reject every forwarded answer for it and return SERVFAIL.
`validate-except` needs BIND 9.13.3+: RHEL 9+, or RHEL 8 with
`bind_use_bind9_16: true`.

The role refuses to render an `allow-recursion` or `allow-query-cache` ACL
that lets any client in — `any`, `0.0.0.0/0` or `::/0`, whether named
directly in `bind_allow_recursion_acl`/`bind_allow_query_cache_acl` or
reached through ACLs nested inside other ACLs (see `tasks/assertions.yml`).
Open recursive resolvers are a DDoS reflection vector. Scope
`recursion_clients` to real client networks.

## Zone content

Two ways to manage a master zone's data:

1. **Out of band** (default): give the zone entry no `records` key. The role
   only checks the file exists in `bind_zones_dir` before starting `named` —
   ship the zone file yourself (`copy`/`git`/whatever your workflow already
   uses).
2. **Role-managed**: add `records` (plus `primary_ns`, `nameservers`, etc. —
   see the comment block above `bind_zones` in `defaults/main.yml`) and the
   role renders the zone file from [`templates/zone.db.j2`](templates/zone.db.j2),
   validated with `named-checkzone` before it's put in place. Each record
   may include an optional `comment` — rendered as a trailing `; <comment>`
   on that record's line, for documentation only, no effect on the record.
   Leave `serial` unset and the role manages the SOA serial: it keeps the
   serial already on disk while the zone's content is unchanged, so
   re-running the play changes nothing, and bumps it — to the larger of
   current+1 and today's `YYYYMMDD00` — only when the content changes, so
   secondaries always see the update. Setting `serial` yourself pins it, and
   then it's on you to bump it whenever `records` change.

Slave zone files are always pulled by `named` itself via AXFR/IXFR from
`masters:` — the role never templates slave zone content.

### Managing many zones

One flat `bind_zones:` list gets painful to review, diff, and merge in git
somewhere well before you reach hundreds of zones. Splitting it across
several host_vars files doesn't help on its own — Ansible doesn't merge a
list variable defined the same way in multiple files, it just lets
whichever loads last win, unlike a dict (which *can* be configured to
merge). `bind_zones_vars_dir` is this role's answer: point it at a
directory and every `*.yml`/`*.yaml` file in it is loaded and appended to
`bind_zones` before anything else in the role runs — one small file per
zone (or a handful of related zones kept together, like a domain and its
reverse zone) instead of one big one.

```yaml
bind_zones_vars_dir: "{{ playbook_dir }}/host_vars/{{ inventory_hostname }}/zones.d"
```

Use an absolute path, or one built from the `playbook_dir` magic variable
like above, rather than a bare relative path — what that resolves against
here isn't worth relying on. It's additive with `bind_zones:` itself, not
a replacement for it: a couple of hand-maintained zones can stay inline
while the bulk lives in files — see
[`examples/host_vars/dns-master-01...`](examples/host_vars/dns-master-01.example.internal.yml)
and [`examples/zones.d/`](examples/zones.d/) for both mechanisms combined
on one host.

Each file holds either one zone (a bare mapping) or several (a list) —
whichever reads more naturally for how you're grouping them; both examples
above are demonstrated in `examples/zones.d/`. `tasks/assertions.yml` fails
the play if the same zone name ends up defined more than once, wherever
its definitions came from, so a stray leftover or copy-paste duplicate
across hundreds of files gets caught immediately instead of silently
picking one.

[`scripts/zone_to_bind_vars.py`](scripts/zone_to_bind_vars.py)'s
`--split-output DIR` writes directly in this one-file-per-zone shape,
so a large migration doesn't mean hand-merging its output into one file
either — see below.

### Migrating from an existing BIND 9.11 deployment

Three scripts in [`scripts/`](scripts/), meant to be run in this order,
help move an existing hand-run BIND 9.11 deployment onto this role:

- [`scripts/named_conf_to_zones.py`](scripts/named_conf_to_zones.py) reads
  `named.conf` itself — following its own `include` statements, and
  correctly handling zone stanzas with each directive on its own line in
  any order, which a naive line-window grep/awk approach silently drops —
  and produces the `<zone> <file>` list the other two scripts consume.
- [`scripts/check_ptr_records.py`](scripts/check_ptr_records.py) — cross-checks
  `A`/`AAAA` records against `PTR` records across all your forward and
  reverse zones, so existing forward/reverse DNS mismatches get caught
  *before* migration rather than carried across.
- [`scripts/zone_to_bind_vars.py`](scripts/zone_to_bind_vars.py) reads an
  existing master zone file — `$INCLUDE`s and all — and prints (or writes)
  the `bind_zones` entry above for it, instead of hand-transcribing each
  zone. It also detects any existing KSK/ZSK and writes a comment
  explaining how to carry (or deliberately not carry) that DNSSEC state
  into this role's automatic `dnssec-policy` management. Migrating
  hundreds of zones at once: its `--split-output DIR` writes one file per
  zone directly in the shape `bind_zones_vars_dir` reads (see **Managing
  many zones**, above), instead of one file you'd have to split up by hand.

Full docs, including known limitations: [`scripts/README.md`](scripts/README.md).

## GeoIP

BIND on RHEL 8+ (both the base `bind` package and `bind9.16`) is built
against MaxMind's GeoIP2 (`libmaxminddb`), not the legacy GeoIP library —
the role reflects that: `bind_geoip_enabled: true`
sets `geoip-directory` in `options{}` and lets `geoip <family> <value>`
match elements appear in `bind_acls` entries (validated in
`tasks/assertions.yml` — using one without `bind_geoip_enabled: true` fails
the play instead of failing silently at `named-checkconf` time on the
target).

```yaml
bind_geoip_enabled: true
bind_acls:
  us_ca_only: ["geoip country US", "geoip country CA"]
  recursion_clients: [10.0.0.0/8, us_ca_only]   # ACLs can nest other ACL names
```

Database files: either drop `.mmdb` files into `bind_geoip_directory`
yourself, or set `bind_geoipupdate_install: true` with
`bind_geoipupdate_account_id`/`bind_geoipupdate_license_key` (put these in
Ansible Vault, never plaintext inventory) to have the role install and run
`geoipupdate`. `bind_geoipupdate_run_now: false` by default so a fresh
install doesn't block on external network access during the play — flip it
on once credentials are in place, or run `geoipupdate` out of band /
scheduled via your own cron/systemd-timer role.

## Chroot

```yaml
bind_chroot_enabled: true
```

Installs `bind-chroot` (or `bind9.16-chroot`, if `bind_use_bind9_16` applies
— see **RHEL 8 and bind9.16** below) and switches from `named.service` to
`named-chroot`, which runs BIND rooted at `/var/named/chroot` (that path is
fixed by the package's unit file, not a role variable). RHEL's own `/etc/named-chroot.files`
already bind-mounts `/etc/named` and `/var/named` wholesale — since every
path this role manages (`bind_conf_dir`, `bind_zones_dir`, `bind_stats_dir`,
`bind_dnssec_keys_dir`) lives under one of those two trees, and
`bind_geoip_directory` defaults to `/usr/share/GeoIP` (also in RHEL's default
list), turning chroot on needs no other configuration. The one path outside
those trees, `bind_log_dir` (`/var/log/named`), gets added to
`/etc/named-chroot.files` automatically. Point anything else your own
config might need at the target through `bind_chroot_extra_paths` — a plain
list of host paths (files or directories) to bind-mount in as well. For
each path it adds, the role also creates the matching mount point under
`/var/named/chroot`: RHEL's chroot setup script only bind-mounts a
directory onto one that already exists in the chroot, and never creates
it, so without the mount point `named-chroot` fails to start.

Toggling `bind_chroot_enabled` on an already-deployed host cleanly switches
services in either direction: the role always checks both `named.service`
and `named-chroot.service` and stops/disables whichever one shouldn't be
active, so re-running the play after flipping the setting doesn't leave two
listeners fighting over port 53.

Bind-mounted paths keep the SELinux label already applied to the real
directory (a bind mount is the same inode at a second path, not a copy), so
the `named_log_t`/`named_zone_t`/`named_cache_t` fcontexts this role already
sets (see **SELinux / firewalld** below) apply inside the chroot with no
extra work.

New entries in `/etc/named-chroot.files` only take effect on a full service
restart (its `ExecStartPre` re-establishes the bind mounts; a `rndc reload`
does not) — the role handles this by notifying the same `restart named`
handler used for `bind_service_name`, which already resolves to
`named-chroot` once `bind_chroot_enabled` is set.

## RHEL 8 and bind9.16

RHEL 8's base `bind` package is 9.11, which predates `dnssec-policy`
(upstream added it in 9.16). RHEL 8 separately carries `bind9.16` —
Red Hat's AppStream backport of BIND 9.16, packaged under a different name
specifically so it can be installed as an alternative to the base package.
`bind_use_bind9_16` picks which one this role installs:

```yaml
# the actual default — bind_bind9_16_rpm is tasks/detect.yml's "is bind9.16 installed?" check
bind_use_bind9_16: >-
  {{ true if (ansible_facts['distribution_major_version'] | int == 8 and
  (bind_dnssec_enable_signing or (bind_bind9_16_rpm | default({})).rc | default(1) == 0)) else false }}
```

In practice you never need to set this yourself — it's already true by
default the moment `bind_dnssec_enable_signing: true` is set on a RHEL 8
host, and false (using the base `bind` package) otherwise. Once a host is
on `bind9.16` it stays there: [`tasks/detect.yml`](tasks/detect.yml) checks
whether `bind9.16` is installed, and that keeps the default true, so turning
signing off later never silently downgrades a host to 9.11. Set
`bind_use_bind9_16: false` explicitly if you do want to go back. The
variable also lets `bind9.16` be forced on for reasons other than DNSSEC,
and gives `tasks/assertions.yml` something concrete to check.

`bind9.16` and the base `bind` package **Conflict:** at the RPM level — they
own the same binary and systemd unit names and can't be installed together
(`bind9.16-dnssec-utils` even conflicts with `bind-utils` < 9.16).
[`tasks/install.yml`](tasks/install.yml) installs the selected flavor with
dnf's `allowerasing` on RHEL 8, so flipping `bind_use_bind9_16` on a
previously-deployed host swaps one flavor for the other in a single dnf
transaction — erasing whatever conflicts — instead of failing on the
conflict, or removing the old flavor first and leaving the host without
`named` if the install then fails. As with any package swap, dnf also
erases packages that depend on the erased flavor's packages. `bind9.16`'s
`named`/`named-chroot` services and
`/var/named/chroot` chroot layout are identical to the base package's — the
rest of this role doesn't need to know or care which flavor is installed.

On RHEL 9+, `bind_use_bind9_16` is asserted off — the base `bind` package is
already 9.16+ there, so the AppStream package doesn't exist and isn't needed.

## System crypto policy

RHEL sets which cryptographic algorithms are acceptable system-wide with
`update-crypto-policies` (DEFAULT, FUTURE, FIPS, …). Its BIND back end,
`/etc/crypto-policies/back-ends/bind.config`, lists the DNSSEC algorithms
and DS digest types the policy forbids, as `disable-algorithms` and
`disable-ds-digests` statements. RHEL's stock `named.conf` includes it
inside `options`, and so does this role (`bind_crypto_policy_enabled:
true`, the default), so named follows the same policy as the rest of the
system.

What that disables under the DEFAULT policy:

| Release | Disabled algorithms | Disabled DS digests |
|---|---|---|
| RHEL 8 | RSAMD5, DSA, NSEC3DSA, ECCGOST | GOST |
| RHEL 9, 10 | RSAMD5, RSASHA1, NSEC3RSASHA1, DSA, NSEC3DSA, ECCGOST | SHA-1, GOST |

named treats a zone signed only with a disabled algorithm as insecure
(unsigned): it still answers, just without validating it. The role
includes the file only if it exists on the host, so hosts without
crypto-policies still work. In a chroot it needs nothing extra, because
RHEL's `/etc/named-chroot.files` already lists it. Set
`bind_crypto_policy_enabled: false` to leave it out, or point
`bind_crypto_policy_file` at another file of the same statements.

After changing the system policy (`update-crypto-policies --set FUTURE`),
reload named (`rndc reconfig` or `systemctl reload named`). The role only
notices on its next run if something else in the config changed.

## DNSSEC key management (KSK/ZSK)

By default, `dnssec: true` on a zone (see **Master**, above) signs with
BIND's built-in `"default"` dnssec-policy — a single CSK
(combined signing/zone key), `ecdsap256sha256`, unlimited lifetime, never
rolled. That's a reasonable starting point, but it gives you no control
over key algorithm, size, or rollover schedule, and no separate KSK. To get
an actual KSK/ZSK split with its own rollover timing, define one or more
named policies in `bind_dnssec_policies` and point `bind_dnssec_policy` (or
a specific zone's `dnssec_policy`) at it by name:

```yaml
bind_dnssec_policies:
  strict:
    keys:
      - { role: ksk, lifetime: P1Y, algorithm: ecdsap256sha256 }
      - { role: zsk, lifetime: P30D, algorithm: ecdsap256sha256 }
    signatures_validity: P14D
    max_zone_ttl: P1D

bind_dnssec_policy: strict   # or set per-zone via bind_zones[].dnssec_policy
```

Each entry under `keys` needs `role` (`ksk`, `zsk`, or `csk`), `lifetime`
(a duration — `P1Y`, `30d`, or `unlimited`), and `algorithm`; `key_size` is
optional and only meaningful for `rsasha*` algorithms. The rest of a
policy's fields (`dnskey_ttl`, `publish_safety`, `retire_safety`,
`signatures_refresh`, `signatures_validity`, `signatures_validity_dnskey`,
`max_zone_ttl`, `zone_propagation_delay`, `parent_ds_ttl`,
`parent_propagation_delay`, `purge_keys`, `nsec3param`) are all optional —
BIND fills in its own defaults for anything you don't set. Full field list
and an example: [`defaults/main.yml`](defaults/main.yml)'s comment above
`bind_dnssec_policies`; rendering: [`templates/conf.d/dnssec-policies.conf.j2`](templates/conf.d/dnssec-policies.conf.j2).
`tasks/assertions.yml` fails the play up front if a policy has no `ksk`/`csk`
key, an unrecognized `role`, or if a zone points at a policy name that
doesn't exist — instead of a `named-checkconf` error on the target.

BIND itself then generates, publishes, activates, and rolls the actual key
files under `bind_dnssec_keys_dir` according to whichever policy applies —
this role doesn't (and, with `dnssec-policy` + `inline-signing`, shouldn't)
run `dnssec-keygen` itself. What the role *does* do, after `named` starts,
is help you see the result:

- **Key status**: for every master zone with `dnssec: true`, runs `rndc
  dnssec -status <zone>` and prints it during the play — KSK/ZSK key tags,
  states, and any pending rollover, without needing to log into the box.
- **DS record retrieval**: finds the zone's current KSK key file(s) under
  `bind_dnssec_keys_dir` — by content (the DNSKEY record's flags field is
  `257` for a KSK/CSK, `256` for a ZSK), not by guessing a filename, since
  `inline-signing` doesn't reliably produce the `dsset-<zone>.` files that
  manual `dnssec-signzone` does — runs `dnssec-dsfromkey` against each, and
  writes the result to `bind_dnssec_ds_output_dir/<zone>.ds` **on the
  control node** (default: `dnssec-ds-records/` next to the playbook). Hand
  that file's contents to your registrar/parent-zone operator to complete
  the delegation.

Both run automatically whenever `bind_dnssec_enable_signing` and
`bind_dnssec_manage_keys` (default `true`) are set — tagged `dnssec_keys`
if you'd rather skip them on routine runs and invoke them selectively
(`--tags dnssec_keys` / `--skip-tags dnssec_keys`). Pending handlers are
flushed just before these steps, so a zone that was only just given
`dnssec: true` is already loaded under its policy when they run. Key
generation happens in the background shortly after `named` first loads a
zone under a new policy, so on a *freshly* signed zone the DS-record step
retries for up to `bind_dnssec_key_wait_retries × bind_dnssec_key_wait_delay`
seconds (30s by default) before giving up for that run with a message to
re-run the play once keys exist. The wait shows as an ignored failure in
the play output, but it doesn't fail the play, since it's an expected,
temporary condition rather than a misconfiguration.

## Reverse zones

Reverse (`in-addr.arpa`/`ip6.arpa`) zones use exactly the same `bind_zones`
entry shape as forward zones — `type: master` or `type: slave` both work
identically, since neither the role nor `templates/zone.db.j2` treats zone
direction specially. The only difference is the zone `name` and the record
types you put in it (`PTR` instead of `A`/`AAAA`):

```yaml
# Master, alongside the example.com zone — covers 10.0.1.0/24
bind_zones:
  - name: 1.0.10.in-addr.arpa
    type: master
    allow_transfer_acl: transfer_hosts
    also_notify: [10.0.1.11]
    primary_ns: ns1.example.com
    nameservers: [ns1.example.com, ns2.example.com]
    records:
      - { name: "10", type: PTR, value: "ns1.example.com." }
      - { name: "11", type: PTR, value: "ns2.example.com." }
      - { name: "20", type: PTR, value: "www.example.com." }

# Slave — pulls the zone above via AXFR/IXFR, same as any forward zone
bind_zones:
  - name: 1.0.10.in-addr.arpa
    type: slave
    masters: [10.0.1.10]
```

See [`examples/host_vars/dns-master-01...`](examples/host_vars/dns-master-01.example.internal.yml)
and [`dns-slave-01...`](examples/host_vars/dns-slave-01.example.internal.yml)
for this paired alongside the existing forward zone.

Two things worth knowing that are about DNS itself, not this role:

- **Subnets not aligned on an octet boundary** (anything other than a /8,
  /16, or /24) can't have their own `in-addr.arpa` zone — the parent zone
  still owns that octet. The standard workaround is
  [RFC 2317](https://www.rfc-editor.org/rfc/rfc2317) classless delegation:
  the parent zone (e.g. `0.168.192.in-addr.arpa` for a /27 carved out of
  `192.168.0.0/24`) delegates each address via a `CNAME` to
  `<addr>.<subnet-id>.0.168.192.in-addr.arpa`, and *that* zone — named for
  the subnet, not a plain octet — is what you host here as a normal
  `bind_zones` entry with `PTR` records. `records` on the parent zone needs
  the `CNAME` pointers; `records` on the RFC 2317 zone needs the `PTR`s.
- **IPv6 PTR zones** (`ip6.arpa`) use the same `bind_zones` shape, just with
  nibble-reversed zone names (e.g. `2001:db8::/32` is
  `8.b.d.0.1.0.0.2.ip6.arpa`) and full nibble-reversed owner names on each
  `PTR` record — this role doesn't compute that reversal for you, since it's
  standard DNS zone-file content, not role-specific configuration.

## Logging: individual files, and the existing Elasticsearch pipeline

By default the role writes one file per category:
`{{ bind_log_dir }}/queries.log`, `xfer-in.log`, `security.log`, and so on.

There's already an ingest pipeline for BIND logs in the companion
repository [`elastic-bind`](https://github.com/jmaughmer/elastic-bind), built
against a **single** consolidated log file with 17 of the 18 categories
this role defaults `bind_log_categories` to. The 18th is `query-errors`:
failed queries such as `query failed (SERVFAIL) for www.example.com/IN/A`,
in `query-errors.log`. The pipeline indexes those lines too, with the
client and `event.outcome: failure`. Two variables pick the layout, and
both can be on at once:

| `bind_log_consolidated` | `bind_log_individual_files` | Files written |
|---|---|---|
| `false` (default) | `true` (default) | one file per category |
| `true` | `false` (default when consolidated) | `named.log` only |
| `true` | `true` | `named.log` **and** one file per category |

- **Per-category files**: point Elastic Agent's Custom Logs "Paths" at
  `{{ bind_log_dir }}/*.log`. The pipeline parses `bind.category` out of the
  line content (`print-category yes` is set on every channel), not the
  filename, so this works unmodified.
- **Consolidated file**: set `bind_log_consolidated: true`. The role then
  renders the *exact* channel/category layout from that pipeline's
  `named.conf.logging.conf` (same filename by default:
  `{{ bind_log_dir }}/named.log`), for drop-in compatibility.
- **Both**: also set `bind_log_individual_files: true`. Every line goes to
  `named.log` and to its category's own file, so you can ship the one file
  and still read each category separately on the server. Point Elastic Agent
  at `named.log` only: a `*.log` glob would send every line twice.

**Rolling.** Per-category files roll at `bind_log_file_size` (default
`100m`) and keep `bind_log_file_versions` (default 3) rolled copies besides
the live one, so each takes at most about 400 MB. The consolidated file
collects every category, so it has its own settings,
`bind_log_consolidated_size` and `bind_log_consolidated_versions`. They
default to the per-category values:

```yaml
bind_log_consolidated: true
bind_log_consolidated_size: 500m
bind_log_consolidated_versions: 5
```

**Keeping query logs local.** To keep a query log on the server without
sending it to the log server, use the consolidated layout and exclude the
`queries` category from the shipped file:

```yaml
bind_log_consolidated: true
bind_log_consolidated_exclude: [queries]
```

Queries then go only to `{{ bind_log_dir }}/queries.log`, with the
per-category rolling, while everything else still goes to `named.log`,
which Elastic Agent ships. Any category in `bind_log_categories` can be
excluded the same way, in the consolidated-only and in the both layout. In
the per-category-only layout every category already has its own file, so
there you point Elastic Agent's paths at the files you want instead of
`*.log`, or add `queries.log` to its excluded files. To stop query logging
altogether, set `bind_querylog: false`.

Either way, `bind_log_print_time: "yes"` (the default) matches what that
pipeline's grok expects as its primary format (BIND 9.11-safe legacy
timestamps, no UTC offset — see that repo's README for the timezone caveat
this implies for Elastic Agent config). Set it to `"iso8601-utc"` only once
every target host is confirmed BIND 9.12+.

### DNS answers (dnstap)

The `queries` log only ever records the *question* (name, class, type,
flags) — BIND has no text logging channel that includes answer records. To
log answers, turn on BIND's [dnstap](https://kb.isc.org/docs/aa-01342)
capture, which records the complete DNS message: question,
answer/authority/additional sections, rcode and flags.

```yaml
bind_dnstap_enabled: true
bind_dnstap_types: [client response]   # the default; add "resolver response" on resolvers
```

- `client response` (the default) captures every answer the server sends
  its clients, on authoritative and recursive hosts alike. On recursive
  hosts, add `resolver response` to also capture the answers named gets
  back from upstream servers.
- **Answer latency** (`event.duration`) needs the queries captured too.
  BIND stamps each dnstap message with one time only: the query time on
  queries and the response time on responses. The export
  ([below](#exporting-dnstap-to-elasticsearch)) therefore computes latency
  by pairing each response with its query. It matches on client address
  and port, transport, DNS ID and question. To enable it, add the query
  type that matches the host's role:
  - authoritative: `[auth query, client response]`. named logs a query it
    answers from its own zones (recursion off) as `auth query`, not
    `client query`, so `client query` captures nothing on an
    authoritative-only server.
  - resolver: `[client query, client response]`.

  Capturing queries roughly doubles the dnstap volume. A query still
  waiting for its answer when a run ends is kept in the state file, so the
  pair still matches if the answer lands in the next rolled file. Queries
  unanswered after 30 seconds are dropped.
- Output goes to `{{ bind_log_dir }}/dnstap.tap`, rolled at
  `bind_dnstap_file_size` and keeping `bind_dnstap_file_versions` old files
  (same defaults as the text logs: 100m × 3). `rndc dnstap -roll` rolls it
  on demand. It lives in the log directory, so the chroot bind mount and
  the `named_log_t` SELinux label already cover it.
- It's a binary Frame Streams file, not text. Read it on the host with
  `dnstap-read` (in `bind-utils`/`bind9.16-utils`): `-p` for one line per
  message plus the full message in zone-file format, `-y` for YAML.
- It's deliberately not named `*.log`, so the Elasticsearch pipeline's
  per-category `*.log` glob never picks up the binary file. To get answers
  into Elasticsearch, see **Exporting dnstap to Elasticsearch** below.
- It's off by default because it writes a record for every captured
  message — size the rotation settings for your query rate.
- Needs BIND 9.12+ for rotation: RHEL 9+, or RHEL 8 with
  `bind_use_bind9_16: true`. RHEL 8's base `bind` (9.11) can only write one
  file that grows without limit, so enabling dnstap there fails the play
  with a message saying so.

```bash
dnstap-read -p /var/log/named/dnstap.tap
```

### Exporting dnstap to Elasticsearch

Elastic Agent can't read dnstap's binary format, so the role can convert it
to JSON for you:

```yaml
bind_dnstap_enabled: true
bind_dnstap_export_enabled: true
```

That installs a converter
([`files/bind-dnstap-to-ndjson.py`](files/bind-dnstap-to-ndjson.py) —
standard-library Python, nothing extra to install) and a systemd timer,
`bind-dnstap-ndjson.timer`, that runs it every
`bind_dnstap_export_interval` (default `1min`). Each run:

1. rolls the live capture with `rndc dnstap -roll`, so nothing waits for
   the size limit;
2. decodes every rolled `dnstap.tap.N` file it hasn't converted yet (it
   records finished files in `/var/lib/bind-dnstap-ndjson/state.json`);
3. appends one JSON object per DNS message to
   `{{ bind_log_dir }}/dnstap.ndjson`, rotating it itself at
   `bind_dnstap_ndjson_size` × `bind_dnstap_ndjson_versions` (the text-log
   defaults: 100m × 3).

Each line already uses Elastic Common Schema field names, and Elastic
Agent decodes it with its `ndjson` parser — see
[`examples/elastic-agent-dnstap.yml`](examples/elastic-agent-dnstap.yml)
(dataset `bind.dnstap`, path `/var/log/named/dnstap.ndjson*`). That config
also routes events through `logs-bind.dnstap@custom` from
[`elastic-bind`](https://github.com/jmaughmer/elastic-bind), which
adds registered domain/subdomain/TLD, `event.outcome`, `event.action` and
`related.ip`, alongside a component template with the field mappings; load
both with that repo's `setup.sh` first. That repo also has Kibana
dashboards for the exported answers and for the text logs, and alerting
rules for the answers (NXDOMAIN and random-subdomain spikes, failures,
slow answers, possible DNS tunnelling, and the export stopping). One event as the
converter writes it, pretty-printed:

```json
{
  "@timestamp": "2026-10-14T14:00:00.103500Z",
  "event": {"kind": "event", "category": ["network"], "type": ["protocol"], "duration": 3500000},
  "network": {"protocol": "dns", "transport": "udp", "type": "ipv4"},
  "client": {"ip": "10.0.0.5", "port": 51234},
  "server": {"ip": "10.0.0.1", "port": 53},
  "dns": {
    "type": "answer", "id": 48879, "op_code": "QUERY", "response_code": "NOERROR",
    "header_flags": ["AA", "RD", "RA"],
    "question": {"name": "www.example.com", "type": "A", "class": "IN"},
    "answers": [
      {"name": "www.example.com", "type": "CNAME", "class": "IN", "ttl": 300, "data": "web.example.com"},
      {"name": "web.example.com", "type": "A", "class": "IN", "ttl": 60, "data": "192.0.2.1"}
    ],
    "resolved_ip": ["192.0.2.1"]
  },
  "observer": {"vendor": "ISC", "product": "BIND", "type": "dns", "hostname": "ns1", "version": "9.16.23-RH"},
  "bind": {"dnstap": {"message_type": "CLIENT_RESPONSE", "socket_protocol": "UDP"}}
}
```

`source`/`destination` mirror `client`/`server` and are left out above.
Authority and additional records, which ECS has no fields for, go under
`bind.dnstap.authorities` / `.additionals`.

`event.duration` (in nanoseconds) is present only on answers the converter
could pair with their query. That requires capturing the queries as well;
see **Answer latency** under [DNS answers (dnstap)](#dns-answers-dnstap).
Without it, the Kibana latency panels and the slow-answers alert stay
empty.

Things to know:

- **Volume:** one Elasticsearch document per captured message. Size the
  `bind.dnstap` data stream's lifecycle (ILM) policy for your query rate,
  or narrow what's captured with `bind_dnstap_types`.
- **Delay:** answers reach Elasticsearch up to one
  `bind_dnstap_export_interval` after they're sent.
- **Binary history:** rolling every interval means the
  `bind_dnstap_file_versions` rolled `dnstap.tap.N` files cover only the
  last few intervals; the JSON output is the long-term copy.
- **If the converter stops** (`systemctl status bind-dnstap-ndjson`),
  named goes back to rolling only at the size limit, so up to
  `bind_dnstap_file_versions` × `bind_dnstap_file_size` of capture waits
  for it to catch up; anything named prunes beyond that is lost.
- **Delivery is at-least-once:** a crash partway through a file re-sends
  that file's events on the next run.
- Setting `bind_dnstap_export_enabled: false` later removes the timer and
  converter; JSON already written is left in place.

## Statistics

`bind_zone_statistics: true` (default) turns on the standard
`zone-statistics` counters. `bind_statistics_channels_enabled: true`
(default) also opens BIND's small built-in HTTP stats server
(`statistics-channels`), bound to `127.0.0.1:8053` by default — change
`bind_statistics_channel_address`/`_port`/`_allow` to expose it elsewhere.
Binding it beyond loopback additionally opens that port in `firewalld`.
Wherever it's bound, the stats listener needs two SELinux settings, which
the role applies: the port is labeled `http_port_t`, and the
`named_tcp_bind_http_port` boolean is turned on — RHEL's policy only lets
`named_t` bind `http_port_t` with that boolean set, so the label alone
isn't enough.

## Performance tuning

BIND's own defaults already cover the settings most often tuned by hand:
every RHEL 8+ build defaults `edns-udp-size`/`max-udp-size` to 1232 (DNS
Flag Day 2020), `max-cache-size` to 90% of RAM, and `prefetch` to `2 9`,
so the role leaves those alone. What it sets by default:

- **`minimal-responses no-auth-recursive`** (`bind_minimal_responses`) —
  leaves authority/additional records out of answers that don't need them:
  smaller responses, less work per query, fewer truncations to TCP. This is
  BIND 9.16+'s own default; setting it brings RHEL 8's 9.11 (default `no`)
  in line.
- **`ixfr-from-differences yes`** on master zones (`bind_ixfr_from_differences`)
  — when a zone file changes, named journals the difference so secondaries
  get a small IXFR instead of re-transferring the whole zone. DNSSEC zones
  already get this from `inline-signing`. It relies on the SOA serial
  increasing with every change, which the role handles for zones whose
  `records` it manages without a pinned `serial`. On RHEL 8's 9.11 journals
  default to growing up to 2 GB; cap them with `bind_max_journal_size`.

Query logging is the most expensive thing named does per query — BIND's
documentation warns its cost "may be significant on heavily loaded
servers". It stays on (`bind_querylog: true`) because the Elasticsearch
pipeline above reads `queries.log`; turn it off on busy resolvers that
don't need it, or set `bind_log_buffered: true` so named stops flushing
every log line to disk as it's written (lines then reach the log, and
Elastic Agent, a little later, and the last few can be lost if named
crashes).

Everything else is workload-dependent, so it's off or at BIND's default
unless you set it:

| Variable | BIND default | Raise or set when |
|---|---|---|
| `bind_recursive_clients` | 1000 | A busy resolver logs `no more recursive clients` |
| `bind_max_cache_size` | 90% of RAM | named shares the host with other services (e.g. `"50%"`, `"4g"`) |
| `bind_tcp_clients` | 150 | Many clients use TCP (large responses, DoT proxies, zone transfers) |
| `bind_transfers_in` / `bind_transfers_per_ns` | 10 / 2 | A secondary pulls hundreds of zones from one primary |
| `bind_serial_query_rate` | 20/s | A secondary refreshes hundreds of zones |
| `bind_transfers_out` / `bind_notify_rate` | 10 / 20/s | A primary serves hundreds of zones to its secondaries |
| `bind_rate_limit` | off | An authoritative server is reachable from the internet |

`bind_rate_limit` turns on response rate limiting, which caps identical
responses per client netblock and blunts DNS amplification attacks bounced
off the server. Each key is a `rate-limit` option:

```yaml
bind_rate_limit:
  responses-per-second: 10
  window: 5
  exempt-clients: [trusted]   # list values render as an address match list
```

## rndc key

`rndc`, and the role itself (DNSSEC key status, the dnstap export),
control `named` with the key in `/etc/rndc.key`. By default the role
generates a random key on each host the first time, as RHEL itself would,
and never changes it afterwards.

To use a key you already have, supply its secret from Ansible Vault. You
might want this to keep a host's existing key across a rebuild, or to
manage every server's key centrally instead of leaving each one random:

```yaml
# group_vars/bind_dns/vault.yml, encrypted with ansible-vault
vault_bind_rndc_key_secret: "<base64 secret>"
```

```yaml
# group_vars/bind_dns/main.yml
bind_rndc_key_secret: "{{ vault_bind_rndc_key_secret }}"
bind_rndc_key_name: rndc-key          # the default; must match the other end
bind_rndc_key_algorithm: hmac-sha256  # the default
```

Generate a new secret with `rndc-confgen -A hmac-sha256 | grep secret`, or
take it from an existing host's `/etc/rndc.key`. With a secret set, the
role writes `/etc/rndc.key` (root:named, 0640) on every run and restarts
`named` when it changes. The task runs with `no_log`, so the secret
appears in neither output nor `--diff`. The `controls` block in
`named.conf` only accepts commands from 127.0.0.1. Remote `rndc` would need
a `controls` entry for the management host, which this role doesn't add.

To go back to a generated key, empty `bind_rndc_key_secret` and delete
`/etc/rndc.key`; the next run generates a new one.

## SELinux / firewalld

`bind_manage_selinux` / `bind_manage_firewalld` (both default `true`) apply:

- `firewalld`: opens the `dns` service (53/tcp+udp), plus the statistics
  port if bound beyond loopback. Skipped with a debug note if firewalld
  isn't installed; if it's installed but stopped, only the permanent
  configuration is written.
- SELinux: the `named_write_master_zones` boolean when any master zone or
  DNSSEC signing is in use; file contexts `named_log_t` on the log
  directory, `named_zone_t` on the zones directory, and `named_cache_t`
  (the type RHEL uses for directories `named` writes to) on the slave zone,
  DNSSEC key and managed-keys directories; and, for the statistics channel,
  the `http_port_t` port label plus the `named_tcp_bind_http_port` boolean.
  Directories whose file context changes are relabeled right away, before
  `named` starts.

The SELinux part is skipped gracefully (with a debug note) if SELinux is
disabled on the target.

## Testing

[`molecule/default/`](molecule/default/) runs the role against three
systemd containers on one container network, mirroring
[`examples/`](examples/):

| Instance | Role in the test |
|---|---|
| `ns-master` | DNSSEC-signing primary with a custom KSK/ZSK policy, role-managed forward and reverse zones, a zone loaded from `zones.d/`, and response rate limiting |
| `ns-slave` | Secondary that transfers all three zones from the primary |
| `resolver` | Caching resolver forwarding `example.test` to the primary, with DNS64, tuning options, and dnstap export |

Molecule converges the three (primary first), converges them again to
check nothing changes the second time, then
[`verify.yml`](molecule/default/verify.yml) checks real DNS behavior with
`dig`:

- the primary answers from its zones and signs `example.test`, writes its
  DS record on the control node, logs queries, and serves statistics;
- the secondary has transferred every zone (still signed) and saved them
  to disk;
- the resolver answers through its forward zone, synthesizes a DNS64
  AAAA record, refuses recursion to a client outside its ACL, and exports
  dnstap answers as JSON.

Inside containers SELinux is off and firewalld isn't installed, so the
tests exercise the role's skip paths for both.

The default scenario uses Podman (rootless works). A `docker` scenario
runs the same test on Docker, sharing the default scenario's playbooks,
inventory (`molecule/default/inventory/`) and `zones.d/`. The servers find
each other through gathered facts rather than fixed addresses, so the
container network's subnet doesn't matter.

[`molecule/chroot/`](molecule/chroot/) covers chroot with one server,
switched the way an existing host would be: `prepare.yml` deploys the
role with chroot off, then converge turns it on. `verify.yml` checks that
`named-chroot` replaced `named.service`, that `named` really runs with
`/var/named/chroot` as its root, that the log directory and
`bind_chroot_extra_paths` are bind-mounted in and listed once each in
`/etc/named-chroot.files`, and that DNSSEC signing, query logging and
dnstap all work from inside the chroot. The same switch replaces the
generated rndc key with a supplied, vault-encrypted one (decrypted with
the test-only `vault-password.sh`), and `verify.yml` checks `rndc` still
controls the chrooted `named` with it. In a rootless container,
`named-chroot`'s setup can't create the chroot's `/dev` device nodes, so
that one detail differs from a real host; `named` runs fine without them.

[`molecule/geoip/`](molecule/geoip/) checks that GeoIP ACLs really match
by country. `prepare.yml` installs MaxMind's public GeoLite2-Country *test*
database (pinned to a commit and checksum; no MaxMind account needed) and
gives the container one address from a GB test network and one from an SE
network. A zone whose `allow_transfer_acl` is `geoip country GB` must then
transfer to the GB address and refuse the SE and loopback addresses.
`geoipupdate` itself isn't exercised, since it needs real MaxMind
credentials.

[`molecule/dnstap/`](molecule/dnstap/) tests dnstap capture and the
Elasticsearch export on one authoritative server. `verify.yml` covers four
things:

1. **Live export.** It sends real queries through `named` (A, MX, NXDOMAIN,
   and AAAA over TCP) and runs the export service. It then checks the
   exported JSON field by field (including that every answer was paired
   with its `auth query` and has a latency), that the file is owned by `named` with mode
   0640, and that a second run doesn't export anything twice.
2. **Converter on the host's own Python** (platform-python 3.6 on EL8). It
   runs the converter on prepared dnstap files from
   [`make_test_dnstap.py`](molecule/dnstap/files/make_test_dnstap.py). These
   cover:
   - name compression and EDNS;
   - TXT escaping and RRSIG;
   - IPv6 over TCP;
   - a truncated file, which is reported with exit code 1 while its good
     frames are kept;
   - skipping the live file and non-rolled files;
   - answer latency from query/response pairing, both within one file and
     across runs through the state file;
   - not converting anything twice;
   - output rotation.
3. **Turning the export off.** It applies the role with the export
   disabled, then checks the timer, units and converter are removed while
   the capture and the exported JSON stay.
4. **Rocky 8 only.** It checks that enabling dnstap on the base BIND 9.11
   fails with its explanation.

Requirements: Podman or Docker, and the Python packages in
[`molecule/requirements.txt`](molecule/requirements.txt). On Windows, run
from a WSL shell. The containers use Jeff Geerling's systemd-enabled
`docker-rockylinuxN-ansible` images; `MOLECULE_DISTRO` picks the EL
release (default `rockylinux9`):

```bash
pip install -r molecule/requirements.txt
```

```bash
molecule test
```

```bash
MOLECULE_DISTRO=rockylinux8 molecule test
```

```bash
MOLECULE_DISTRO=rockylinux10 molecule test
```

```bash
molecule test -s chroot
```

```bash
molecule test -s geoip
```

```bash
molecule test -s dnstap
```

```bash
molecule test -s docker
```

On Rocky 8, the primary's DNSSEC signing and the resolver's dnstap both
switch those hosts to `bind9.16`, while the secondary stays on the base
BIND 9.11 package, so one run covers both RHEL 8 flavors — `verify.yml`
checks each host ends up on the expected one. Rocky 8's only Python is
3.6, which ansible-core 2.17+ can't manage, so
[`prepare.yml`](molecule/default/prepare.yml) installs Python 3.11 on EL8
containers first (see **Requirements**). While working on
the tests, `molecule converge` and `molecule verify` run those stages
without destroying the containers; `molecule destroy` cleans up.

## Design notes / things deliberately left out

- **No BIND views.** Each host is one thing (authoritative XOR recursive) by
  design, per the brief. If you need split-horizon answers from a single
  process, that's a real feature gap here, not an oversight — it's a
  meaningfully bigger config shape (per-view ACLs, zone duplication, match
  ordering) that deserves its own variable design rather than being bolted
  onto this one.
