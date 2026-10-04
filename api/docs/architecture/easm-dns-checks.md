# EASM DNS-only checks: dangling DNS and email posture

> RFC-036 P1. Built. Passive (tier T0): the platform asks its own recursive
> resolver about the tenant's names. The only direct queries are DNS
> questions about the tenant's own name to the name servers of its parent
> zone and of its delegation, for the lame-delegation check below. Nothing is
> sent to the tenant's hosts or to the CNAME targets, and no HTTP request is
> made.

## What runs

A daily controller (`internal/infra/controller/easm_dns_checks.go`, name
`easm-dns-checks`) runs two checks for every active tenant that has the
`attack_surface` module (O10):

| Check | Names | Finds | Exposure type |
|---|---|---|---|
| Dangling DNS | active `domain` and `subdomain` assets | a CNAME whose target does not exist; a delegation whose name servers do not exist | `dangling_cname`, `dangling_ns` |
| Email posture | active `domain` assets that are registrable domains (subdomains inherit the organisation's DMARC policy) | SPF, DMARC, MTA-STS and TLS-RPT gaps | `email_security_weak` |

Code: `internal/app/easmdns` (checks, service), `pkg/dnsprobe` (DNS client),
`internal/infra/postgres/easm_dns_repository.go`, migration 000325.

**Attribution.** Every asset is checked except those whose attribution is
`rejected` (RFC-036 §6.4). A name awaiting review is still checked: looking
up a name under the tenant's domain is passive, and a dangling record there is
worth knowing before anyone has confirmed the host.

## Dangling DNS

For each name: ask for its `A` record. The resolver follows CNAMEs; when the
chain ends in a name that does not exist it answers `NXDOMAIN` **with** the
CNAME chain, which is how the check sees the dangling target (`net.Resolver`
hides this, hence `pkg/dnsprobe`). Names without a CNAME are then asked for
`NS`; a delegation is dangling when its name servers do not exist.

| Finding | Severity | Why |
|---|---|---|
| CNAME (or all name servers) on a registrable domain that is not registered | high | whoever registers that domain answers for the tenant's name |
| CNAME to a provider that [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) marks *Vulnerable*, target `NXDOMAIN` | medium | anyone can claim that name at the provider. Medium until a sensor confirms (nuclei `takeover`, T1) — the exposure carries `confirmation: pending` |
| all name servers of a delegation missing (their domain registered) | medium | the zone does not resolve; one registration away from takeover if the provider allows it |
| some name servers missing | low | broken redundancy |
| every delegated name server exists but none answers authoritatively for the zone (lame delegation) | medium | the name does not resolve; at many DNS providers whoever creates the zone on those servers controls it |
| some delegated name servers lame | low | broken redundancy |
| CNAME to any other missing target | low | a broken record, not a known takeover path |

"Registrable domain" is one label below the ICANN public suffix. Private
suffixes in the Public Suffix List (`azurewebsites.net`, `herokuapp.com` …)
are deliberately ignored there: a missing `x.azurewebsites.net` is a
provider-claimable name, reported with the provider, not an unregistered
domain.

**Fingerprints.** `internal/app/easmdns/fingerprints/can-i-take-over-xyz.json`
is the project's `fingerprints.json`, copied unmodified, under CC BY 4.0 (the
FSF lists it as GPLv3-compatible); attribution and the source commit are in
`fingerprints/NOTICE.md`. Only `service`, `cname`, `status` and `nxdomain` are
read.

## Takeover confirmation

A `dangling_cname` stays medium with `confirmation: pending` until a sensor
confirms it. Confirmation is a **nuclei takeover template** (tagged
`takeover`, or a template id `<provider>-takeover[-detection]`) that matches
the same name in a scan the tenant ran (`internal/app/ingest/takeover.go`,
`internal/app/easmdns/takeover.go`):

- the report must be bound to a command the tenant's sensor ran (RFC-040
  §5.3), and the asset must be one the report created or the command's
  targets cover; unsolicited reports, uploads and imports confirm nothing;
- the asset must have an **active** `dangling_cname` from this check; a
  template match alone (an HTTP fingerprint) never raises a high;
- the platform then raises `subdomain_takeover` (**high**, migration
  000485; details: template, sensor, command, matched text, the
  dangling exposure) and sets `confirmation: confirmed` on the
  `dangling_cname`.

**No new probe path.** The confirming request is an ordinary tenant scan,
which went through the active-probe gate (scope exclusions, attribution:
only confirmed assets, zones; see
[active-probe-gate.md](active-probe-gate.md)) before the command existed.
Nothing is dispatched from here.

**Lifecycle.** The takeover shares the name's identity with the DNS check: a
check that finds the CNAME fixed (or replaced by a delegation) resolves the
takeover with the `dangling_cname`, and a takeover this check resolved is
reopened by the next confirmation. A person's resolution is never reopened.

## Email posture

DNS TXT only:

| Check | Raised when | Severity (mail domain / domain without MX) |
|---|---|---|
| SPF (RFC 7208) | missing | medium / low |
| | more than one record (permerror) | medium |
| | `+all` | high |
| | `?all`; no `all` and no `redirect` | low |
| | more than 10 DNS-querying terms after following `include`/`redirect` (at most 20 records fetched, loops counted once) | medium |
| DMARC ([RFC 9989](https://www.rfc-editor.org/rfc/rfc9989), which obsoletes RFC 7489) | missing | medium / low |
| | more than one record | medium |
| | `p=none` or no `p` (RFC 9989 treats it as none) | low |
| | test mode `t=y`, or the legacy `pct` below 100 | low |
| | `sp=none` under an enforcing `p` | low |
| | no `rua` | info |
| MTA-STS (RFC 8461) / TLS-RPT (RFC 8460) | TXT record missing on a domain with MX | info |

An exposure is raised only when at least one issue is low or above; info
items ride along in `details.issues`. A domain with a null MX (`MX 0 .`) is a
non-mail domain: it should still publish `v=spf1 -all` and an enforcing
DMARC record, and gaps there are low.

**Not checked:** DKIM (it needs the selector, and guessing selectors is a
brute-force probe; a tenant-provided selector list is future work) and the
MTA-STS policy file (fetched over HTTPS from the tenant's host, not DNS-only).

## Lifecycle of an exposure

- Found: upserted by fingerprint (source `easm_dns`; the title carries only
  the name, so a record that changes target keeps one exposure).
- Fixed: the next check that finds nothing resolves it, with a state-history
  row and the note `Resolved automatically: …`.
- Broken again: the same exposure is reopened — only if this check resolved
  it. A person's resolution, acceptance or false-positive mark is never
  touched.
- Resolver failure (SERVFAIL, timeout): nothing is concluded, raised or
  resolved; the outcome `unknown` is stored.

**Lame delegation.** When the resolver answers SERVFAIL for a name (what a
lame delegation looks like through a recursive resolver), the check
(`internal/app/easmdns/lame.go`):

1. finds the parent zone by asking the resolver for `NS` of each ancestor,
   stopping at the registrable domain, so public-suffix (TLD) servers are
   never asked;
2. asks up to 3 addresses of the parent's name servers for the name's `NS`
   **without recursion** (`dnsprobe.QueryServer`, RD=0) and reads the referral
   from the authority section (an authoritative answer means the name is not
   delegated: nothing concluded);
3. asks each delegated name server (at most 8) for the name's `SOA` without
   recursion; a server that does not answer authoritatively is lame, one that
   does not exist is missing.

All servers lame or missing: `dangling_ns` medium with `lame_name_servers` in
the details; some: low; none: nothing concluded (`unknown`, the SERVFAIL has
another cause, e.g. DNSSEC). **Safety:** every server address comes from DNS
data, so `QueryServer` accepts only a public IP literal under the platform's
SSRF policy (`httpsec.IsIPBlocked`: loopback, RFC 1918, link-local/metadata,
CGNAT … refused before anything is sent), always port 53, through the same
rate limiter and 3 s bound. A delegated server reachable only at a refused
address is not judged at all, so a private name server is never called lame.

## Scale and politeness

- One rate limiter for all tenants (`EASM_DNS_QPS`, default 20 queries/s),
  3 s per query, UDP with TCP retry on truncation, at most 64 answer records
  read per response.
- Per tenant and check: names checked longest ago first, at most
  `EASM_DNS_MAX_NAMES_PER_RUN` (500) per run, a 30-minute budget, a name
  checked within 5/6 of the interval is not due (restarts do not re-check),
  and a per-tenant controller lease (`easm_dns:<tenant>:<kind>`, RFC-046 P1.8) so two API replicas never run the same
  tenant's check at once. State: `easm_dns_check_state`.

## Configuration

| Variable | Default | |
|---|---|---|
| `EASM_DNS_CHECKS_ENABLED` | `false` | off until the scans P1 work lands (claim-N with `SKIP LOCKED`, controller leases, write-amplification fixes): a daily controller over every tenant should not run by default before that. Turn it on per deployment; the per-run cap and budget bound it |
| `EASM_DNS_RESOLVER` | first `nameserver` of `/etc/resolv.conf` | `host[:port]` of a recursive resolver |
| `EASM_DNS_QPS` | `20` | |
| `EASM_DNS_CHECK_INTERVAL` | `24h` | RFC-036 O9: daily light checks |
| `EASM_DNS_MAX_NAMES_PER_RUN` | `500` | |

The resolver sees which names the tenant owns. Point `EASM_DNS_RESOLVER` at
an internal resolver if that matters; a public resolver also works. Its
answers may be cached for up to the record TTL, so a fix can take that long
to clear.

## Cadence tiers (O9)

O9 sets the fastest shared cadence at **Tier A: daily light checks and weekly
nuclei**. These DNS checks are the daily light part for every name (they are
cheap and passive), so they do not wait for tiers. The weekly nuclei part is a
sensor scan: today a tenant expresses it as a **weekly scan configuration**
(`schedule_type=weekly`, nuclei, on an asset group of its Tier A assets);
the scan gate skips members that are not confirmed. The platform creates no
scan schedule by default — nothing scans a tenant's hosts unless the tenant
sets it up (owner decision if that should change). Automatic tier assignment
is RFC-036 P4.

## Related

- [easm.md](easm.md), RFC-036 and its
  [assurance appendix](../rfcs/RFC-036-appendix-assurance.md).
- [certificate-transparency-monitoring.md](certificate-transparency-monitoring.md):
  the other daily passive collector.
