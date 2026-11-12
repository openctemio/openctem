# RFC-083: Passive lookalike-domain monitoring

| | |
|---|---|
| Status | Implemented (2026-10-11) |
| Scope | api (`pkg/domain/lookalike`, `internal/app/easm/lookalikes.go`, `lookalike_ct.go`, `/api/v1/easm/lookalikes`, `easm-lookalikes` controller, exposure type `lookalike_domain`, one migration), web (Attack surface › Lookalikes) |
| Architecture | [easm.md §4l](../architecture/easm.md#4l-lookalike-domains-built) |
| Related | RFC-036 (EASM; phase P6, decision O5: lookalikes passive only), RFC-054 (scope entries, verified domains), research/22 E4 (EASM alerts) |

## 1. Summary

Phishing and brand abuse start with a domain that looks like the
organization's own. The platform now watches the organization's root domains
for registered lookalikes:

- **Generation** (local, no network): missing, doubled and swapped letters,
  neighbouring and extra keys, hyphens, bit flips, look-alike characters
  (ASCII sequences such as `rn`/`m` and the common Cyrillic and Greek
  confusables, as punycode) and other top-level domains. Every candidate is a
  valid registrable name; at most 1000 per watch (default 300).
- **Passive checks only** (decision O5): an NS query through the platform
  resolver says whether the name is registered; A/AAAA and MX queries whether
  it serves addresses or receives mail; crt.sh says how many unexpired
  certificates name it. No candidate host is ever contacted.
- A registered candidate is a **`lookalike_domain` exposure** (medium when it
  receives mail, or serves addresses with a certificate; low otherwise),
  announced through the EASM alert path (immediate for medium on an approved
  asset, otherwise the daily digest). A candidate that stops resolving is
  resolved automatically.
- **Review queue:** Attack surface › Lookalikes lists registered lookalikes
  by state, with three decisions on the exposure: *ours or benign*
  (accepted), *not a threat* (false positive), *taken down* (resolved).
- **Owner-tunable per root domain:** on/off, which kinds, how many candidates.

## 2. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Watches only for the organization's own roots: an active permanent domain scope entry (`example.com` or `*.example.com`) or a verified domain | Monitoring a third party's brand is vendor-risk work (O6 says no) and an abuse vector |
| D2 | Checks from the API: the platform DNS client (5 queries/s for this job) and crt.sh through the SSRF-guarded client | Passive public metadata; no sensor needed; same pattern as the DNS checks and the CT monitor |
| D3 | Registered candidates re-checked daily, the rest weekly, at most 100 per watch and 300 per tenant per hourly run; CT at most 10 queries per tenant per run and weekly per name | Bounded load on the resolver and on crt.sh |
| D4 | Findings are exposures, triaged with the existing exposure states | One triage model; alerts, digest and the change feed pick them up |
| D5 | A resolver failure concludes nothing (the candidate stays due) | No false "unregistered" |
| D6 | Per-organization off switch `lookalike_ct_enabled` (EASM settings, on by default, audited with the section); off, or an unreadable setting, sends no candidate name to crt.sh and the DNS checks continue | Same pattern as the CT opt-out (E8) |

Not built: WHOIS/RDAP registration dates, page similarity (would contact the
host), takedown workflows with registrars, monitoring of third-party brands,
active checks of any kind.

## 3. Design

- `easm_lookalike_watches` (tenant, domain, enabled, techniques, max
  candidates, generated_at; unique per tenant and domain; at most 20) and
  `easm_lookalike_candidates` (domain, technique, state
  unchecked/unregistered/registered, A, MX, name servers, CT count, first
  registered, last checked). Changing techniques or the cap regenerates the
  candidates and keeps what was seen for the ones kept.
- `exposure_events.chk_exposure_events_type` gains `lookalike_domain`
  (`NOT VALID` then `VALIDATE`, no long lock). Fingerprint: tenant, type and
  the candidate name, so re-sightings update one row. The exposure is linked
  to the root's domain asset when there is one (data scope applies), else to
  no asset.
- Routes (module `attack_surface`): `GET/POST /api/v1/easm/lookalikes/watches`,
  `PUT/DELETE /watches/{id}`, `GET /watches/{id}/registered` (scope
  permissions; create, change and delete audited `easm_lookalike_watch.*`).
  Triage uses `/api/v1/exposures/{id}/accept|false-positive|resolve` with
  their own permissions. Deleting a watch resolves its open exposures.
- Controller `easm-lookalikes`, hourly, skips tenants with the module off.
- Web: Attack surface › **Lookalikes** tab (watches with counts, settings
  per watch, review by state); `lookalikes` i18n namespace (en, vi).

## 4. Threat model

| Asset / actor | Abuse case | Control |
|---|---|---|
| Third parties | Probing lookalike hosts (possibly the attacker's, possibly innocent) | Never contacted: DNS through the resolver and CT only (O5); no HTTP, no port, no nuclei |
| Third parties | A tenant watches someone else's brand | Only the tenant's own roots (scope entry without expiry, or verified domain); DB test |
| Another organization | Read or change watches across tenants | Tenant from the token in every query; cross-tenant get/update/delete negatives |
| Platform resolver / crt.sh | Load or abuse | Rate limits and per-run budgets (D3); SSRF-guarded client for crt.sh; 2 MiB response cap |
| Hostile names | Markup or IDN tricks in the UI | Names are generated by us and shown as text; IDNs shown in Unicode beside their punycode identity |
| Alert noise | Many low findings | Low severity goes to the daily digest; immediate alerts only for medium on approved assets (E4) |

## 5. Rollout

Migration `easm_lookalikes` (two tables, constraint update). Nothing runs
until an organization adds a watch.

## 6. Tests

`pkg/domain/lookalike` (root validation, every technique, IDN homoglyphs,
caps, filters); `easm.TestLookalikeService` (own roots only, validation,
exposures and severity, resolver failure concludes nothing, the root is never
queried as a candidate, lapsed names resolved, delete resolves, disabled
watch not checked); `TestCrtShCounter` (decoding; the production client
refuses loopback); `postgres.TestEASMLookalikeRepository` (ownership rules
incl. one-off entries and other tenants, regeneration keeps observations,
due rules, cascade, cross-tenant negatives, the exposure type accepted);
handler test; web test (list, add, triage, permissions).
