# RFC-080: Typed attack-surface changes and the weekly digest

| | |
|---|---|
| Status | Implemented (2026-10-11) |
| Scope | api (`pkg/domain/easmchange`, `internal/app/easm/changes.go`, `postgres.EASMChangeRepository`, `GET /api/v1/easm/changes`, the EASM settings section, the weekly digest controller, one migration), web (Attack surface › Changes, the digest switch on the monitoring card) |
| Architecture | [easm.md §4i](../architecture/easm.md#4i-typed-changes-and-the-weekly-digest-built) |
| Related | RFC-036 (EASM, phase P4 continuous monitoring), RFC-069 (asset change timeline), RFC-075 (asset freshness), research/22 E4 (EASM alerts) |

## 1. Summary

The platform already records what changes on the external surface, in three
places: asset state history (`appeared`, `disappeared`, `recovered`), the
RFC-069 change timeline (IP addresses, technologies, open ports) and exposure
events (dangling DNS, certificate expiry, TLS and email posture, ...). Each
answers a different question and none says "what changed on my attack surface
this week".

This RFC gives every such change one of ten **kinds**, serves them as one
feed, and sends each organization a **weekly digest**. Nothing is stored a
second time: the feed is a read model over the three records.

| Kind | Read from |
|---|---|
| `host_added` | state history `appeared` / `recovered` of a domain, subdomain, address or other internet-facing asset |
| `host_removed` | state history `disappeared` of the same |
| `port_opened` / `port_closed` | timeline `open_ports` added / removed; state history of internet-facing `service` assets |
| `cert_changed` | state history `appeared` of a `certificate` asset (issued, rotated, newly served) |
| `cert_expiring` | exposure `certificate_expiring`, `certificate_expired` |
| `dns_changed` | timeline `ip_addresses`; exposure `dns_change` |
| `dns_dangling` | exposure `dangling_cname`, `dangling_ns`, `subdomain_takeover` |
| `tech_changed` | timeline `technologies` |
| `exposure_new` | every other new exposure (TLS issue, weak email posture, misconfiguration, leaked credential, ...) |

Exposure types that only repeat an asset change (`port_open`,
`service_detected`, `subdomain_discovered`, their removals) are left out so a
change is counted once.

## 2. Goals and non-goals

Goals: one answer to "what changed since last week", by kind, with counts;
the same answer pushed weekly to administrators and to the channels that
already receive EASM alerts; per-organization off switch and weekday.

Non-goals (deliberately not built):

- A new event table. The three records exist, have retention (timeline 400
  days, state history immutable) and tenant isolation; a copy would drift.
- Per-kind alert rules or real-time typed alerts. Immediate alerts stay as
  decided in E4 (`new_exposure` for medium+ on approved assets); the digest is
  the summary.
- New workflow trigger types. New hosts already fire `asset_discovered`
  (`assetdiscovery.Notifier` → `automation.DispatchAssetsDiscovered`) and the
  in-app/`new_asset` notice; the remaining workflow types are tracked in
  issue #1003.
- Observation hashing for "service banner changed" (RFC-036 P4
  `easm_observations`): it needs the P3 pipeline's richer facets.

## 3. Design

### 3.1 Feed

`GET /api/v1/easm/changes?from&to&kind&limit&cursor` (module
`attack_surface`, permission `assets:read`). The window defaults to the last
7 days and is at most 31 days; `kind` is a comma-separated list; keyset
pagination on `(at, id, kind)` with an opaque cursor. The response carries
`counts` for every kind in the window (ignoring the kind filter) and `total`.

One SQL `UNION ALL` over the three records, each branch tenant-scoped on its
own table and on the joined asset. Asset-sourced changes count only assets in
the inventory (not waiting for review, not rejected), not deleted, and on the
surface (a surface type or internet-facing). Exposure-sourced changes skip
rejected assets and false positives; an exposure linked to no asset is kept.

### 3.2 Weekly digest

A controller ticks hourly. For each active organization with the module on:

1. Read the EASM settings (`weekly_digest_disabled`, `digest_weekday`); an
   unreadable setting skips the organization (fail closed).
2. The slot is the latest chosen weekday at 08:00 UTC; the window is the
   seven days before it.
3. Count the changes, then **claim** the slot: `INSERT INTO
   easm_weekly_digests ... ON CONFLICT DO NOTHING`. Only the replica whose
   insert succeeded sends; a week is never sent twice.
4. A week with no change is recorded and sends nothing.
5. Otherwise one outbox event `attack_surface_digest` (title, counts by kind,
   up to 10 named changes, the riskiest kinds first, a link to the page with
   the window) and one in-app notification per active owner and administrator.
   If the outbox write fails the claim is released and the next tick retries.

`attack_surface_digest` is a new notification event type (category exposure,
module `attack_surface`, severity filter exempt: its severity is a constant).
It is default-on for new integrations, and the migration adds it to every
existing integration that receives `new_exposure`, so channels that get EASM
alerts get the digest without setup; the per-integration event list stays the
switch.

### 3.3 Settings

The EASM settings section gains `weekly_digest_disabled` (zero value = on) and
`digest_weekday` (0 = Monday, else ISO 1..7). `GET/PUT /api/v1/easm/settings`
expose `weekly_digest_enabled`, `digest_weekday`, `digest_hour_utc` and
`last_digest_at`; omitted fields keep their value. Changes are audited with
the rest of the section (`easm_settings.updated`).

### 3.4 UI

Attack surface gets a third tab, **Changes** (`/attack-surface/changes`):
toggle chips per kind with their counts, a 7/14/30-day window, or the
digest's own window from its link. The monitoring card gets a **Weekly
digest** switch, the weekday and when the last one went out. All text is in
the `attackSurface` i18n namespace (en, vi). Channel and in-app digest text is
rendered by the server and is English.

## 4. Threat model

| Asset / actor | Abuse case | Control |
|---|---|---|
| Another organization's surface | Read changes across tenants | Every branch filters `tenant_id` on its table and on the joined asset; the tenant comes from the token. DB test with two tenants |
| Member with a narrow data scope | See asset names outside their scope in the feed | The feed goes through the data-scope enforcer (`user_accessible_assets`, hidden program assets); a restricted member sees no asset-less exposure. DB test |
| Member with a narrow data scope | See names in the digest | In-app digests go only to owners and administrators; channels are configured by administrators. The digest counts the whole organization by design |
| Discovered names (attacker-influenced, e.g. CT entries) | Inject markup into channels or the page | Names are data: React escapes them; channel clients format messages as text as for the existing EASM alerts |
| Replicas | Double send | Primary-key claim per tenant and slot |
| Outbox or DB failure | Silent loss | Claim released on enqueue failure and retried; failures logged per tenant |
| Notification volume | Spam | One message per organization per week, none for a quiet week, off switch |

No new outbound request, no new permission, no new data collected.

## 5. Rollout

Migration `easm_weekly_digests` (new table; additive update of integration
event lists, reversible). On by default: the first digest goes out at the next
slot after deploy, only for organizations with changes.

## 6. Tests

- `pkg/domain/easmchange`: slot computation, weekday mapping, query limits.
- `postgres.TestEASMChanges` (real schema): classification of every source,
  exclusions (review queue, rejected, internal host, skipped exposure types,
  false positives), kind filter, keyset pages, bad cursor, cross-tenant and
  data-scope negatives, the once-per-slot claim and release.
- `easm.TestDigestJob`: once per slot, off, quiet week, outbox failure
  releases, unreadable settings fail closed, weekday.
- Handler tests: query parsing and 400s, settings defaults, omitted fields
  kept, weekday range.
- Web: the page (counts, kind filter reaching the API, digest window, no
  fetch without `assets:read`) and the monitoring card switch.
