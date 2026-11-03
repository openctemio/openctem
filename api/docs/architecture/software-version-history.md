# Software version history

How the platform decides which version of a product an asset runs at a
place, so that later scans do not close findings by mistake (wrong closes,
flapping, "fixed" claims from one weak sighting). Code:
`pkg/domain/software/history.go` (the state machine, pure),
`internal/infra/postgres/software_repository.go` (`UpsertLinks`),
`internal/app/vulnmatch/service.go` (closing and proposals). Design and edge
cases: RFC-066 §5.2 and §8, this page.

## Model

A history is one (tenant, asset, product, location): the location is
`tcp/443` for a service, `''` for host level. Every version a source reports
there keeps its own `asset_software` row:

| Column | Meaning |
|---|---|
| `first_seen_at`, `last_seen_at` | first and last **observation** time (the report's time, clamped to the dispatch window and to now), never the ingest time |
| `sightings` | distinct observation times |
| `evidence_class` | the strongest way a source knew this version (below) |
| `confidence` | the highest identity confidence seen |
| `version_state` | `established` (findings are built on it) or `candidate` (seen, not yet trusted) |
| `streak`, `streak_since` | consecutive scans this version was the trusted reading of |
| `superseded_at` | when another version became established here (the confirming reading's time) |

Packages (`source = 'package'`) are authoritative inventory, written by the
package writer as complete sets; they never go through this history.

### Evidence classes

From strongest: `inventory` (authenticated package or host inventory),
`sbom`, `probe` (an active fingerprint: a service probe that named the
product, a CPE from the tool), `banner` (banner, Server header, page meta or
generator, technology detection), `heuristic` (OS guess, partial version,
no version). A partial version (fewer than three segments) is at best
heuristic.

## Rules

1. **The reading of a scan** is the set of decisive versions at the
   strongest class the scan holds. Weaker sightings of the same scan only add
   history. Versions one scan reports together are present together (two
   copies of a library on a page, a partly rolled-out deployment).
2. **Neutral sightings** never displace anything: no version or an
   unparseable one, a coarser compatible version ("7.1" against 7.1.3), the
   same upstream version with another distribution build (a back-port is not
   a version change).
3. **First sighting:** the reading is established.
4. **A new version is a candidate.** It joins or replaces the established
   set only when
   - it is **strong**: class `sbom` or `inventory`, or a `probe` at
     confidence 80 or more, and its class is at least the established
     version's class; or
   - it was the reading of **3 consecutive scans spanning at least 12
     hours** (`PromoteSightings`, `PromoteMinSpan`).
   A reading that leaves a version out resets that version's streak, so
   alternating readings (load balancer, stale cache, blue/green) never
   promote.
5. **On promotion** every row not in the confirming reading is superseded at
   that reading's time.
6. **Out-of-order reports** (an older scan ingested after a newer one) add
   history and can break a streak they fall inside, but never promote.
7. **Rollback:** a superseded version seen again after it was superseded is a
   candidate again and needs the same evidence.
8. **Re-import** of the same report (same observation time) is idempotent.
9. **Not seen is not gone.** Nothing is superseded because a scan did not
   report it; a history with nothing established and recent for 30 days makes
   its findings stale, never fixed.

## What the matcher does with it

- Findings are built from established, recent rows only (candidates never
  create findings).
- A finding is closed as `version_changed` only when another version is
  **established** at its place and its own version is superseded. Its own
  version still seen as a candidate counts as current.
- That close follows the organization's closing mode. In review mode the
  Ready to close proposal stores the evidence: `product`, `from_version`,
  `to_version`, `to_source`, `to_evidence_class`, `to_confidence`,
  `to_sightings`, `to_first_seen`, `observed_at`; `evidence_at` is the new
  version's latest reading. No banner text or URL is copied.
- When a finding's identity matches again (its version is established again,
  or the change was never confirmed), its pending version-change proposal is
  canceled (`seen_again`).
- An advisory change stays a separate close (`advisory_updated`,
  false positive, never counted as fixed).

## Security

- Every read and write is scoped to the tenant (`tenant_id` in every
  statement; the per-history advisory lock includes it). A link to another
  tenant's asset fails the `(tenant_id, asset_id)` foreign key.
- A source can at most make its own version a candidate; displacing an
  established version takes strong evidence or repeated readings, and a
  weaker class never overrides a stronger established one on its own. A
  compromised sensor that reports fake versions therefore cannot close
  findings with one report, and its probe-class readings cannot override
  inventory.
- Proposal evidence holds catalog facts only (no secrets, no source text).
