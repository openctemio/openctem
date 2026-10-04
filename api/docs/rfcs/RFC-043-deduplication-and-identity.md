# RFC-043 — Deduplication and identity

> Status: **Accepted — decisions D1–D15 approved** (owner, 2026-10-03; #892).
> Progress: P0 merged; P1 item 10 implemented, item 11 implemented: v2 recipes at ingest and the re-fingerprint job with dry run (see §12).
> Scope: api (ingest, finding and asset repositories, merge, tickets,
> notifications, migrations) + sensor/sdk-go (fingerprint hints only) + web
> (duplicate link, correlation group view). No change to the CTIS wire format is
> required for P0.
> Current state, entity table and edge-case checklist:
> [architecture/deduplication.md](../architecture/deduplication.md).
> Builds on [ADR-004](../architecture/decisions/004-finding-provenance.md)
> (provenance belongs to the sighting), [RFC-028](RFC-028-asset-identity-model.md)
> (asset identifiers), [RFC-039](RFC-039-continuous-retest.md) (regression
> reopen), [RFC-040](https://github.com/openctemio/openctem/pull/870) (mutual
> distrust: a sensor's claim is a hint) and
> [RFC-042](https://github.com/openctemio/openctem/pull/878) (Asset Inventory v2:
> source records → links → canonical asset). **Asset identity design is RFC-042's;**
> this RFC only lists the normalizer bugs that must be fixed before it lands and
> the finding-side consequences of an asset merge or split.

## 1. Answer in short

Dedup in OpenCTEM is one unique index (`findings(tenant_id, fingerprint)`) fed
by five fingerprint producers that disagree, an ingest path that checks before
it writes, and an asset merge that resolves collisions by deleting rows. The
audit reproduced **20 failures** on a migrated database through the real ingest
service. The ones that lose data:

1. **An asset merge deletes the triaged copy of a finding** (risk acceptance,
   Jira link, comments, audit activities, validation evidence all cascade away).
2. **A concurrent ingest race** reports a finding as created twice, fires the
   created hooks with an id that does not exist, and the loser's
   `ON CONFLICT DO UPDATE` **wipes the ticket link and metadata** of the winner.
3. **Line-keyed identity** for SAST (semgrep OSS, SARIF without `fingerprints`)
   and secrets: inserting three lines above a false positive re-opens it as a new
   finding; the FP is auto-resolved and forgotten.
4. **Version-keyed SCA identity**: a still-vulnerable version bump is a new
   finding; the in-progress one, with its ticket, is auto-resolved.
5. **Cross-tool lifecycle**: a finding seen by two tools is closed by whichever
   tool misses it, and reopened by the other — flapping.
6. **Asset normalization**: `http_service` URLs are stored under garbled names
   (3 assets for one URL), two EC2 instances collapse into one asset, a host is
   absorbed into a domain of the same name.

The design in one paragraph: every deduplicated entity gets a **canonical
identity tuple** computed **only on the server**, hashed with a **versioned**
recipe whose fields are unit-separated; findings are written with **one atomic
upsert** that returns whether the row was inserted; a finding can be found by
**any of its fingerprints** (an alias table) so an algorithm change re-keys
without losing state; every observation becomes a **sighting** (ADR-004) and
lifecycle is decided per sighting; same-vulnerability-same-asset across
techniques is a **correlation group**, not a forced merge; and any merge —
finding or asset — **moves state to a survivor and tombstones the loser**
(`status = duplicate`, `duplicate_of`), never deletes it.

## 2. Problem statement

Proven failures, ordered by data-integrity risk. Probe ids refer to
[architecture/deduplication.md §5](../architecture/deduplication.md#5-how-the-evidence-was-produced).

| Id | Failure | Probe | Risk |
|---|---|---|---|
| B1 | Asset merge: post-commit fingerprint recompute **deletes** the merged asset's finding on collision; its status (`accepted_risk`), tickets, comments, activities, approvals, evidence, retests cascade away | P9 | Critical — silent loss of risk decisions and audit trail |
| B2 | Ingest check-then-write race: loser counts "created", fires hooks with a phantom id; `ON CONFLICT` overwrites `work_item_uris` and `metadata` | P1, P1b | High — lost ticket links, double notifications, orphan side rows |
| B3 | SAST identity includes line numbers (semgrep fallback, SARIF without `fingerprints`, F1 `sast`) | P4 | High — triage (FP, accepted) lost on every refactor |
| B4 | Secret identity includes the line; masks collide | P12 | High — secret triage lost on edits; distinct secrets merged |
| B5 | SCA identity includes the installed version | P5 | High — ticket/assignee/SLA history split on every bump |
| B6 | Cross-tool merged findings auto-resolved by `tool_name` (first writer) | P11 | High — flapping status, false "fixed" metrics |
| B7 | `http_service`/`discovered_url` stored names (`https:::host`) differ from lookup keys | P17 | High — asset sprawl, findings split across 3 assets |
| B8 | Cloud compute/serverless ARNs truncated at `/` | P17 | High — **wrong merge** of distinct machines |
| B9 | Asset key ignores type; a host is absorbed into a domain row | P17 | Medium — wrong type, wrong scans |
| B10 | `occurrence_count` never increments on the main path | P8 | Medium — "seen N times" is false |
| B11 | DAST without a sensor fingerprint keys on rule + title | P6 | Medium — distinct URLs merged |
| B12 | Network VA keys on the lowest CVE of a multi-CVE plugin; port vs host-level split | P2 | Medium — duplicates across Nessus/Qualys/Tenable |
| B13 | Same CVE via package (trivy) and host (Tenable) — no correlation | P2 | Medium — double counting in risk and SLA |
| B14 | Pentest identity = campaign + title (no asset) | code | Medium — cannot file the same issue on two assets |
| B15 | Manual fingerprint has no field separators | P13 | Low — collision by construction |
| B16 | `findings.cve_id` not case-normalized; GHSA/OSV aliases unused | P14 | Low/Medium — CVE filters, KEV joins miss rows |
| B17 | Asset normalizer gaps: IDN, IPv4 leading zeros, `.git/`, container `docker.io/library/`, S3 URL forms, cert fingerprint forms, URL with/without scheme | P3, P17 | Medium — asset sprawl |
| B18 | Batch upserts without in-batch dedup: one duplicate fails the **whole** exposure batch (0 rows) and drops **all** branch occurrences of a report; same shape in certmonitor (overlapping roots) and EPSS sync | P18 | High — silent loss of a whole batch |
| B19 | Network VA without a CVE keys on rule + title: one plugin on ports 443 and 8443 → one finding | P18 | Medium — **wrong merge** |
| B20 | Exposure fingerprints embed `asset_id` and are not recomputed on asset merge (and CT's `nearestAsset` changes) → duplicate exposures, the moved one never auto-resolves | code | Medium |
| B21 | Tickets: read → create → write array, no uniqueness; concurrent `create_ticket` → two issues; GitHub repo match case-sensitive → a new issue every run | code | Medium — duplicate tickets, orphan issues |
| B22 | Tenant-wide threat model: `UNIQUE` with a NULL column → two models | P18 | Low |
| B23 | Converter fingerprints discarded (Nessus `nessus:…`, DefectDojo `defectdojo:…` not hex); `/ingest/scanner` SARIF adapter picks a **random** `fingerprints` entry; in-tree adapters and sensor parsers fingerprint the same tool differently | code | Medium — duplicates on re-import |
| B24 | No dedup key on notifications, commands, threat actors; IOC values not canonicalized; PURLs verbatim; asset-components index collides across ecosystems and the error is swallowed | code | Medium |

Not data loss, but blocking any fix: no fingerprint records its algorithm or
version (P15), so today **no recipe can be changed without re-keying every
finding** (mass "new" + mass auto-resolve).

## 3. Goals and non-goals

Goals

- One canonical identity per entity, defined in one place, versioned, and
  testable as a pure function.
- No dedup step ever deletes a row that carries human state.
- Ingest is safe under concurrency and re-delivery: rows, counters and hooks.
- Changing a fingerprint recipe is a migration that preserves triage state.
- The same vulnerability on the same asset seen by several tools is presented
  and counted once, and closed only when every source agrees.

Non-goals

- The asset identity model (canonical/link/source layers) — RFC-042.
- Fuzzy / ML dedup of findings. Correlation stays deterministic; similarity
  suggestions may come later as review items, never automatic merges.
- Cross-tenant dedup. Identity is always tenant-scoped (catalog rows such as
  `vulnerabilities` stay global).

## 4. Canonical identity per entity

### 4.1 Principles

1. **Layered, server-decided** (R1). Per tool, the server's parser declares
   an explicit identity recipe: a **tool-native stable id** where the tool has
   one that is known to be stable (SARIF `partialFingerprints`, Semgrep
   `match_based_id`, gitleaks' fingerprint), else a
   hash over an explicit, per-parser field list (DefectDojo's
   `unique_id_from_tool` / `hash_code` model). The recipe — not the sensor —
   decides which tool fields count. The opaque `Finding.Fingerprint` a sensor
   sends is stored on the sighting (`external_fingerprint`) and never becomes the
   identity by itself (RFC-040: a sensor's claim is a hint). Today any 16-hex
   string from any sensor becomes the identity verbatim, and every non-hex
   tool id (Nessus, DefectDojo, gitleaks) is discarded. No field is
   "always included" across tools: DefectDojo's always-on `service` field is the
   documented way such a field silently breaks cross-scanner dedup (R1).
2. **Explicit scope** (R2). The unique key is `(tenant_id, scope_key,
   fingerprint)`; `scope_key` defaults to the canonical asset id and a wider
   pool (a business service, a repository family) is opt-in per tenant. Today
   the asset id is hashed into the fingerprint, which is what makes a merge
   re-key everything.
3. **Tuple first, hash second.** Store the canonical tuple
   (`identity_key JSONB`) next to the hash so a recipe change can be recomputed
   from the row, without the original report. This replaces the
   `partial_fingerprints["composite/base"]` workaround of #263.
4. **Versioned and separated** (R6).
   `fingerprint = sha256("v" || version || 0x1f || kind || 0x1f || field1 || 0x1f || …)`.
   The unit separator closes B15 and the `:`-joined ambiguity in
   `ctis/fingerprint`.
5. **No secrets, no volatile fields** (R3, R4). Never a raw or masked secret (use the
   per-tenant HMAC of #849), never a line number when a stable anchor exists,
   never a message or title, never a scanner-local id (plugin id, QID) when a
   canonical vulnerability id exists.
6. **Asset-scoped through the canonical asset id** (RFC-042), so an asset merge
   re-keys findings by recomputing from `identity_key`, not by guessing.

### 4.2 Finding identity recipes (version 2)

| Kind | Identity tuple | Notes |
|---|---|---|
| SAST | tool, rule family¹, repo-relative POSIX path², then the tool's partial fingerprint (SARIF `primaryLocationLineHash` incl. its `:N` occurrence suffix, Semgrep `match_based_id`), else `hash(normalized snippet)` + logical location + occurrence index in the file | Never absolute lines or byte offsets (SARIF 2.1.0 App. B, R3). When a SARIF file has no fingerprints, compute the fallback server-side (GitHub only does this in `upload-sarif`, so API uploads duplicate, R3). Known limits (R4): a file rename or rule-id change re-keys (handled by the rename map / rule alias table below and a rule+snippet fallback match that copies triage); an identical block inserted earlier shifts the `:N` suffix and can swap twins |
| SCA | asset, canonical PURL type/namespace/name (**without** version; qualifiers only from an allowlist, e.g. `distro` for OS packages)³, canonical vuln class⁴ | Version moves to the sighting (`installed_version`, `fixed_version`); manifest path moves to a location list. Decision D2 on manifest-level splitting |
| Container | asset (image repository, RFC-042), package (PURL w/o version), canonical vuln id | Digest and tag on the sighting |
| Secret | asset, `secret_fingerprint` (HMAC of the normalized **raw** secret under a server-held per-tenant key — not #849's key, which is a public constant + tenant id, and not over the masked string), repo-relative path | No line. Same secret in two files → two findings, one correlation group |
| DAST | asset, canonical rule⁵, method, normalized URL template⁶, sorted parameter names | Query **values** dropped, names kept |
| Network VA | asset, canonical vuln id, `port/proto` (or `host` for host-level) | Multi-CVE plugin → one finding per CVE (decision D3), not "lowest id" |
| Misconfig / IaC | asset, policy id (canonical), resource id (type + name or address), repo-relative path | No message |
| Cloud (CSPM) | asset (provider resource id), policy id | Account-level controls key on the account asset |
| Pentest | asset, campaign, author-chosen `finding_key` (default: slug of the first title, frozen at creation) | Title edits do not re-key; same title on two assets is allowed |
| Manual | asset, user-supplied rule or CVE, path, line — v2 recipe with separators | Optional "link to existing finding" instead of a new row |
| Validation evidence, retest | not deduplicated as findings; bound to `finding_id`, idempotent on `(finding_id, attempt_id)` | §8 |

¹ rule family: the tool's rule id with known renames mapped (a small, versioned
alias table per tool, e.g. semgrep `python.lang.security.x` → `…v2`).
² repo-relative POSIX path: strip the scan root, `\` → `/`, collapse `./`, keep
case (paths are case-sensitive on most VCS).
³ PURL (ECMA-427, R9): parse and re-serialize; per-type rules (pypi lower-case
and `_`→`-`, maven case-sensitive, …); version in its own field; qualifiers
dropped except an explicit allowlist. PURL keeps ecosystems apart on purpose:
deb, rpm and pypi copies of one library are different components, linked only
through advisory/CPE mapping, never by PURL string.
⁴ canonical vuln class: union-find over OSV **`aliases` only** (symmetric and
transitive, R7) into an equivalence class; the class id prefers CVE > GHSA >
OSV/vendor, upper-cased. **Never** union across `upstream` (a distro advisory vs
the upstream CVE) or `related` (different vulnerabilities). Every alias merge
is logged and can be split by hand; each finding keeps its source ids. An
over-broad GHSA listing several CVEs would fuse them — the split tool and the
log exist for that case.
⁵ canonical rule: nuclei template id; for CVE templates the CVE id.
⁶ URL template: scheme + lower-case host (IDNA) + default-port strip + path
with numeric/uuid segments replaced by `{id}` (decision D4).

### 4.3 Other entities (summary; details in the architecture doc)

| Entity | Canonical identity | Enforced by |
|---|---|---|
| Asset | RFC-042 deterministic keys | RFC-042 |
| Vulnerability | canonical id after alias resolution | `UNIQUE(cve_id)` + `vulnerability_aliases(alias UNIQUE)` |
| Component | normalized PURL without qualifiers | `UNIQUE(purl)` on the normalized form |
| Ticket | (finding or correlation group, provider, project) | new `UNIQUE` (§7) |
| Notification | (tenant, rule, event type, entity, window) dedup key | outbox `UNIQUE(dedup_key)` (§7) |
| Ingest report | (tenant, sensor, report_id) | existing v2 key; v1 gets one (§8) |
| Command / scan run | client idempotency key | `UNIQUE(tenant_id, idempotency_key)` (§8) |

## 5. Write path: one atomic upsert

Replace check-then-write with:

```sql
INSERT INTO findings (…) VALUES …
ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
    -- observation columns only
    last_seen_at = EXCLUDED.last_seen_at,
    scan_id = EXCLUDED.scan_id,
    occurrence_count = findings.occurrence_count + 1,
    severity = …, cvss_* = …, epss_* = …,   -- per the enrichment rules
    snippet = COALESCE(EXCLUDED.snippet, findings.snippet), …
RETURNING id, (xmax = 0) AS inserted, status;
```

- The conflict set lists **observation columns only**. `work_item_uris`,
  `metadata` user keys, `assigned_to`, `sla_deadline`, `priority_class_override*`,
  `status`, `resolution*` are never in it (today `work_item_uris` and `metadata`
  are, `finding_repository.go:543,564`).
- Duplicates inside one batch are merged in memory before the statement
  (Postgres refuses to update one row twice).
- `RETURNING` drives everything after: ids are remapped from the database, and
  hooks (created callback, assignment, remediation key, exposure bridge,
  notifications) run **only for `inserted = true`**.
- Reopen becomes part of the same statement's follow-up on `inserted = false`
  rows whose returned status is closed-as-fixed, so the regression decision sees
  the committed row, not a pre-read.
- Enrichment of existing rows stops being read-modify-write: per-column SQL
  expressions (`GREATEST`, array union, `jsonb ||` on scanner-owned keys only).

## 6. Fingerprint versioning and re-fingerprint migration

Schema:

```sql
ALTER TABLE findings ADD COLUMN fingerprint_version SMALLINT NOT NULL DEFAULT 1,
                     ADD COLUMN identity_key JSONB;
CREATE TABLE finding_fingerprints (
    tenant_id   UUID NOT NULL,
    fingerprint TEXT NOT NULL,
    finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version     SMALLINT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, fingerprint)
);
```

Ingest computes the current-version fingerprint, looks it up in
`finding_fingerprints` (any version) and upserts on the alias. Migration to a new
version, per tenant, in batches, resumable:

1. Compute `v_new` from `identity_key` (or, for v1 rows without one, from the
   row's columns where that is lossless — SAST rows with a snippet, SCA rows with
   a PURL; rows that cannot be recomputed keep v1 and are re-keyed on their next
   sighting by matching the v1 alias).
2. Insert the alias `(v_new → finding_id)`. On conflict two v1 findings map to
   one v2 identity: run the **finding merge** of §9 (survivor + tombstone), never
   a delete.
3. Flip `fingerprint_version`; keep the v1 alias for N days so late reports in
   the old scheme still land on the right row; then drop it.
4. Auto-resolve is **suspended** for a tenant while its migration runs (an
   unmatched old key must not close findings).

Dry-run mode reports, per tenant: rows re-keyed, merges it would make, rows it
cannot recompute.

## 7. Cross-tool correlation, tickets and notifications

### 7.1 Correlation group

Same canonical vulnerability on the same canonical asset reported through
different techniques (package scan vs network scan vs DAST CVE template) stays
**separate findings** — they have different fixes and different evidence — but
share a `correlation_id = sha256(v ‖ asset ‖ canonical_vuln_class ‖ component
identity incl. PURL type/distro)` (the column exists and is unused). The
component part is required (R8): Red Hat backported the CVE-2023-32681 fix to
`requests 2.20.0-3` (RHSA-2023:4520) while upstream fixes it only in 2.31.0, so
an upstream-range scanner and a vendor-advisory scanner legitimately disagree
on the same CVE and host. Each source's verdict is kept on its sighting; the
last writer never wins. Effects:

- risk, SLA and dashboard counts count the group once (worst member);
- the UI shows the group with its members;
- triage of one member can be offered to the others (decision D5: offer, not
  automatic);
- one ticket per group by default (§7.2).

### 7.2 Tickets

- `UNIQUE (tenant_id, provider, project, subject_type, subject_id)` on the
  ticket link table, `subject` = finding or correlation group. Creation is
  insert-first (`ON CONFLICT DO NOTHING RETURNING`), and only the inserter calls
  the provider. A re-detection comments on the existing ticket instead of
  opening a new one; a regression reopens it.
- On a finding merge the survivor takes the union of links; the loser's ticket
  gets a "duplicate of" comment.

### 7.3 Notifications

- Dedup key `(tenant, rule, event_type, entity_id, window_start)` on the outbox,
  `ON CONFLICT DO NOTHING`.
- Storm control: above N events per rule per window, collapse into one digest
  (count + top items).
- Only `inserted = true` rows emit "new finding"; a reopen emits "regression"
  once per `(finding, reopen)`.

## 8. Lifecycle per sighting (auto-resolve interplay)

Adopt ADR-004's sighting model now (`finding_sightings`: finding, tool, channel,
sensor, scan/report, external fingerprint, first/last seen, installed version,
location). Then:

- **Default-branch and coverage auto-resolve close a sighting**, keyed on the
  sighting's tool — not on `findings.tool_name`.
- A finding is closed-as-fixed only when **no sighting is open**. A tool that
  stops reporting closes its own sighting only. B6 disappears.
- Coverage-scoped auto-resolve (`coverage_autoresolve.go`) already checks that the
  last sighting belongs to a run of the same profile; with sightings that check
  becomes exact per tool.
- Reopen (scan, retest, IOC, exception expiry) reopens the sighting and the
  finding; RFC-039's fresh SLA on regression applies once per reopen.
- Asset merge moves sightings with their findings; coverage state already moves
  (`scan_coverage_state` in `asset_merge_plan.go`).
- Ingest reports: v1 gets the v2 rule — `(tenant, sensor, report_id)` unique, a
  re-sent report is a no-op on sightings (today it re-runs enrichment).
- Validation evidence and retests: idempotent on `(finding_id, attempt_id)`.

## 9. Merge and split semantics

One procedure, used by asset merge, fingerprint migration and a new manual
"mark duplicate of":

1. Choose the survivor: the **earliest-created** finding (R2); the kept asset's
   finding only breaks a tie.
2. **State inheritance** (in the merge transaction):

| Field | Rule |
|---|---|
| status / resolution | the more deliberate wins: `false_positive`, `accepted` (risk) > `in_progress`/`fix_applied` > `confirmed` > `new`; a closed-as-fixed loser never closes an open survivor. Conflicting deliberate decisions (FP vs accepted) → keep survivor's, raise a review item |
| assignee, groups | survivor's; else loser's; group assignments unioned |
| SLA | earliest `first_detected_at` → earliest deadline; breach history kept |
| tickets (`work_item_uris`, ticket links) | union; loser's ticket commented "duplicate of" |
| comments, activities, approvals, evidence, retests, verification checklists, AI triage, compliance mappings, compensating controls | **re-parented** to the survivor (UPDATE `finding_id`), with an activity "merged from <id>" |
| suppressions / exceptions | union; the stricter expiry wins |
| sightings, branch occurrences, data flows, remediation keys | moved, deduplicated on their own keys |
| loser row | `status = duplicate`, `duplicate_of = survivor`, kept (tombstone) so URLs, tickets and audit references resolve |

3. Runs **inside** the asset-merge transaction (today the recompute runs after
   commit, best-effort, `admin_dedup_handler.go:83`).
4. **Split** (RFC-042 un-merge): findings follow their sightings' source
   records; a finding whose sightings now point to two assets is cloned per
   asset, state copied, both linked in an activity. Never automatic: split is an
   admin action with a preview.

## 10. Asset normalization fixes that cannot wait for RFC-042

RFC-042 owns the model; these are bugs in today's normalizer, each with a probe:

- `NewAsset` must normalize with the sub-type it is given (B7: pass sub-type into
  the constructor; `processor_assets.go:1664`, `asset/service.go:328`, `import.go:88`).
- Cloud resource ids must not go through the DNS normalizer (B8): ARNs are
  identifiers; case rules per provider.
- The asset unique key includes the type family, or a cross-type collision raises
  a review instead of absorbing (B9; decision D6).
- IDNA (UTS-46) to A-labels for DNS names, hosts and URL hosts; strict IPv4
  (reject leading zeros or canonicalize as decimal, decision D7); `.git` and
  trailing slash strip in a fixed order; `ssh://` repo URLs; container image
  references via the distribution reference grammar (`docker.io/library/`
  default, digest identity); S3 URL forms; certificate identity = SHA-256 of the
  DER (not CN).
- One wildcard rule for CT and ingest (decision D8).

## 11. Test strategy

1. **Property tests** (`pgregory.net/rapid` or `testing/quick`) for every
   normalizer and recipe: idempotence `N(N(x)) = N(x)`; invariance under case,
   surrounding whitespace, trailing dot, default port, path separator; recipes
   are injective over field boundaries (fuzz `a‖b` splits); the type never
   changes the result of the asset normalizer for equal sub-types between
   constructor and lookup.
2. **Golden corpus** `testdata/dedup/`: real tool outputs (semgrep, CodeQL SARIF,
   trivy fs/image/config, betterleaks, nuclei, Nessus, Qualys, Tenable) in pairs
   `{before, after, expect: same|different}` — line shift, version bump,
   re-tag, secret move, multi-CVE plugin, URL query churn, rule rename. A recipe
   change must state which golden pairs change outcome.
3. **Concurrency tests** on a migrated database: N goroutines ingest one report;
   assert one row, one "created", hooks once, counters exact; run with `-race`.
4. **Merge tests**: every table that references `findings(id)` is either
   re-parented or listed as deliberately dropped — the same shape as
   `TestAssetMergeCoversEveryAssetReference`, for findings.
5. **Migration tests**: v1 → v2 re-key on a fixture with triaged findings; no
   status, ticket, comment or activity lost; dry-run equals real run.
6. **Schema gate**: every table with an identity column has a `UNIQUE` (or a
   documented exemption) and no nullable column in a unique key without
   `NULLS NOT DISTINCT`.

## 12. Phase plan

**P0 — stop losing data (proven bugs, highest integrity risk)**

1. Asset merge: replace the collision `DELETE` with the §9 merge (survivor +
   tombstone + re-parent) and run it inside the merge transaction (B1).
2. Finding upsert: drop `work_item_uris` and `metadata` from the conflict set;
   add `RETURNING id, (xmax = 0)`; hooks and counters only for inserted rows;
   dedupe the batch in memory (B2, P7).
3. `occurrence_count` increments atomically on every sighting (B10).
4. Asset normalizer: sub-type in the constructor (B7); ARNs out of the DNS path
   (B8). Both with a migration that finds already-garbled names and queues
   dedup reviews (not automatic merges).
5. Stop auto-resolving rows whose `tool_name` differs from the last sighting's
   tool until sightings land (interim guard for B6).
6. In-batch dedup before every multi-row upsert: exposure `BulkUpsert`,
   branch occurrences, certmonitor, EPSS (B18). One helper, one test each.
7. Network VA without a CVE: port/proto in the key (B19 wrong merge).
8. Asset merge also recomputes exposure-event fingerprints, with the same
   survivor/tombstone rule (B20).
9. `threat_models`: `UNIQUE NULLS NOT DISTINCT` (PG 15+) after collapsing
   existing duplicates (B22).

**P1 — versioned identity**

10. `fingerprint_version`, `identity_key`, `finding_fingerprints` alias table;
   ingest looks up by alias.
   **Done** (migrations 000370–000371): alias table with a tenant-bound foreign
   key, maintained by triggers on `findings`; merges keep and re-point aliases;
   ingest and the sensor fingerprint check resolve former keys.
11. v2 recipes for SAST (snippet/logical location; SARIF partialFingerprints in
   sdk-go `FromSARIF`), secrets (HMAC from #849, no line), SCA (no version),
   DAST, network VA (one finding per CVE). Re-fingerprint migration with dry run.
   **v2 recipes done** (`pkg/domain/vulnerability/identity*.go`,
   `internal/app/ingest/identity_v2*.go`): computed at ingest for SAST, SCA,
   secret, DAST, network VA (one finding per CVE) and misconfig; a version-1
   finding is re-keyed in place on its next sighting, keeping its old key as an
   alias; asset merge rewrites the tuple's asset. Golden corpus in
   `tests/integration/testdata/dedup/`. sdk-go keeps SARIF
   `partialFingerprints` in `FromSARIF` (sdk-go#142).
   **Re-fingerprint job done** (`cmd/refingerprint`, `internal/app/refingerprint`,
   migration 000462 `finding_rekey_runs`): per tenant, batched, resumable,
   idempotent. The default is a dry run on a read-only connection that reports
   re-keys, would-merge pairs and the rows it cannot recompute; `-apply` merges
   through the finding merge (earliest wins, tombstone), never across assets,
   and pauses scan auto-resolve for the tenant while its run is open (D11,
   bounded to 2 hours without progress).
12. Pentest `finding_key`; manual recipe with separators; "mark duplicate of"
   (writes `duplicate_of`). Converter fingerprints (Nessus, DefectDojo) kept as
   sighting keys; SARIF adapter picks `fingerprints` deterministically; one
   parser per tool (retire the in-tree adapters or make them call the sensor
   parsers) (B23).
   **"Mark duplicate of" done:** `POST /api/v1/findings/{id}/duplicates`
   (`findings:triage`; `findings:approve` as well when either finding is a
   false positive or risk acceptance) folds the body's finding into `{id}`
   through the finding merge (tombstone, references and keys move). Both must
   be in the caller's tenant and data scope and on the same asset; pentest
   findings are excluded; audited as `finding.duplicate_marked`. Web: "Mark as
   duplicate" in the finding page menu.

**P2 — sightings and correlation**

13. `finding_sightings`; lifecycle per sighting (B6 for good); v1 report
   idempotency.
14. `vulnerability_aliases` and canonical vuln id; `cve_id` upper-case backfill
    (B16).
15. `correlation_id` groups; group-aware counts, SLA and UI (B13).

**P3 — tickets, notifications, assets**

16. Ticket link table with uniqueness and insert-first creation; case-insensitive provider matching; group tickets (B21).
17. Notification dedup key and storm digest; command idempotency keys; threat-actor and IOC canonical keys; PURL normalization (B24).
18. Remaining normalizer fixes (B9, B17) — coordinated with RFC-042.

**P4 — hardening**

19. Golden corpus in CI, property tests, schema gate, finding-merge coverage
    test; sensor fingerprints demoted to sighting attributes everywhere.

## 13. Owner decisions (approved as recommended, 2026-10-03)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Is the sensor's opaque fingerprint ever the identity? | No — a hint stored on the sighting (RFC-040). Tool-native ids are used only where the server's per-tool recipe names them (R1) |
| D2 | SCA: one finding per (package, vuln) per asset, or per manifest? | Per asset; manifests as locations |
| D3 | Multi-CVE network plugin: one finding per CVE, or one per plugin with CVE list? | One per CVE (cross-scanner dedup needs it) |
| D4 | DAST URL template: replace numeric/uuid path segments? | Yes, with a per-tenant opt-out |
| D5 | Correlation group: propagate triage automatically? | Offer, do not auto-apply |
| D6 | Same name, different asset type: separate assets or review? | Separate rows keyed by type family; review on conflict |
| D7 | IPv4 with leading zeros: reject or canonicalize? | Reject (ambiguous octal) and log |
| D8 | Wildcard `*.example.com`: own asset or the parent? | Own asset, linked to the parent (it is a certificate/DNS fact, not a host) |
| D9 | Severity on re-ingest: MAX (today, `EnrichFrom`) or last-writer? | Per sighting; finding = max over open sightings, so a vendor downgrade can lower it |
| D10 | Tombstone retention for merged findings | Keep forever (cheap, keeps links valid) |
| D11 | Migration window: auto-resolve paused per tenant while re-keying | Yes |
| D12 | File rename / move: how does a SAST or secret finding keep its triage? | git rename detection on the scan's commit range where available, else a rule + snippet-hash fallback match that copies triage to the new finding and links the old one as duplicate; manual re-link in the UI |
| D13 | PURL qualifiers that count toward identity, per type | `distro` (deb/rpm/apk) only at first; `arch`, `epoch`, `repository_url` excluded; revisit with Syft/Trivy samples in the golden corpus |
| D14 | An upstream feed corrects a bad alias (over-broad GHSA) | Rebuild the class, split the affected correlation groups, keep findings and their triage, record an activity on each; never auto-merge findings on alias change alone |
| D15 | Dedup scope wider than one asset (pools) | Not in P0–P2; opt-in later per tenant |

## 14. Duplicates as linked records, earliest wins

Following DefectDojo (R2), a merged-away finding is never deleted: it stays as
an inactive record linked to its original (`status = duplicate`,
`duplicate_of`). The canonical original is the **earliest-created** record,
regardless of which ingest arrived first, so an old, triaged finding is never
demoted to a duplicate of a newer one. §9's survivor rule is amended
accordingly: kept-asset first only breaks ties between records created at the
same time; otherwise earliest wins. Triage state is keyed on
`(scope, fingerprint)` so it carries to re-detections, other branches and
re-imports (R5; Semgrep shows a fingerprint triaged on every branch it appears
on). DefectDojo's optional "delete oldest duplicates beyond N" is **not**
adopted.

## 15. Alternatives considered

- **Keep sensor fingerprints as identity** and fix each sensor: rejected — five
  producers already disagree, and a sensor is not trusted to define identity
  (RFC-040).
- **Fuzzy matching (similarity of message/location)**: rejected for automatic
  merges; acceptable later as review suggestions.
- **Delete-on-collision with "copy status first"**: rejected — 15 tables cascade;
  a copy list would rot exactly like the merge plan did before
  `TestAssetMergeCoversEveryAssetReference`.

## 16. Research

Folded in from the adversarially verified report
`research/10-dedup-best-practices.md` (2026-10-03). Findings cited above as R1–R9:

| R | Verified finding | Source | Where used |
|---|---|---|---|
| R1 | Layered identity: tool unique id, else per-tool hash fields (DefectDojo `hash_code` / `unique_id_from_tool` / OR); an always-included field breaks cross-scanner dedup | DefectDojo docs | §4.1.1 |
| R2 | Explicit scope (per asset by default, wider pools opt-in); duplicates kept as linked inactive records; earliest-created is canonical | DefectDojo docs | §4.1.2, §14 |
| R3 | SARIF 2.1.0 Appendix B: tool + rule + path + partialFingerprints, no absolute lines/offsets; GitHub matches on `primaryLocationLineHash`; API uploads without fingerprints duplicate | OASIS SARIF 2.1.0, GitHub docs | §4.2 SAST |
| R4 | Content hashes survive moves, break on renames; repeated snippets get an occurrence index (`hash:N`, Semgrep per-file index) | codeql-action `fingerprints.ts`, Semgrep docs | §4.2 SAST |
| R5 | Triage follows the fingerprint across branches | Semgrep docs (single source, medium) | §14 |
| R6 | Versioned fingerprint keys (`x/v2`), compare on the newest version both results share | SARIF 2.1.0 | §6 |
| R7 | Vuln ids: OSV `aliases` only, symmetric + transitive; never `upstream` or `related` | OSV schema | §4.2 note 4 |
| R8 | Cross-scanner CVE correlation must include ecosystem/distro (Trivy, RHSA-2023:4520) | Trivy docs | §7.1 |
| R9 | PURL (ECMA-427) only after parse + canonical re-serialization; qualifier allowlist; "ecosystem-independent key" claim refuted 0-3 | ECMA-427, purl-spec | §4.2 note 3 |

Matching the alias design in §6 to R6: `finding_fingerprints` holds one row per
`(finding, version)`; a lookup tries the newest version the incoming result
carries, then older ones, which is SARIF's "newest shared version" rule.

**Not covered by verified research — our own engineering reasoning:** asset
identity normalization (§10; RFC-042 owns the model), certificate identity,
secret fingerprints (keyed HMAC), the concurrency/upsert design (§5), lifecycle
per sighting (§8), merge state-inheritance rules (§9), ticket and notification
dedup (§7.2–7.3) and the test strategy (§11). These rest on the probes in the
architecture document, not on external sources.

Open questions the research leaves (added to the decisions): file-rename
identity (D12), the PURL qualifier allowlist per type and epoch/version
normalization across Syft/Trivy (D13), and rebuilding an alias class when a feed
corrects a bad alias without corrupting attached triage (D14).
