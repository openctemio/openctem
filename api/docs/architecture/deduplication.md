# Deduplication and identity — current state

> Audit of 2026-10-03 against `develop` at `8422b7b8` (api), sdk-go `main`,
> sensor `main` and ctis `22afe545d848` (the commit the API pins).
> Design and phase plan (with the verified research folded in): [RFC-043](../rfcs/RFC-043-deduplication-and-identity.md).
> Asset identity *design* belongs to [RFC-042](../rfcs/RFC-042-asset-inventory-v2.md)
> (PR #878); this page audits the asset dedup that runs **today**.
> Finding provenance: [ADR-004](decisions/004-finding-provenance.md).

Every claim marked **proven** was reproduced on a scratch PostgreSQL 17 database
migrated to `000272`, through the real ingest service
(`ingest.NewService` + the postgres repositories), not a mock. The probes are
listed in [§5](#5-how-the-evidence-was-produced). Claims marked **code** are
read from the cited lines and not reproduced.

## 1. How a finding gets its identity today

There are **five** producers of a finding fingerprint, and they do not agree
with each other:

| # | Producer | Where | Shape | Inputs |
|---|---|---|---|---|
| F1 | Scanner ingest (CTIS, v1 and v2) | `internal/app/ingest/processor_findings.go:689-758` | 64 hex, `sha256(asset_id ":" base)` (`pkg/domain/vulnerability/fingerprint_composite.go:20`) | `base` = (a) the sensor's `Finding.Fingerprint` when it is ≥16 hex chars (`:693`, `isValidFingerprint` `:1916`), else (b) `netva:<port>:<lowest CVE>` for a CVE with no package and no file (`:697-705`), else (c) `ctis/fingerprint.GenerateAuto` (`:706-752`) |
| F2 | Manual finding create | `internal/app/finding/vulnerability_service.go:693` → `Finding.GenerateFingerprint` (`pkg/domain/vulnerability/finding.go:1803`) | 32 hex | `asset_id ‖ rule_id ‖ file_path ‖ start_line ‖ message`, **no separators** |
| F3 | Pentest finding | `internal/app/compliance/pentest.go:1297`, `:1669` | 64 hex | `pentest:<campaign_id>:<lower(trim(title))>` — **no asset** |
| F4 | Sensor-side (becomes `base` of F1) | sensor `internal/scanners/{trivy,semgrep,nuclei}/parser.go` | various | trivy: `sha256(vulnID:pkg:installedVersion:target)[:16]`; semgrep: semgrep's own fingerprint, else `GenerateSAST(path, rule, startLine)`; nuclei: `sha256(template|host|matched-at|matcher)`; betterleaks/gitleaks: not hex → ignored, F1(c) recomputes |
| F5 | Type strategies | `pkg/domain/vulnerability/fingerprint_strategy.go` (`sast/v1`, `sca/v1`, `secret/v1`, …) | 32 hex | **dead code**: `GenerateFingerprintWithStrategy` has no caller |

The only database guard is `UNIQUE (tenant_id, fingerprint)`
(`migrations/000012_findings.up.sql:324`). Nothing records which algorithm or
version produced a fingerprint: `partial_fingerprints` holds only
`{"composite/base": …}` (**proven**, probe P15).

**Since RFC-043 item 10 (migrations 000370–000371):** `findings.fingerprint`
stays the current key, and `finding_fingerprints (tenant_id, fingerprint) →
finding_id` holds every key a finding has had. Triggers on `findings` add the
current key on insert and on every re-key, and keep the previous one; a finding
merge (`asset_merge_findings.go`) records the loser's key and moves all its
aliases to the survivor (`finding_fingerprints` is in `findingMergeRefs`).
Ingest resolves incoming keys through `FindingRepository.ResolveFingerprintAliases`
before the existence check, so a former key lands on the finding that carries it
now; the sensor fingerprint check reports a former key as known. The alias
references `findings (id, tenant_id)`, so it cannot name another tenant's
finding, and every lookup is tenant-scoped. `findings.fingerprint_version` and
`findings.identity_key` exist.

**Since RFC-043 item 11 (identity version 2):** scanner ingest keys a finding
with a server-computed identity tuple (`pkg/domain/vulnerability/identity.go`,
recipes in `identity_recipes.go`, CTIS mapping in
`internal/app/ingest/identity_v2.go`). The tuple is stored in
`findings.identity_key`, `fingerprint_version = 2`, and the fingerprint is
`sha256("v2" 0x1f kind 0x1f (name 0x1e len 0x1e value 0x1f)*)`, so no field
boundary can be moved to forge a collision. Recipes:

| Kind | Tuple | Not in it |
|---|---|---|
| SAST | asset, tool, rule, repo-relative path, then one anchor: SARIF `primaryLocationLineHash` (with its `:N`), Semgrep `matchBasedId/v1`, else `hash(normalized snippet)` + logical location + occurrence index of that snippet in the file | line numbers, message |
| SCA | asset, canonical PURL without version (`distro` qualifier only for deb/rpm/apk, D13), canonical vuln id | installed version, manifest path |
| Secret | asset, per-tenant keyed HMAC of the reported (masked) value, repo-relative path | line, the value or its mask |
| DAST | asset, rule (the CVE for a CVE template), method, URL template (lower-case IDNA host, default port dropped, numeric/UUID segments `{id}`, D4), sorted parameter names | query values |
| Network VA | asset, canonical CVE (one finding per CVE, D3; else `rule:<id>`), `port/proto` or `host` | plugin title |
| Misconfig | asset, policy id, resource type/name, path | message |

A result no recipe covers (compliance, web3, a SAST result with only a line,
a secret without a configured server key) keeps its version-1 key. The
sensor's own fingerprint is kept as the sighting key
`partial_fingerprints["sensor/fingerprint"]` and is never the identity (D1).

Migration without losing triage: when a scan reports a result whose version-1
key still names a stored finding and no finding holds the version-2 key yet,
that finding is re-keyed in place on that sighting
(`FindingRepository.AdoptFingerprint`); its version-1 key stays an alias. An
asset merge re-keys a version-2 finding by rewriting the `asset` field of its
stored tuple, only when the stored tuple still reproduces the stored key.

Known limits: the SAST occurrence index is counted within one report, so twin
snippets split across report chunks can swap; the secret HMAC is over the
masked value the sensor sends (CTIS carries no raw value), so two secrets that
mask alike in one file are one finding.

CTIS producer fields and identity (coordinated with the CTIS review,
`research/16-ctis-review-2026-10-04.md` G5, Q1, Q2, Q8, P4, P5):

- **Producer fingerprints (Q8, D1):** a finding with a version-2 recipe never
  takes its identity from `Finding.Fingerprint`; the value is kept as the
  sighting key `partial_fingerprints["sensor/fingerprint"]`. Only kinds
  without a recipe (compliance, web3, a generic finding without a location)
  still use the version-1 key, which can include it.
- **Network transport:** the version-2 network recipe keys on `port/proto`
  (`tcp` when absent) for CVE and non-CVE findings alike, so the version-1
  split between `netva:` (no transport) and `netport:` (transport) is gone.
- **SARIF paths (Q2):** `NormalizeRepoPath` drops any `file:` scheme form and
  percent-decoding (once, only when no `%` is left, so it stays idempotent).
  `uriBaseId` is not resolved: an absolute runner path stays absolute.
- **SARIF secrets (Q1):** while `ctis.FromSARIF` leaves `secret.masked_value`
  empty, such a secret has no keyed HMAC and keeps its version-1 key; once
  CTIS sets it, the next sighting re-keys the finding to its version-2 key in
  place (`AdoptFingerprint`), with its triage. No separate migration.
- **Ready for CTIS 1.4 (P4, P5):** a producer `fingerprint_recipe` and
  `fingerprint_aliases[]` would be sighting keys and alias candidates, never
  the identity; a producer `secret.hash` would replace the masked value as
  the input of the server-keyed HMAC (`identity_v2_apply.go`, where the
  secret input is chosen), so the server key stays the only key.

What `ctis/fingerprint.GenerateAuto` keys on, per detected type
(`ctis/fingerprint/fingerprint.go:112-213`, `DetectType` `:435-472`), given the
fields the API fills in (`processor_findings.go:706-748`):

| Detected type | Key | Consequence |
|---|---|---|
| `sca` (package + CVE) | package, **installed version**, vuln id | A still-vulnerable version bump is a new finding |
| `secret` (masked value) | path, rule, **start line**, `sha256(masked)[:16]` | Moving the line is a new finding; two secrets that mask alike on one line merge |
| `misconfig` | resource type, resource name, rule, path | — |
| `sast` (path + rule + line) | path (lower-cased), rule, **start line, end line** | Any code inserted above is a new finding |
| `generic` (everything else, incl. DAST without a sensor fingerprint) | rule, path, lines, **message** | Same rule on two URLs with the same title merges; a reworded message splits |

The API never sets `Snippet`, `LogicalLocation`, `TargetHost`, `TargetPath`,
`Parameter` or `ImageTarget`, so the line-independent `sast-content` recipe and
the `dast` / `container` recipes are unreachable from ingest.

### 1.1 The write path

`FindingProcessor.processBatch` (`processor_findings.go:213-640`) is
**check-then-write**:

1. `CheckFingerprintsExist` (`:323`, a plain `SELECT … IN (…)`,
   `finding_repository.go:1489`).
2. Existing → `AutoReopenByFingerprintsBatch` (`:373`) then
   `EnrichBatchByFingerprints` (`:545`), which **loads the rows, merges in Go
   (`Finding.EnrichFrom`, `finding.go:2857`) and writes every column back**
   (`finding_repository.go:3776-3866`) — a read-modify-write with no lock and no
   version check.
3. New → `CreateBatchWithResult` (`:412`), a multi-row
   `INSERT … ON CONFLICT (tenant_id, fingerprint) DO UPDATE` (`finding_repository.go:518-610`)
   that has **no `RETURNING`** and counts every row as created (`:376`, `:387`).
4. Post-insert hooks run on the in-memory `newFindings` (created callback `:495`,
   assignment, remediation keys, exposure bridge, suppression audit).

## 2. Entity table

Status: **OK** works as intended · **PARTIAL** works for the common case with a
known hole · **BROKEN** produces wrong data today · **MISSING** no dedup at all.

### 2.1 Findings

| Entity | Current identity | Status | Evidence | Proven failure |
|---|---|---|---|---|
| Findings, all kinds — concurrent ingest | F1 + `UNIQUE(tenant_id, fingerprint)`; check-then-write | **BROKEN** | `processor_findings.go:323,412`; `finding_repository.go:376,387,518` | **P1:** 12 concurrent ingests of one new finding → 1 row but `FindingsCreated` = 2, so the created callback (notifications, workflows, assignment, exposure bridge) fires for a finding ID **that does not exist** (`returned_id_exists=false`, P1b) |
| Findings — ON CONFLICT update set | `findingUpsertConflictSQL` | **BROKEN** | `finding_repository.go:543` `metadata = EXCLUDED.metadata`, `:564` `work_item_uris = EXCLUDED.work_item_uris` | **P1b:** a collision wipes the ticket link (`work_item_uris` `{X-1}` → `{}`) and the metadata (`{"user_note":…}` → `{}`); status survives |
| Findings — re-sighting counter | `occurrence_count` | **BROKEN** | enrich path writes the loaded value back (`finding_repository.go:3908`); only the upsert path increments (`:558`) | **P8:** the same finding sent twice → `occurrence_count = 1`; **P1:** 12 sightings → 2 |
| Findings — duplicate inside one report | in-memory batch | **PARTIAL** | `insertChunk` fails on a double row, falls back per row (`finding_repository.go:403-405`) | **P7:** two identical findings in one report → 1 row, `FindingsCreated = 2` |
| SAST (semgrep OSS, CodeQL without `fingerprints`, any SARIF) | F4 semgrep fallback `GenerateSAST(path, rule, line)` or F1(c) `sast` | **BROKEN** | sensor `semgrep/parser.go:132-136` (semgrep OSS returns `"requires login"`); `fingerprint.go:116-124` | **P4:** a finding marked false positive at line 42 reappears as a **new** finding at line 45 when 3 lines are inserted above; the FP row is auto-resolved |
| SCA (trivy via sensor) | F4 trivy: vuln, pkg, **installed version**, target | **PARTIAL** | sensor `trivy/parser.go:165,475-479` | version in key: see next row (same shape) |
| SCA (no sensor fingerprint) | F1(c) `sca`: pkg, **version**, vuln | **BROKEN** | `fingerprint.go:138-145` | **P5:** bumping lodash 4.17.15 → 4.17.20 (still vulnerable) creates a new finding; the in-progress row with its Jira link is auto-resolved. Two manifests (`web/`, `api/package-lock.json`) collapse into one finding with one path |
| Container image vulns | trivy F4 (`target` = image ref incl. tag) | **PARTIAL** | `trivy/parser.go:165`; `container` recipe unreachable (§1) | a re-tag (`app:1.2` → `app:1.3`) of the same digest is a new set of findings (**code**) |
| Secrets (betterleaks/gitleaks) | F1(c) `secret`: path, rule, **line**, `sha256(masked)` | **BROKEN** | betterleaks fingerprint is not hex (`sensor/.../betterleaks/parser.go:129-133`) → ignored; mask is first3 + `****` + last3 (`sdk-go/pkg/core/utils.go:137-142`) | **P12:** moving the secret 6 lines down is a new finding (old auto-resolved); two different secrets that mask alike on one line are one finding. #849 adds an HMAC `secret_fingerprint` but does not change the key (§3) |
| Secrets (trivy) | F4 trivy: rule, target, **line**, `Match` | **PARTIAL** | `trivy/parser.go:359` | line in key (**code**) |
| DAST / nuclei via sensor | F4 nuclei: template, host, **matched-at (full URL incl. query)**, matcher | **PARTIAL** | `nuclei/parser.go:330-341` | `?id=1` vs `?id=2` are two findings; host not normalized (**code**) |
| DAST without sensor fingerprint (imports, other tools) | F1(c) `generic`: rule + title | **BROKEN** | `TargetHost/Path` never set (§1) | **P6:** the same template on `/a/.git/config` and `/b/.git/config` → **1** finding |
| Network VA (Nessus/Tenable/Qualys) | F1(b) `netva:<port>:<lowest CVE>` | **PARTIAL** | `processor_findings.go:697-705,770-800` | **P15:** same CVE + same port from Nessus and Qualys → 1 (OK). **P2:** a plugin that lists two CVEs keys on the lexically lowest one (`CVE-2023-39325`), the single-CVE scanner on `CVE-2023-44487` → 2 findings; port 443 vs host-level → 2 |
| Same CVE, same asset, different technique (trivy package vs Tenable host) | none | **MISSING** | different recipes by design | **P2:** 4 findings for one CVE on one host (nessus:443, qualys host-level, qualys multi-CVE, trivy package). No correlation key links them |
| Cross-tool merged row lifecycle | `AutoResolveStale*` keyed on `tool_name` (first writer) + `scan_id` (last writer) | **BROKEN** | `finding_repository.go:3217-3300`, `service.go:417`; ADR-004 §"Related" | **P11:** trivy creates, grype re-sees, trivy's next full scan misses it → **resolved** although grype still reports it (it reopens on grype's next scan: flapping) |
| Misconfig / IaC (trivy config, checkov via SARIF) | F4 trivy `ID:Target:Type:Message`; SARIF → F1(c) | **PARTIAL** | `trivy/parser.go:270`; message in key | reworded message → new finding (**code**). trivy emits an empty `ctis.Finding{}` for PASS results (`trivy/parser.go:266-268`, appended at `:93-96`) |
| Cloud (CSPM) | F1(c) `misconfig` / `generic` | **PARTIAL** | ARN-named assets collapse (asset table, P17) | findings of two EC2 instances land on one asset (**proven** at the asset layer) |
| Pentest manual findings | F3 `campaign + title` | **BROKEN** | `pentest.go:1297,1669`; `Create` maps the unique violation to `FindingAlreadyExists` (`finding_repository.go:127-129`) | two "Reflected XSS" findings on two assets in one campaign cannot both be filed; editing a title does not change the fingerprint (**code**) |
| Manual findings | F2 | **PARTIAL** | `finding.go:1803-1813` | **P13:** `(rule=a, file=b1, line=2)` and `(rule=a, file=b, line=12)` hash identically. F2 and F1 never match, so a manual finding never dedups against a scanner finding |
| SARIF ingest | sdk-go `FromSARIF` uses `result.fingerprints` (lowest key) | **PARTIAL** | `sdk-go/pkg/ctis/sarif.go:321,335-352`; `partialFingerprints` not parsed (`:86-100`) | CodeQL emits `partialFingerprints` (`primaryLocationLineHash`), so its line-stable hash is thrown away and F1(c) `sast` keys on lines (**code**) |
| CTIS with a sensor fingerprint | used verbatim as `base` | **PARTIAL** | `processor_findings.go:693` | identity is whatever the sensor says: no version, no normalization, a buggy or hostile sensor controls merging inside its tenant (RFC-040) |
| Validation evidence | append-only `validation_evidence` | **PARTIAL** | `migrations/000178:8-30` (no unique key) | a re-POST of the same evidence is a second row (**code**). Cascades away with the finding (§2.4) |
| Retest results | `pentest_retests`; RFC-039 (#867/#881, open) | see §3 | — | — |
| Manual "duplicate" link | `findings.duplicate_of` | **MISSING** | column exists (`000012:96`), `MarkAsDuplicate` (`finding.go:1757`) has **no caller**, `Update` does not write the column | a user can set status `duplicate` but never say of what |

### 2.2 Vulnerabilities, components, catalog

| Entity | Current identity | Status | Evidence | Proven failure |
|---|---|---|---|---|
| Vulnerability catalog | `vulnerabilities.cve_id UNIQUE` (`000011:9`) | **PARTIAL** | concurrent first sighting from 8 reports → 1 row (**P16**, OK) | GHSA-only ids never reach the catalog; `aliases TEXT[]` exists and nothing reads it for identity |
| `findings.cve_id` | copied from the report | **BROKEN** | no case normalization on the finding column | **P14:** `cve-2099-0001` is stored lower-case on the finding while the catalog row is `CVE-2099-0001` |
| Components, asset components | see §2.5 | | | |

### 2.3 Assets

The only unique key on `assets` is `(tenant_id, name)`
(`migrations/000008_assets.up.sql:136`) — **`asset_type` is not part of it**.
Names are normalized by `pkg/domain/asset/normalize.go` at construction
(`entity.go:117`). Ingest upserts with
`INSERT … ON CONFLICT (tenant_id, name) DO UPDATE … RETURNING` (`asset_repository.go:1439-1482`),
so concurrent ingests of one normalized name are safe (**P1:** 12 concurrent
ingests → 1 asset). Strong identifiers (RFC-028) live in `asset_identifiers`
with `UNIQUE (tenant_id, kind, value) WHERE strong` (`000243:30-31`).

| Asset type | Normalization | Status | Proven failure (P3 / P17) |
|---|---|---|---|
| domain / subdomain | lower-case, trailing/leading dot, scheme/port/path strip (`normalize.go:110-123`) | **PARTIAL** | `Example.COM.` = `example.com` (OK). `bücher.example` ≠ `xn--bcher-kva.example` (no IDNA). `*.wild.example` is its own asset; CT strips `*.` (`certmonitor/service.go:740-749`) but `NormalizeName` keeps it — two rules for one name |
| ip_address | `net.ParseIP`, IPv4-mapped → v4, RFC 5952 (`normalize.go:151-183`) | **PARTIAL** | IPv6 and `::ffff:` forms OK. `010.000.000.001` is stored raw (ParseIP rejects it) next to `10.0.0.1` → 2 assets; DNS-derived IPs are looked up raw (`processor_assets.go:1062-1097`) |
| host | `normalizeHostName` (`normalize.go:129-146`) | **PARTIAL** | case + trailing dot OK. `[2001:db8::1]` keeps its brackets |
| any type — cross-type | key has no type | **BROKEN** | host `collide.example.com` ingested after domain `collide.example.com` → **absorbed into the domain row** (1 row, type domain). A website without a scheme lands on the domain too |
| http_service / discovered_url | constructor normalizes with `subType=""` (`processor_assets.go:1664` → `entity.go:117`), lookup with the real sub-type (`:389`) | **BROKEN** | `https://api.example.com`, `…:443`, `HTTPS://API.example.com/` → **3 assets** named `https:::api.example.com`, `https:::api.example.com:443`, `https:::api.example.com:` |
| website / application / api | `normalizeURL` (`normalize.go:260-291`) | **PARTIAL** | `https://Shop.Example.com:443/` = `https://shop.example.com` (OK). `example.com` ≠ `https://example.com`; trailing dot in the host not stripped |
| repository | `normalizeRepoName` (`normalize.go:302-335`) | **PARTIAL** | ssh vs https, `.git`, case → OK. `…/tool.git/` → `github.com/acme/tool.git` ≠ `github.com/acme/tool` (strip order). SCM import names repos `org/repo` without host (`integration/repo_import.go:176-200`) → never matches CI ingest's `github.com/org/repo` (**code**) |
| container image | `ToLower` only (`normalize.go:54-55`) | **BROKEN** | `nginx:1.25` ≠ `docker.io/library/nginx:1.25`; no digest identity |
| cloud compute / serverless | routed to the **DNS** normalizer (`value_objects.go:98-99`), which cuts at the first `/` | **BROKEN** | `arn:aws:ec2:…:instance/i-0aaa` and `…/i-0bbb` → **one** asset `arn:aws:ec2:us-east-1:123456789012:instance` (a wrong merge: two machines' findings mix) |
| s3 bucket | ingest does not know `s3_bucket` → `unclassified`, raw name | **BROKEN** | `s3://my-bucket` ≠ `my-bucket.s3.amazonaws.com` → 2 assets |
| certificate | CN or fingerprint (`normalize.go:340-368`) | **PARTIAL** | `SHA256:AB:…` vs `AB:…` → 2 assets; different certs with one CN collapse; correlator matches the raw fingerprint property (`correlator.go:340-349`) (**code**) |
| service (host:port) | `normalizePortIdentifier` (`normalize.go:203-255`) | **PARTIAL** | port not parsed: `:0443` ≠ `:443`; unbracketed IPv6 falls to lower-case only (**code**). `asset_services` has `UNIQUE (asset_id, port, protocol)` but only a manual writer (plain INSERT) |
| network / CIDR | `ParseCIDR` → canonical (`normalize.go:400-408`) | **OK** | — |
| Asset merge (dedup review approve) | `ApproveAndMerge` + `mergeAssetReferences` (`asset_merge_plan.go:120`) + post-commit `RecomputeFingerprintsForAsset` (`admin_dedup_handler.go:83`) | **BROKEN** | **P9:** two assets with the same finding; the merged asset's copy is `accepted` / `accepted_risk` with a Jira link. After merge the recompute **deletes** that row and keeps the kept asset's `new` row: risk acceptance and ticket link gone. The delete cascades comments, activities (audit trail), approvals, validation evidence, pentest retests, suppressions, group assignments (§2.4) |
| Dedup review queue | `uq_asset_dedup_review_pending (tenant_id, keep_asset_id) WHERE pending` (`000170:6`) | **PARTIAL** | identifier reviews are select-then-insert (`asset_dedup_repository.go:140-232`); no detector exists for normalization-variant or cross-type duplicates |

### 2.4 What a finding delete takes with it

`RecomputeFingerprintsForAsset` resolves a post-merge collision with
`DELETE FROM findings` (`finding_repository.go:2696-2701`). Foreign keys to
`findings(id)` on the migrated schema:

`ON DELETE CASCADE`: `finding_activities`, `finding_comments`,
`finding_status_approvals`, `validation_evidence`, `pentest_retests`,
`finding_suppressions`, `finding_group_assignments`, `finding_remediation_keys`,
`finding_branch_occurrences`, `finding_data_flows`, `finding_data_sources`,
`finding_verification_checklists`, `compliance_finding_mappings`,
`compensating_control_findings`, `ai_triage_results`.
`ON DELETE SET NULL`: `findings.duplicate_of`, `ioc_matches.finding_id`,
`iocs.source_finding_id`.

A dedup step must therefore never delete a finding that carries state; it must
merge into the survivor and tombstone the loser (RFC-043 §5).

### 2.5 Other entities

| Entity | Current identity | Status | Evidence | Proven failure |
|---|---|---|---|---|
| Vulnerability aliases (GHSA/OSV) | none — `vulnerabilities.aliases` exists (`000011:10`), never filled (`processor_cves.go:164-202`); CTIS has no alias field | **MISSING** | `cve_id` regex is upper-case only (`pkg/domain/vulnerability/entity.go:11`); ingest reads only `CVEID`, never `CVEIDs` (`processor_cves.go:54-56`) | the same lodash vuln as `CVE-2021-23337` from one tool and `GHSA-35jh-r3h4-6jhm` from another → 2 findings (**code**); a lower-case CVE is never catalogued and misses the case-sensitive KEV join (`kev_escalation.go:54`) (P14 shows the lower-case finding) |
| Components | `components.purl` verbatim, `UNIQUE (purl)` (`000044:45`); `ON CONFLICT DO NOTHING` (`component_repository.go:59-80`) | **PARTIAL** | no PURL normalization: case, qualifiers, type `golang` vs `go` (`processor_components.go:449-458`, `value_objects.go:272-289`) | `pkg:pypi/Django@4.2` vs `pkg:pypi/django@4.2` → 2 components; remediation groups (keyed by component id) split the same way (**code**) |
| Asset components | `(asset_id, component_id, path)` (`000044:25`) and `(tenant_id, asset_id, name, version, branch)` (`000060:148-152`, no ecosystem) | **BROKEN** | the second index collides across ecosystems; ingest swallows "duplicate" errors (`processor_components.go:530-541`) | npm `debug@1.0.0` and pypi `debug@1.0.0` on one asset → the second link is silently dropped (**code**). A manual add drops the namespace: `@angular/core` → `pkg:npm/core` (`internal/app/asset/component.go:86-104`) |
| Exposure events | sha256 over {tenant, type, title, source, asset_id, whitelisted details} (`pkg/domain/exposure/entity.go:136-165`); `UNIQUE (tenant_id, fingerprint)` (`000028:47`); `ON CONFLICT` keeps state (`exposure_repository.go:321-334,432-445`) | **BROKEN** | `BulkUpsert` does not dedupe its batch (`exposure_repository.go:369`); asset id in the key but a merge repoints `asset_id` without recomputing (`asset_merge_plan.go:53`) | **P18:** a batch of 4 with one duplicate → `ON CONFLICT DO UPDATE command cannot affect row a second time`, **0 rows** written. After an asset merge the next check creates a second exposure and the moved one never auto-resolves (**code**, also #852) |
| `exposures` table | no key, no writer (`000013:7`) | n/a | — | dead table |
| Exposure bridge (secret finding → `credential_leaked`) | tenant, type, finding title, `secret_scan`, asset, `service`, `path` (`exposurebridge/bridge.go:163-213`); read-then-create, race handled (`apply.go:28-46`) | **PARTIAL** | no line, no secret identity | two different AWS keys flagged by one rule in one file → 1 exposure; a title or asset change → new exposure, old stays open (**code**) |
| Leaked credentials (import) | `CalculateFingerprint`: lower(identifier), type, source + breach/code/paste fields, no secret (`pkg/domain/credential/import.go:157-213`); read-then-create with re-read (`credential_import.go:156-177`) | **PARTIAL** | different recipe than the bridge | one key found by the secret scan and imported as a code-source credential → 2 `credential_leaked` exposures (**code**) |
| CT names (certmonitor) | exposure events titled `Subdomain seen in Certificate Transparency: <host>`, asset = `nearestAsset` (`certmonitor/service.go:467-554`) | **BROKEN** | asset id in the fingerprint changes when a closer asset appears; overlapping roots (`selection.go:91-93`) emit the same fingerprint twice in one batch | run 1 → exposure on the root asset; once `dev.example.com` exists, run 2 → a second exposure, first stays active. Overlapping verified/unverified roots make every sweep fail on the in-batch duplicate (same failure as P18) (**code**) |
| IOCs | trim + lower (`pkg/domain/ioc/indicator.go:215-223`); `UNIQUE (tenant_id, ioc_type, value_normalized)` (`000156:60`); `ON CONFLICT DO UPDATE` | **PARTIAL** | no IP/URL/domain canonical form | `evil.com.` vs `evil.com`, `2001:db8::1` vs `2001:0db8:0:0::1` → 2 IOCs (**code**). `ioc_matches` unique only `WHERE telemetry_event_id IS NOT NULL` (`000156:100`) |
| Threat actors | none (`000121:4-41`); plain INSERT | **MISSING** | — | "APT29" twice → 2 rows (**code**) |
| KEV / EPSS | `cve_id` PK; KEV batch dedupes, EPSS does not (`threatintel_repository.go:244-252,510-561`) | **PARTIAL** | — | a feed with a repeated CVE fails the whole EPSS sync (**code**) |
| Tickets (Jira / GitHub) | `findings.work_item_uris TEXT[]`, no constraint; read → create issue → write array (`jira/sync_service.go:472-532`, `ticketing/github_ticket.go:142-180`) | **BROKEN** | idempotent only sequentially (`jira/sync_dedup_test.go:92-118`, `ticketing/github_ticket_test.go:161`) | two `create_ticket` workflow actions on one finding both see an empty array → 2 issues, one link lost (**code**). GitHub match is case-sensitive: `openctem/api` vs `OpenCTEM/API` → a new issue on every run (**code**). And P1b shows the ingest race erasing the array, after which the next sync opens a second ticket |
| Campaign epics | `UNIQUE (tenant_id, campaign_id, provider)` (`000177:15`); read → create epic → INSERT | **PARTIAL** | no insert-first | two concurrent calls → 2 Jira epics, one orphaned (**code**, acknowledged in a comment) |
| Notifications | `notification_outbox` has no dedup key or throttle (`000020:22-47`, `outbox/service.go:78-131`); delivery idempotency only (`Idempotency-Key: outbox-<id>`) | **MISSING** | SLA breach is de-duplicated by state transition only (`sla_escalation.go:90-99`) | every duplicate "created" from P1/P7 becomes a notification; no storm collapse |
| Commands | no idempotency key, plain INSERT from 8 call sites (`command_repository.go:46`); no `Idempotency-Key` handling in HTTP | **MISSING** | — | a client retry creates a second command (**code**) |
| Scan schedule | CAS on `next_run_at` (`scan_repository.go:636-648`) | **OK** | — | — |
| Manual scan trigger | `FOR UPDATE` on the scan, up to 3 concurrent runs (`pipeline_run_repository.go:380-395`) | **PARTIAL** | — | a double click → 2 runs (**code**) |
| Ingest reports v1 sync | none (`ingest_handler.go:608-668`) | **PARTIAL** | findings dedupe by fingerprint | **P8:** rows idempotent; side effects and enrichment re-run |
| Ingest reports v1 async | `UNIQUE (tenant_id, report_id, payload_sha)` (`000175:29`) | **PARTIAL** | raw-byte SHA, not sensor-scoped, `report_id` may be `''` | the same report re-serialized is a new job (**code**) |
| Ingest reports v2 | `(tenant, sensor, report_id)` (`000237:63`), segment keys, `Content-Digest` replay check (`v2_receiver.go:326-329`) | **OK** | — | a re-compressed replay gets 409 instead of a no-op (**code**); v1 + v2 of one report are both processed |
| Branch occurrences | `UNIQUE (finding_id, branch_id)` (`000173:37`), `ON CONFLICT DO UPDATE` | **BROKEN** | the caller does not dedupe fingerprints in a batch (`processor_findings.go:607-634`) | **P18:** a report with one duplicated finding → **0** occurrences recorded for the whole report (only a warning) |
| Network VA without a CVE | F1(c) `generic`: rule + title — **port not in the key** | **BROKEN** | `ctis/fingerprint.go:201-209` | **P18:** Nessus plugin 51192 on ports 443 and 8443 → **1** finding |
| Nessus / DefectDojo converter fingerprints | `nessus:host:plugin:port/proto`, `defectdojo:<hash>` (`nessus/converter.go:242`, `defectdojo/converter.go:130`) | **BROKEN** | not hex → discarded by `isValidFingerprint` | DefectDojo's "stable across re-imports" key is never used; two jars with one CVE on a product merge via `netva::<cve>` (**code**) |
| SARIF via `/ingest/scanner?scanner_type=sarif` | `matchBasedId/v1`, else the **first map entry** (`internal/infra/adapters/sarif/adapter.go:171-195`) | **BROKEN** | Go map iteration order is random | a result with two `fingerprints` entries gets a different identity on each ingest → duplicates; disagrees with `/ingest/sarif` (lowest key) (**code**) |
| In-tree adapters (`internal/infra/adapters/*`) vs sensor parsers | two implementations of trivy/semgrep/nuclei/betterleaks parsing with different fingerprints | **PARTIAL** | API nuclei adapter: `GenerateSAST(host, template, 0)` (`nuclei/adapter.go:164`); sensor: `template|host|matched-at|matcher` | the same nuclei result uploaded through `/ingest/scanner` and through the sensor → 2 findings (**code**) |
| Threat models | `UNIQUE (tenant_id, scope_type, scope_ref_id)` with `scope_ref_id` NULL for tenant-wide (`000189:33`); unlocked select-then-insert (`threat_model_repository.go:125-170`) | **BROKEN** | NULLS DISTINCT | **P18:** two tenant-wide models inserted for one tenant |
| Attack paths | `attack_paths` tables have no key and no writer; paths computed on read | n/a | — | — |
| Remediation groups | `finding_remediation_keys` PK `finding_id`, `ON CONFLICT DO UPDATE` | **PARTIAL** | key `sca:<component_id>` inherits the PURL split; stale key never deleted (`key_applier.go:32-34`) | (**code**) |
| Suppression rules | no uniqueness on criteria; `finding_suppressions UNIQUE (finding_id, rule)` | **OK** (rules are user data) | rules match on tool/rule/asset/path, not fingerprint (`suppression/entity.go:320-350`), so they survive re-keying | — |
| Asset dedup review pairs | partial unique on `keep_asset_id` | **BROKEN** | keep = most findings (`correlator.go:186-193`); reversed pending pairs not checked (`asset_dedup_repository.go:241-243`) | scan 1 proposes keep A/merge B, scan 2 keep B/merge A → two contradictory pending reviews (**code**) |
| Comments / activities | append-only, cascade with the finding | **OK** | — | lost on a finding delete (§2.4) |

## 3. Open pull requests that change identity

Read from the PR diffs on 2026-10-03; line numbers are the PRs' new-file lines.

| PR | What it does to identity | Gap |
|---|---|---|
| #849 type_details / `secret_fingerprint` | HMAC-SHA256 (128 bits) of `TrimSpace(MaskedValue as reported)`, key `"openctem/secret-fingerprint/v1/" + tenant_id` (`secret_preview.go:78-90`); stored in `type_details` JSONB, **no index, not part of the finding fingerprint** (develop still feeds the raw `MaskedValue` to `GenerateAuto`, `processor_findings.go:735-752`); no backfill | The input is whatever the scanner calls the masked value, so two secrets masked alike share it and one secret reported raw vs masked gets two values. The key is derived from a public constant + tenant id, so for a scanner that reports the raw secret the 128-bit value (returned by the API) is an offline guess oracle. `enrichSecretFields` (`finding.go:2935-2937`) does not carry it across a merge. RFC-043 §4.2 asks for a keyed HMAC over the **normalized raw secret**, keyed with a per-tenant secret the server holds (so the value is not a guess oracle) |
| #835 CT names → assets | `normalizeDomain` (lower, trailing dot, strip `*.`); exact `GetByNames` (type-blind) then ingest `ON CONFLICT (tenant_id, name)`; evidence `UNIQUE (asset_id, rule, source)` with `ON CONFLICT` (`000324:45`, `attribution_repository.go:58-76`); merge plan gains `easm_evidence` + `mergeAttribution` (most recent human decision wins) | No IDNA (U-labels dropped, A-labels kept raw). A kept asset with an automatic `needs_review` record and a merged legacy (implicitly confirmed) asset stays `needs_review`, blocking scans that ran before |
| #852 DNS-only checks | Exposure events; fingerprint = sha256(tenant, event_type, title, source, **asset_id**, `domain`) (`pkg/domain/exposure/entity.go:136-165`, develop); `BulkUpsert ON CONFLICT (tenant_id, fingerprint)` keeps state; auto-resolve/reopen only rows it resolved itself; `unknown` neither raises nor clears | **Develop bug, inherited:** an asset merge repoints `exposure_events.asset_id` (`asset_merge_plan.go:53`) without recomputing the stored fingerprint → the next check on the kept asset creates a second exposure and the moved one is never auto-resolved. A rename changes title/domain and orphans the old exposure `active`. Archived assets drop out of `DueTargets`, their exposures never resolve |
| #867 / #881 RFC-039 retest | `finding_retests` bound by `finding_id` (CASCADE); one pending per finding (`ux_finding_retests_one_pending … WHERE status='pending'`); tick claimed by CAS; settle locks retest + finding; reopen still by fingerprint; #881 restarts SLA on each reopen (no idempotency key) | Cooldown and caps are read-then-insert (not atomic). No idempotency key on dispatch: if `SetCommands` fails the row is settled `unknown` while the commands still run. After a merge or fingerprint change, re-detection creates a new finding, so the old resolved one (with its retest history) never regresses — no reopen, no fresh SLA. Deleting a finding (B1) cascades the retest history |
| #878 RFC-042 | Three layers (source records → links `asset_sources.linked_by` → canonical); inline strong-key / exact-name match, windowed hostname/IP only **propose** merges; private IPs keyed by (zone, address); split = merge plan in reverse; identity keys per type for repository, host, certificate (sha256), iam_user, domain; service rows `UNIQUE (tenant_id, asset_id, port, transport)` | Defines no key for ip, url, container image or cloud resource; F7 (name unique regardless of type) is a known limit — the cross-type absorb of §2.3 |

## 3a. Against verified practice

From the adversarially verified report `research/10-dedup-best-practices.md`
(R-numbers as in RFC-043 §16). Areas the research does not cover (asset
normalization, certificates, secrets, concurrency, lifecycle, tickets, testing)
are judged against the probes above only.

| Practice | Today | Gap |
|---|---|---|
| R1 Layered identity: tool's stable id, else explicit per-tool fields | Any ≥16-hex string the sensor sends is the identity; non-hex tool ids (Nessus, DefectDojo, gitleaks) are discarded; no per-tool field list | B23; identity is decided by whoever wrote the sensor |
| R2 Explicit scope; duplicates kept as linked records; earliest wins | Scope hashed into the fingerprint (asset id); merge collisions **delete** the moved row; `duplicate_of` never written | B1 |
| R3 SAST: tool + rule + path + partialFingerprints, no absolute lines | semgrep OSS fallback and `ctis` `sast` key on start/end line; `partialFingerprints` stored but not used | B3 |
| R4 Content hash + occurrence index; renames need explicit handling | `sast-content` exists in ctis but is unreachable from ingest; no rename handling | B3, D12 |
| R5 Triage follows the fingerprint across branches | finding identity is branch-independent (`finding_branch_occurrences`), so triage does carry across branches — **OK** | — |
| R6 Versioned fingerprints, compare on the newest shared version | no version stored (P15) | blocks any recipe change |
| R7 OSV `aliases` only, equivalence classes | `aliases` column never filled; GHSA ids not catalogued | B16 |
| R8 Correlation includes ecosystem/distro; per-source status | no correlation; one status per row, last writer for most columns | B6, B13 |
| R9 Canonical PURL, qualifier allowlist | PURL stored verbatim | B24 |

## 4. Edge-case checklist

"Covered" names an existing test in the repository that exercises the case on a
real database or the real function. Probes from this audit (`P*`) are listed as
evidence but are throwaway and **not** in the repository, so they do not count as
coverage.

### 4.1 Findings

| # | Edge case | Coverage |
|---|---|---|
| E1 | Two concurrent ingests of the same new finding produce one row | Not covered (P1 shows 1 row) |
| E2 | …and report exactly one "created" and fire hooks once | Not covered — **fails** (P1) |
| E3 | ON CONFLICT never overwrites tickets, metadata, assignee, SLA | Not covered — **fails** (P1b) |
| E4 | Same finding twice in one report | Not covered — counts wrong (P7) |
| E5 | Re-sent identical report is idempotent | Partially: `ingest_v2_test.go` (v2 report id); v1 not covered (P8: idempotent rows, broken counter) |
| E6 | `occurrence_count` grows by one per sighting | Not covered — **fails** (P8) |
| E7 | SAST line shift (code inserted above) keeps the finding | Not covered — **fails** (P4) |
| E8 | SAST finding moved to another file / renamed file | Not covered |
| E9 | SAST same rule twice in one function | Not covered |
| E10 | Windows vs POSIX path, `./src` vs `src`, absolute sensor path | Partially: betterleaks strips base path (sensor tests); API: not covered |
| E11 | Path case (`Src/A.go` vs `src/a.go`) — `sast` lower-cases, `sast-content` keeps case | Not covered |
| E12 | SCA version bump, still vulnerable | Not covered — **fails** (P5) |
| E13 | SCA same package in two manifests | Not covered (P5: merges, keeps one path) |
| E14 | SCA PURL case / qualifiers / `v` prefix | Not covered |
| E15 | Container re-tag of one digest | Not covered |
| E16 | Secret moved to another line | Not covered — **fails** (P12) |
| E17 | Two secrets with the same mask on one line | Not covered — merges (P12) |
| E18 | Secret rotated (new value, same place) | Not covered |
| E19 | DAST same template on two URLs | Not covered — merges without a sensor fingerprint (P6) |
| E20 | DAST query-value churn (`?id=1` / `?id=2`) | Not covered (sensor fingerprint splits them, **code**) |
| E21 | Network VA same CVE, same port, two scanners | Covered: `internal/app/ingest/processor_findings_netva_fingerprint_test.go` (`…_SameCVESameHostDifferentScanner_Dedups`, `…_CVEIDvsCVEIDsAgree`); P15 |
| E22 | Network VA multi-CVE plugin vs single-CVE plugin | Not covered — **fails** (P2) |
| E23 | Network VA port vs host-level | Not covered — splits (P2, P15) |
| E24 | Same CVE via package (trivy) and via host (Tenable) | Not covered — 2 findings, no correlation (P2) |
| E25 | Cross-tool merged finding not closed while any tool still sees it | Not covered — **fails** (P11) |
| E26 | Reopen after fix keeps the same row and history | Covered: `internal/infra/postgres/finding_regression_db_test.go`; P10 (same row, `confirmed`) |
| E27 | Reopen respects deliberate dispositions (FP, accepted) | Covered: `internal/infra/postgres/finding_reopen_human_resolved_db_test.go` |
| E28 | Fingerprint algorithm change keeps triage state | Not covered — no version is stored |
| E29 | Sensor fingerprint scheme change (e.g. semgrep login on/off) | Not covered |
| E30 | Tool version renames a rule id | Not covered |
| E31 | Pentest: two findings with one title in a campaign | Not covered — **fails** (**code**) |
| E32 | Manual fingerprint field-boundary collision | Not covered — **fails** (P13) |
| E33 | Manual finding vs identical scanner finding | Not covered (never dedups by design) |
| E34 | CVE id case on the finding | Not covered — **fails** (P14) |
| E35 | GHSA/OSV alias of a CVE | Not covered |
| E36 | Hostile sensor supplies a colliding fingerprint | Not covered (scoped by composite asset id, **code**) |

### 4.2 Assets and merge

| # | Edge case | Coverage |
|---|---|---|
| A1 | `Example.COM.` vs `example.com` | Covered: `pkg/domain/asset/normalize_test.go`; P3 |
| A2 | IDN U-label vs punycode | Not covered — **fails** (P3) |
| A3 | Wildcard `*.x` vs `x` — one rule for CT and ingest | Not covered — rules disagree |
| A4 | IPv6 forms, IPv4-mapped | Covered: `normalize_test.go`; P3 |
| A5 | IPv4 leading zeros | Not covered — **fails** (P3) |
| A6 | Bracketed IPv6 host | Not covered |
| A7 | URL default port, case, trailing slash | Covered: `normalize_test.go`; P3 |
| A8 | URL with vs without scheme | Not covered — splits |
| A9 | http_service stored name equals lookup key | Not covered — **fails** (P17) |
| A10 | Repo ssh vs https vs `.git` | Covered: `normalize_test.go`; P3 |
| A11 | Repo `.git/` trailing slash | Not covered — **fails** (P17) |
| A12 | Repo from SCM import vs CI ingest | Not covered — splits (**code**) |
| A13 | Container `nginx` vs `docker.io/library/nginx`, tag vs digest | Not covered — **fails** (P3) |
| A14 | Two ARNs that differ after `/` | Not covered — **wrong merge** (P17) |
| A15 | S3 bucket URL forms | Not covered — **fails** (P17) |
| A16 | Certificate fingerprint forms | Not covered |
| A17 | Same name, different asset type | Not covered — **absorbed** (P17) |
| A18 | Concurrent ingest of one new asset | Covered by ON CONFLICT; P1 |
| A19 | Merge moves every asset reference | Covered: `asset_merge_coverage_test.go` (`TestAssetMergeCoversEveryAssetReference`) |
| A20 | Merge recomputes finding fingerprints | Covered: `finding_fingerprint_recompute_test.go` |
| A21 | Merge keeps the triaged copy when both assets have the finding | Not covered — **fails** (P9) |
| A22 | Merge keeps comments, activities, evidence of the duplicate | Not covered — **fails** (cascade, §2.4) |
| A23 | Recompute runs in the merge transaction | Not covered — runs after commit, best-effort |
| A24 | Split (un-merge) | Not covered — no split exists |

### 4.3 Other entities

| # | Edge case | Coverage |
|---|---|---|
| O1 | Exposure batch containing a duplicate | Not covered — **fails** (P18) |
| O2 | Exposure fingerprint after asset merge / rename | Not covered — duplicates (**code**) |
| O3 | CT name whose nearest asset changes | Not covered — duplicates (**code**) |
| O4 | IOC canonical forms (trailing dot, IPv6, URL slash) | Not covered |
| O5 | Threat actor created twice | Not covered |
| O6 | Tenant-wide threat model regenerated concurrently | Not covered — **fails** (P18) |
| O7 | Two `create_ticket` actions for one finding at once | Not covered (sequential idempotency covered by `jira/sync_dedup_test.go`, `ticketing/github_ticket_test.go`) |
| O8 | GitHub owner/repo case differs from the issue URL | Not covered |
| O9 | Ticket link survives re-ingest | Not covered — **fails** on the race path (P1b) |
| O10 | Notification storm / duplicate "new finding" | Not covered |
| O11 | Command create retried by the client | Not covered |
| O12 | v1 report re-POST | Not covered (P8) |
| O13 | v2 report replay, same digest | Covered: `tests/integration/ingest_v2_test.go` |
| O14 | Branch occurrences with an in-batch duplicate | Not covered — **fails** (P18) |
| O15 | PURL case / qualifiers / `golang` vs `go` | Not covered |
| O16 | Same package name in two ecosystems on one asset | Not covered |
| O17 | GHSA ↔ CVE alias | Not covered |
| O18 | EPSS feed with a repeated CVE | Not covered |
| O19 | SARIF result with two `fingerprints` entries (adapter path) | Not covered |
| O20 | Same result via sensor parser and in-tree adapter | Not covered |
| O21 | Reversed asset dedup review pair | Not covered |
| O22 | Validation evidence re-POST | Not covered |

## 5. How the evidence was produced

Scratch PostgreSQL 17 (`postgres:17-alpine`) on a random local port, migrated
with `migrate/migrate:v4.18.3` to `000272`. The probes are Go tests in
`tests/integration` that build `ingest.NewService` with the real postgres
repositories (the same constructor as `ingest_host_exposure_test.go`) and log
`RESULT` lines:

| Probe | What it does | Result |
|---|---|---|
| P1 | 12 goroutines ingest one new network-VA finding at once | 1 finding row, 1 asset row, `sum(FindingsCreated)=2`, `occurrence_count=2` |
| P1b | Ticket link + metadata + `in_progress` on a finding, then the race loser's insert (`CreateBatchWithResult` with a fresh entity, same fingerprint) | `Created=1`, `work_item_uris={}`, `metadata={}`, status kept, returned id does not exist |
| P2 | One CVE on one host: Nessus :443, Qualys host-level, Qualys :443 listing two CVEs, trivy package, trivy lower-case CVE | 4 findings |
| P3 | 13 spelling pairs through asset ingest | 17 assets (13 expected) |
| P4 | SAST at line 42 marked FP, rescan at line 45 | FP row kept (stale), new row `new` |
| P5 | lodash 4.17.15 in progress with Jira link, rescan at 4.17.20, then two manifests | old row resolved with link, new row `new` without link; manifests merged |
| P6 | Same nuclei-style finding on two URLs, no sensor fingerprint | 1 finding |
| P7 | Same finding twice in one report | 1 row, `FindingsCreated=2` |
| P8 | Same report sent twice | 1 row, `occurrence_count=1` |
| P9 | Asset merge where the merged copy is `accepted_risk` + Jira | recompute deletes it; survivor is `new`, no link |
| P10 | Fix scan then re-detect | same row, `resolved` → `confirmed` |
| P11 | trivy creates, grype re-sees, trivy misses | `resolved` |
| P12 | Secret same mask twice on one line, then moved | 1 row for the two; move → new row, old resolved |
| P13 | Manual fingerprint boundary | identical hashes |
| P14 | CVE case, GHSA, PURL case | finding `cve_id` lower-case, no GHSA catalog row |
| P15 | Same CVE+port Nessus/Qualys, then host-level; `partial_fingerprints` | 1 then 2; only `composite/base` stored |
| P16 | 8 reports first-see one CVE concurrently | 1 catalog row |
| P17 | http_service, cross-type, ARN, repo `.git/`, s3 | see §2.3 |
| P18 | exposure batch with a duplicate; two tenant-wide threat models; Nessus no-CVE plugin on two ports; report with a duplicated finding on a default branch | 0 exposures (batch error); 2 models; 1 finding; 0 branch occurrences |
