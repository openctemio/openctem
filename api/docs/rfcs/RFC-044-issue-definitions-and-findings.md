# RFC-044 — Issue definitions and findings

> Status: **Accepted** (2026-10-03; decisions D1–D9 approved as recommended, §12; #895).
> P0 shipped (#907, #914, #917, #918, #921). **P1 implemented** (#1101 schema
> and backfill, migrations 000820–000827; #1102 domain package and
> repositories; #1103 docs): see §8.1. P2 next.
> Scope: api (catalog schema, ingest, prioritization, aggregation, routes),
> web (Issues view, finding identifiers), ctis + sdk-go (identifiers on the
> wire; separate repos, separate PRs).
>
> Question: vulnerabilities only record CVEs; how should a vulnerability be
> classified versus a finding?
>
> Current state with evidence:
> [architecture/vulnerability-model.md](../architecture/vulnerability-model.md).
> Sources: OSV schema, GitHub Advisory Database, the finding shape of the
> scanners we ingest, OCSF finding classes (§13).
>
> Builds on and must stay consistent with:
> - [RFC-043](RFC-043-deduplication-and-identity.md) (PR #892) — finding identity, fingerprints, and the
>   canonical vulnerability id. **This RFC owns the catalog that RFC-043's
>   `vulnerability_aliases` resolves into** (§5.3); RFC-043 owns how a finding
>   is keyed.
> - [global-catalog-trust.md](../architecture/global-catalog-trust.md) — tenant
>   input may create a catalog identity, never change shared content.
> - [ADR-004](../architecture/decisions/004-finding-provenance.md) —
>   `findings.source` is technique, `ingest_channel` is channel.
> - PR #849 — `findings.type_details`: per-instance facts by type.
> - [RFC-015](RFC-015-remediation-groups.md) (remediation groups),
>   [RFC-017](RFC-017-ctem-prioritization-surfacing.md) (P0–P3),
>   [RFC-039](RFC-039-continuous-retest.md) (retest), RFC-040 (mutual distrust:
>   sensor claims are hints).

## 1. Answer in short

The design separates the **definition** of an issue (a catalog entry: what it
is, how bad it is in general, how to fix it) from the **finding** (one
occurrence on an asset or code location), and CVE is not the key: a Tenable
finding we ingest is keyed on asset + plugin + port + protocol and a plugin
maps to zero, one or many CVEs; GitHub and OSV issue their own ids and treat
CVE as an alias. The catalog is therefore a registry of *any* identifier
string, linked to findings through an ordered join where position 0 is the
primary id. OCSF splits findings into classes by kind (Vulnerability 2002,
Compliance 2003, Detection 2004, Data Security 2006, AppSec Posture 2007) and
lets a vulnerability entry be identified by a CWE or an advisory alone.

OpenCTEM today has a CVE table and loose per-finding columns. This RFC turns it
into:

1. **A definition catalog.** The existing `vulnerabilities` table, **extended in
   place** (same row ids, so every `findings.vulnerability_id` stays valid) and
   later renamed `issue_definitions`. A definition has a **kind**, a primary
   **`(namespace, external_id)`** (CVE, GHSA, OSV ecosystems, vendor advisory,
   nuclei template, semgrep/CodeQL rule, Trivy/Checkov check, secret rule,
   Tenable plugin, Qualys QID, pentest custom…), a **scope** (global, or one
   tenant for custom rules and pentest issues), a **lifecycle** (published,
   rejected, withdrawn, disputed…) and the shared text, scores and references.
2. **Typed identifiers and relations.** `definition_identifiers` maps every
   identifier to exactly one definition (same-vulnerability aliases, OSV
   `aliases`); `definition_relations` holds `upstream`, `related` and
   `detects` (plugin/template → CVE) edges. Aliases are never flattened with
   upstream/related — that would corrupt "this CVE affects N assets".
3. **A classification**: `vulnerability`, `weakness`, `misconfiguration`,
   `exposure`, `secret`, `compliance`, `malicious`, each mapped to an OCSF
   class. `findings.finding_type` takes the same values.
4. **Findings as instances** linking to one or more definitions through
   `finding_definitions(finding, definition, role, ord)`: one **primary** (the
   issue, ord 0), plus `detected_by` (the rule/plugin/template that found it),
   further CVEs, and weakness links. A finding with no CVE still has a primary
   definition — its rule.
5. **Prioritization per kind.** CVSS/EPSS/KEV stay attributes of
   CVE-namespace definitions and are projected onto findings as the worst value
   over the alias cluster. Other kinds get their own "known exploitable" signal
   (verified live secret, validated exposure, KEV CWE…) so P0 is reachable for
   every kind on evidence, never on severity alone.
6. **Aggregation by definition.** One "Issues" view: one row per definition per
   tenant with affected assets, open findings and worst priority, for every
   kind. Remediation groups gain a `def:` key; campaigns and dashboards filter
   and rank by definition.
7. **Migration without breaking ids**: additive columns, backfill the 69 CVE
   rows as `namespace = CVE`, dual-write, switch reads, compat view, then drop.

## 2. Problem (summary of the audit)

From [vulnerability-model.md](../architecture/vulnerability-model.md) §8:

| # | Gap | Live evidence |
|---|---|---|
| G1 | Catalog is CVE-only (`cve_id VARCHAR(30) UNIQUE NOT NULL`, `000011:9`); no definition for any other identifier | 30 of 103 findings (29 %) have no CVE and no definition |
| G2 | One `cve_id` per finding; `cve_ids[1:]`, GHSA, plugin family, CPE, SARIF taxa, references dropped at ingest | — |
| G3 | No alias resolution; `aliases TEXT[]` never written | 3 non-empty, all nicknames |
| G4 | No trusted CVE source; first reporter's text; no rejected/withdrawn; KEV flag never cleared | 69 rows, all `status = open` |
| G5 | v2 ingest cannot create catalog rows; no back-link job | 17 CVE findings unlinked, 5 of them to CVEs that *are* catalogued |
| G6 | Priority ignores kind, CVSS, exploit availability, secret validity; both P0 rules require KEV | 0 of 30 no-CVE findings are P0/P1 |
| G7 | No aggregation by rule/template/check; default group-by hides non-CVE | `github-pat` on 3 assets = 4 unrelated rows |
| G8 | Five coarse types, inconsistently set | 13 of 14 betterleaks secrets typed `vulnerability` |
| G9 | `rule_name`/`tags` never inserted; CodeQL CWE tags not parsed | 20 of 103 rows have them (re-sighted only) |
| G10 | Exposure pages partition by `source`, missing va/container/cspm/easm/external | — |

## 3. Goals and non-goals

Goals
- Any issue a scanner, integration or person reports has a definition, whether
  or not it has a CVE.
- One finding can carry every identifier the source reported, typed, and none
  is dropped.
- "This issue affects N assets" works for every kind.
- Priority is meaningful for every kind and explainable.
- No existing id changes; existing APIs keep working through the migration.
- The shared catalog stays trusted (global-catalog-trust.md, RFC-040).

Non-goals
- Finding identity, fingerprints, merge/split and cross-tool correlation —
  RFC-043. This RFC gives RFC-043 the canonical definition to key on.
- Asset identity — RFC-042.
- Per-instance type facts — #849 `type_details` stays the place for them.
- A new risk score. P0–P3 (RFC-017) stays the organizing principle; this RFC
  feeds it per kind.

## 4. Classification

### 4.1 Kinds

| Kind | Meaning | Typical identifiers | OCSF class |
|---|---|---|---|
| `vulnerability` | A flaw in a specific product/package/version with an advisory | CVE, GHSA, OSV (PYSEC, RUSTSEC, GO…), vendor (RHSA, DSA, USN, MSRC), Tenable plugin, Qualys QID, nuclei CVE template | 2002 Vulnerability Finding |
| `weakness` | A flaw class in first-party code, no advisory | semgrep/CodeQL/SARIF rule + CWE, SWC (web3) | 2007 Application Security Posture Finding (2002 with `cwe` on OCSF < 1.5) |
| `misconfiguration` | A resource deviates from a secure setting | Trivy AVD/DS, Checkov `CKV_*`, KICS, Prowler, CIS recommendation | 2003 Compliance Finding |
| `exposure` | Something reachable that should not be (panel, file, service, takeover, default login, dangling DNS) without an advisory | nuclei template, EASM check | 2002 Vulnerability Finding (OCSF counts configuration flaws as vulnerabilities) |
| `secret` | A credential or key exposed in code, image or logs | betterleaks/gitleaks rule, trufflehog detector | 2006 Data Security Finding |
| `compliance` | A control evaluated against a framework and failed | framework + control id (CIS, NIST 800-53, ISO 27001, PCI DSS, ASVS) | 2003 Compliance Finding |
| `malicious` | Malware, a malicious package, an IOC match | OSV `MAL-`, GHSA malware advisories, detection rule | 2004 Detection Finding |

`misconfiguration` vs `compliance`: a check is a misconfiguration; the same
check *mapped to a control* produces compliance evidence. One finding is
misconfiguration; the control mapping lives in taxonomy links (§5.4), and the
compliance module reads it. A `compliance` finding is only one that a framework
assessment reports as such (e.g. a manual control test).

`web3` today is a domain, not a kind: SWC entries become `weakness`
definitions in the `SWC` namespace; `type_details.web3` keeps the chain facts
(decision D3).

### 4.2 Kind of a finding

`findings.finding_type` = the kind of the finding's **primary definition**,
decided at ingest from (in order): the CTIS type, the definition's kind (when
the definition already exists in the catalog), the identifier namespace (CVE
→ vulnerability; a secret-scanner rule → secret), then the tool category. This
replaces "one `source` per report" as the type input (G8). `source` keeps its
ADR-004 meaning (technique).

## 5. Data model

### 5.1 `issue_definitions` (today `vulnerabilities`, extended in place)

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | **unchanged for the 69 existing rows** |
| `tenant_id` | uuid NULL | NULL = global; set = visible only to that tenant (custom rules, pentest issues, unknown scanner rules — §5.5) |
| `kind` | enum §4.1 | backfill `vulnerability` |
| `namespace` | text | `CVE`, `GHSA`, `OSV:<db>`, `RHSA`, `NUCLEI`, `SEMGREP`, `CODEQL`, `TRIVY`, `CHECKOV`, `BETTERLEAKS`, `TENABLE`, `QUALYS`, `SWC`, `PENTEST`, `CUSTOM` … (registry in code, §5.6) |
| `external_id` | text | the id inside the namespace, normalized (CVE upper-case) |
| `cve_id` | varchar(30) NULL | **compat**: equals `external_id` when `namespace = 'CVE'`, else NULL; partial UNIQUE keeps `ON CONFLICT (cve_id)` working until P6 |
| `title`, `description`, `remediation`, `reference_urls` | | shared text; writer rules §5.5 |
| `severity`, `cvss_score`, `cvss_vector`, `cvss_version` | | definition default; findings may carry the reporter's own |
| `epss_score`, `epss_percentile`, `cisa_kev_*`, `exploit_available`, `exploit_maturity` | | only meaningful on CVE-namespace rows; feed-written |
| `affected_versions`, `fixed_versions` | | as today |
| `lifecycle` | enum | `published`, `reserved`, `rejected`, `withdrawn`, `disputed`, `deprecated`, `merged` |
| `merged_into` | uuid NULL | set when a definition is folded into another (§5.3) |
| `origin` | enum | `cve_list`, `nvd`, `osv`, `ghsa`, `kev`, `rule_catalog` (platform-curated rule packs), `report` (identity stub created by ingest), `tenant` |
| `published_at`, `modified_at`, `created_at`, `updated_at` | | as today |

Uniqueness: `UNIQUE (namespace, external_id) WHERE tenant_id IS NULL` and
`UNIQUE (tenant_id, namespace, external_id) WHERE tenant_id IS NOT NULL`.

Removed in P6: `aliases TEXT[]` (moved to identifiers), `status`
(open/patched/… is tenant state on findings, not a property of a global
definition; it is `open` on every row and nothing reads it).

### 5.2 `definition_identifiers` — "the same issue"

```
definition_identifiers(
  namespace text, external_id text,
  tenant_id uuid NULL,           -- NULL for global identifiers
  definition_id uuid NOT NULL REFERENCES issue_definitions,
  is_primary bool NOT NULL,
  asserted_by text NOT NULL      -- osv | ghsa | cve_list | nvd | rule_catalog | report | tenant
)
-- unique per scope, as in §5.1:
--   UNIQUE (namespace, external_id) WHERE tenant_id IS NULL
--   UNIQUE (tenant_id, namespace, external_id) WHERE tenant_id IS NOT NULL
```

Every identifier resolves to exactly one definition (OSV `aliases`:
symmetric, transitive). Lookup `GHSA-xxxx` → definition → its CVE primary.
This **is** the `vulnerability_aliases` table RFC-043 §4.2 footnote 4 asks for:
one table, not two (decision D7). Primary choice per cluster follows RFC-043:
CVE > GHSA > OSV/vendor > scanner rule.

### 5.3 `definition_relations` — "different issues that are connected"

```
definition_relations(from_id, to_id, relation, asserted_by)
  relation ∈ { upstream, related, detects }
```

- `upstream` (OSV ≥ 1.7): a distro advisory (DSA/RHSA/USN) bundles a library
  CVE. Transitive, not symmetric. Never an alias.
- `related` (OSV): symmetric, not transitive.
- `detects`: a rule/plugin/template detects a vulnerability (Tenable plugin
  12345 → CVE-A, CVE-B; nuclei `CVE-2021-44228` → CVE-2021-44228). From the
  rule catalog or from the report.

**Merging.** When a trusted feed reveals that two existing definitions are
aliases (a GHSA definition created first, then a CVE assigned), the
non-primary one gets `lifecycle = merged`, `merged_into = <primary>`, its
identifiers move to the primary, and `finding_definitions` rows are re-pointed
in the same transaction. Only trusted feeds merge global definitions (§5.5).
Finding fingerprints keyed on the old canonical id are handled by RFC-043's
fingerprint alias table, not here.

### 5.4 Taxonomies are links, not definitions

CWE, CAPEC, OWASP Top 10, ASVS, MITRE ATT&CK, CIS/NIST/ISO controls classify
definitions; they are not the issue. Storing CWE as a
vulnerability id is a pattern to avoid.

```
taxonomy_entries(namespace, external_id, title, parent)     -- global, seeded from MITRE/OWASP/CIS lists
definition_taxonomy(definition_id, taxonomy namespace, external_id, asserted_by)
```

`findings.cwe_ids` / `owasp_ids` stay as the reporter's per-instance claim
(and the compat read path); the definition's links are the shared mapping.
`kev_catalog.cwes[]` feeds `definition_taxonomy` for CVEs, which also gives
the "KEV CWE" signal of §6.

### 5.5 Scope and trust

Following global-catalog-trust.md and RFC-040 (a sensor's claim is a hint):

| Definition | Scope | Who creates the identity | Who writes shared content |
|---|---|---|---|
| CVE / GHSA / OSV / vendor advisory | global | trusted feed; ingest may create an identity **stub** (`origin = report`) for an id nobody has reported, as today | trusted feeds only (§8 P3). A stub shows the reporter's text **only to that tenant** (as today, from the finding) |
| Rule in a platform-curated pack (nuclei-templates, semgrep registry, Trivy checks, Checkov, betterleaks default rules, Tenable plugin metadata) | global | the rule-catalog import job (`origin = rule_catalog`) | the import job |
| Any other rule id a sensor reports (custom nuclei template, custom semgrep rule, unknown plugin) | **tenant** | ingest | ingest, from that tenant's own reports |
| Pentest issue / tenant custom definition | tenant | the user (`pentest_finding_templates` become tenant definitions; system templates become global `PENTEST` definitions) | the tenant |

Alias claims made by a report (trivy says GHSA-x = CVE-y) are stored on the
finding (`finding_definitions`, role `alias`), never as a global identifier.
Only `osv`/`ghsa`/`cve_list` assert global aliases. A hostile sensor therefore
cannot merge two global definitions or rename one.

### 5.6 Namespace registry

A Go table (`pkg/domain/definition/namespace.go`) with, per namespace: the id
pattern and normalizer (upper-case CVE, GHSA lower-case body per GitHub), the
default kind, display prefix, reference URL template, and whether it is
global-capable. Detection from prefix follows the OSV convention
(`<DB>-<ENTRYID>`); a scanner rule never relies on prefix guessing — ingest
knows the tool and sets the namespace. Unknown advisory prefixes go to
`OSV:<prefix>`; unknown tools to `CUSTOM:<tool>` (tenant scope).

### 5.7 `finding_definitions` — findings as instances

```
finding_definitions(
  finding_id uuid, tenant_id uuid,
  definition_id uuid,
  role text,                 -- primary | detected_by | additional | alias | weakness
  ord smallint,              -- 0 = primary
  asserted_by text,          -- report | feed | user
  UNIQUE (finding_id, definition_id),
  UNIQUE (finding_id, ord)
)
```

- `primary` (ord 0, exactly one): the issue. CVE when present (after alias
  resolution), else the rule/template/check/secret rule/pentest definition.
- `detected_by`: the scanner rule (nuclei template, Tenable plugin) when the
  primary is an advisory. This is the "vuln_id_from_tool" grouping key worth keeping.
- `additional`: other CVEs of the same finding when RFC-043 D3 keeps them on one
  finding (if D3 = one finding per CVE, network VA findings have one CVE primary
  and the plugin as `detected_by`; nuclei templates with several CVEs still need
  `additional`).
- `alias`: a report-asserted alias not (yet) confirmed by a feed.
- `weakness`: a CWE-typed SAST rule's link when the rule is primary and the
  scanner also named an advisory (rare).

Denormalized on `findings` for hot paths: `definition_id` (primary, new),
`vulnerability_id` (kept: primary *vulnerability-kind* definition, for the
existing joins), `cve_id` (kept: primary CVE string, compat).

### 5.8 Wire format (ctis + sdk-go)

CTIS gains, on a finding:

```json
"identifiers": [
  {"type": "rule",     "namespace": "TENABLE", "value": "156860"},
  {"type": "advisory", "namespace": "CVE",     "value": "CVE-2021-44228"},
  {"type": "advisory", "namespace": "CVE",     "value": "CVE-2021-45046"},
  {"type": "advisory", "namespace": "GHSA",    "value": "GHSA-jfh8-c2jp-5v3q"},
  {"type": "taxonomy", "namespace": "CWE",     "value": "CWE-502"}
]
```

`vulnerability.cve_id`, `cve_ids[]`, `cwe_ids[]`, `rule_id` stay (old sensors);
ingest merges them into the same list. The sdk-go parsers stop dropping what
the audit lists (vulnerability-model.md §4.2): nuclei `cve-id[1:]`, trivy
`VulnerabilityID` by namespace + `PkgIdentifier.PURL`, CodeQL
`external/cwe/*` tags, Tenable `cve[]`/xref/IAVA/MSFT/plugin family, SARIF
`taxa`, Checkov/CIS refs. Under RFC-040 these remain claims: they create
tenant-scoped links and global identity stubs, never global content.

## 6. Prioritization per kind

The classifier (`pkg/domain/vulnerability/priority.go:274`) keeps its shape:
P0 needs **evidence of exploitability** plus **reachability** (or a crown
jewel). What changes is that each kind supplies its own evidence instead of
only KEV:

| Kind | Exploit evidence (P0-eligible) | Likelihood signal (P1/P2) | Severity fallback |
|---|---|---|---|
| vulnerability | KEV on **any** identifier of the cluster; validated exploit (RFC-011/039) | EPSS max over the cluster; exploit maturity | definition CVSS, then reporter severity |
| exposure | validated by retest/validation (RFC-039, RFC-011) **and** in a high-impact class (default login, takeover, unauthenticated admin, RCE template) | template severity × internet-facing | reporter severity |
| secret | **verified live** (`secret_valid` and not revoked) | unverified but not revoked; in current tree vs history only | revoked → P3 regardless of severity |
| weakness | validated (pentest/DAST confirms) | CWE in the KEV-CWE set or CWE Top 25; rule confidence; code reachable from an internet-facing service | rule severity; never P0 without validation |
| misconfiguration | validated public exposure (bucket readable, port open from outside) | resource internet-facing; data sensitivity of the resource | check severity |
| compliance | — (not risk-ranked to P0) | framework control criticality | SLA by framework |
| malicious | active detection on the asset | IOC confidence | — |

Rules that follow: a verified live secret on a reachable asset is **P0**; a
revoked one is **P3**. A nuclei exposure confirmed by retest on an internet
asset can be P0; an unvalidated one tops out at P1. A CWE-only SAST finding
never reaches P0 on severity alone.

The classifier gains `Kind`, `ExploitEvidence` (enum: kev, validated,
verified_live, active_detection, none) and `LikelihoodScore` (EPSS or a kind
proxy), computed in `buildPriorityContext` from the primary definition and
the instance. CVSS fills a missing severity. Tenant priority rules
(`priority_rule.go:117-146`) gain `finding_type`, `definition` (namespace /
external id), `exploit_evidence` and `secret_valid`. Every class reason names
the evidence ("Verified live AWS key on internet-facing asset").

KEV and EPSS lookups move from `findings.cve_id` to the CVE identifiers of the
finding's definitions (primary + additional + alias), taking the worst value
over RFC-043's alias cluster.

## 7. Aggregation

**Issues view** — one row per (tenant, definition): kind, namespace:id, title,
open findings, affected assets, worst priority, oldest open, SLA breaches,
KEV/EPSS where they apply. Query over `finding_definitions` (role `primary`,
optionally `detected_by`) joined to open findings; materialize per tenant only
if measurement shows a need.

- "Same nuclei template on 40 hosts" → one row, 40 assets.
- "Same semgrep rule in 30 files" → one row, 30 findings, N repositories.
- "Same Checkov check on many buckets" → one row.
- "Log4Shell from trivy (GHSA), Tenable (plugin → CVE) and nuclei (template)"
  → one row via the alias cluster; "Detected by" lists the three rules.

Group-by "Issue" (`group_by=definition`) replaces CVE as the default on the
findings page; `cve_id` stays as a filter. Bulk actions (assign, mark fixed,
accept risk, ticket) work on an Issue group.

**Remediation groups (RFC-015)** gain a third key, ahead of solution text:
`def:<definition_id>` for kinds whose fix is per definition (misconfiguration,
weakness rule, exposure template, secret rule → "rotate and remove"). `sca:`
stays first for package upgrades. **Campaigns** gain `definition_ids` and
`kinds` in their finding filter. **Dashboards** get "Top issues" (by affected
assets × priority) across kinds, and kind breakdowns replace source
breakdowns where the question is "what kind of problem".

**Threat intel**: KEV/EPSS match through definitions; `/threat-intel` lookups
accept any identifier (`GHSA-…` resolves to its CVE).

## 8. Migration and phases

No id changes at any step. Migration numbers are taken at implementation time
(highest on `develop` today: 000272; #849 holds 000274).

**P0 — bugs, no model change** (each a small PR; worth doing now)
1. Insert `rule_name` and `tags` on first write (`finding_repository.go:161-191`,
   `:486-511`).
2. betterleaks/gitleaks findings typed `secret` (ingest type decision,
   `processor_findings.go:1114-1154`); one-off reclassification of existing rows
   is an approved data change.
3. Widen `findings.cve_id` to 30, upper-case on write; back-link findings whose
   CVE is catalogued; periodic back-link for v2-ingested CVEs.
4. KEV propagation clears `cisa_kev_*` / `exploit_available` for CVEs that
   left the catalog.
5. `findings/groups?group_by=rule_id` (+ web option, "View group") — the cheap
   interim answer to G7.
6. sdk-go: CodeQL `external/cwe/*` tags; keep nuclei `cve-id[1:]` and Tenable
   `cve[]` in `cve_ids[]` (already on the wire).

**P1 — catalog schema, additive**
- Add §5.1 columns to `vulnerabilities` with defaults; backfill
  `kind='vulnerability', namespace='CVE', external_id=cve_id,
  origin='report'|'kev'`; make `cve_id` nullable with the partial UNIQUE.
- Create `definition_identifiers` (backfill one primary per row; move
  `aliases` nicknames to `title`/a `nickname` field — they are not identifiers),
  `definition_relations`, `taxonomy_entries`, `definition_taxonomy`,
  `finding_definitions` (backfill ord 0 from `findings.vulnerability_id`),
  `findings.definition_id`.
- Repositories and domain package `pkg/domain/definition`; `vulnerability`
  domain keeps working on top.

**P2 — identifiers end to end, dual-write**
- CTIS `identifiers[]`; sdk-go parsers per §5.8; ingest resolves every
  identifier (global lookup, then tenant), creates stubs/tenant definitions per
  §5.5, writes `finding_definitions`, sets `definition_id`, keeps writing
  `vulnerability_id`/`cve_id`.
- Backfill rule definitions from existing findings (`rule_id` + normalized
  tool → namespace), tenant-scoped.
- Pentest templates → definitions.

**P3 — trusted sources**
- CVE List v5 bulk (lifecycle: rejected/reserved; CNA CVSS) and OSV bulk
  (GHSA + ecosystem advisories, `aliases`/`upstream`/`related`) as platform
  feeds, admin-controlled like EPSS/KEV. NVD API optional (D6).
- Rule-catalog import: nuclei-templates metadata, Trivy checks, Checkov,
  semgrep registry, betterleaks rules, from the same content versions the
  sensor uses (RFC-031), signed where RFC-031 signs them.
- Merge procedure (§5.3); rejected/withdrawn handling (D4).

**P4 — prioritization per kind** (§6), tenant rule fields, reason text,
re-classification job for open findings (dry-run first, diff reported).

**P5 — aggregation and UI** (§7, §9).

**P6 — cleanup**
- Rename `vulnerabilities` → `issue_definitions`; a read-only view
  `vulnerabilities` (namespace = CVE) for one release.
- Drop `aliases`, `status`; `findings.cve_id` becomes derived (kept as a column
  for indexes and filters, written only from the primary CVE).
- `/api/v1/vulnerabilities*` answered from definitions with
  `namespace = CVE`, marked deprecated (RFC-041 deprecation middleware, #880).

Rollback: P1–P2 are additive and dual-written; reads switch per surface behind
a setting until P6.

### 8.1 P1 as implemented

What landed, and where it refines the design above (current state:
[vulnerability-model.md §9](../architecture/vulnerability-model.md#9-definition-catalog-schema-rfc-044-p1)).

- **Columns** (000820): `tenant_id`, `kind`, `namespace`, `external_id`,
  `lifecycle`, `merged_into`, `origin`, plus `cvss_version` (§5.1 lists it;
  the table had none) and `nicknames TEXT[]` (the "nickname field" of P1).
  Defaults describe today's rows (global CVE), so the deployed code keeps
  inserting valid rows; a trigger fills `external_id` from `cve_id` for those
  inserts.
- **`cve_id`** is nullable and keeps its plain `UNIQUE (cve_id)` constraint
  instead of a new partial index: NULLs never conflict, so it is already unique
  over CVE rows only, and `ON CONFLICT (cve_id)` needs no predicate. A CHECK
  keeps `cve_id` set exactly on CVE rows, global, equal to `external_id`.
- **Scope key.** Every table that points at a definition references
  `(id, scope_tenant_id)`, where `scope_tenant_id` is `tenant_id` or the nil
  UUID for a global row, with a CHECK that the scope is global or the row's own
  tenant. A foreign key ignores a row with a NULL key column, so `tenant_id`
  alone could not prove "global or mine". `finding_definitions` carries
  `definition_scope` for the same reason, and references its finding by
  `(id, tenant_id)`. `findings.definition_id` must be one of the finding's own
  links (immediate key: link first, then point). A definition's scope never
  changes (trigger).
- **Trust in the schema** (§5.5): a global alias identifier only from
  `osv`/`ghsa`/`cve_list`, a global relation only from a feed or the rule
  catalog, a global taxonomy link only from a feed (KEV included) or the rule
  catalog; a tenant row only from `report` or `tenant`.
- **Backfill.** `external_id = cve_id`; `origin = kev` when CISA KEV lists the
  CVE, else `report` (no feed inserts catalog rows, so every other row came from
  a report or a seed); the non-identifier entries of `aliases` became
  `nicknames`. Identifier-shaped `aliases` entries were **not** made global
  identifiers: reports and seeds wrote them, and only the alias feeds may
  assert a global alias. One primary identifier per definition (and a trigger
  writes it for every new row, whoever inserts it); `finding_definitions`
  ord 0 and `findings.definition_id` from `findings.vulnerability_id`. Batched
  with a commit per batch; `updated_at` unchanged.
- **Readers.** `VulnerabilityRepository` (the CVE catalog API) serves only
  global CVE rows, so a tenant definition is never reachable through it. The
  new `pkg/domain/definition` (kinds, namespace registry, scope, trust rules)
  and `DefinitionRepository` / `FindingDefinitionRepository` are not called
  yet.
- **Finding merge** (RFC-043): `finding_definitions` stays on the tombstone;
  the survivor keeps its own links.
- **Gap until P2:** findings stored after P1 get no `finding_definitions` row
  or `definition_id` (the deployed ingest does not write them). P2 starts with
  the 000824 backfill again (idempotent) before dual-write takes over.

## 9. API and UI

API (paths follow RFC-041):
- `GET /api/v1/issues` — tenant Issues rollup (filters: kind, namespace,
  priority, asset, owner, KEV, has_open; sort by affected assets/priority).
- `GET /api/v1/issues/{definition_id}` — definition + this tenant's numbers +
  affected assets/findings.
- `GET /api/v1/definitions/lookup?id=GHSA-…` — resolve any identifier to its
  definition and cluster (global + caller's tenant).
- Finding responses gain `definitions: [{id, kind, namespace, external_id,
  role}]` and `primary_definition`. `cve_id`, `vulnerability_id` stay.
- `/findings/groups?group_by=definition|rule_id`; campaign filter
  `definition_ids`, `kinds`; priority-rule fields of §6.
- Tenant definition write routes (custom rule text, pentest issue library);
  global definitions stay 403 for tenants.

Web:
- **Issues** page with kind tabs (Vulnerabilities, Weaknesses,
  Misconfigurations, Exposures, Secrets, Compliance, Malicious), replacing the
  four source-partitioned exposure pages — which fixes G10 (va, container,
  cspm, easm, external become visible). The CVE catalog tab stays as a
  definition browser.
- Finding detail: identifier chips (CVE, GHSA, plugin, template, CWE) with
  links from the namespace registry; "Same issue on N other assets".
- Findings list: group-by "Issue" (default) and "Rule".
- Priority badge reason shows the kind's evidence.

## 10. Threat model

- **Poisoning the global catalog** — tenant input creates identity stubs only;
  content, aliases and merges come only from trusted feeds and the rule-catalog
  import (§5.5). Unchanged from global-catalog-trust.md, extended to rules.
- **Cross-tenant leak through definitions** — custom rules, pentest issues and
  unknown scanner rules are tenant-scoped; the Issues query is tenant-filtered
  on findings and on `tenant_id IS NULL OR = caller`. A custom template's name
  can reveal internal targets; it never goes global.
- **Over-merging** — aliases only from OSV/GHSA/CVE List; upstream/related kept
  apart; merges audited and reversible (`merged_into`, identifiers moved, not
  deleted).
- **Priority manipulation by a sensor** — a sensor can claim `secret_valid`
  or "validated"; P0 on `verified_live` requires the platform's own
  verification or a signed sensor result (RFC-040) — decision D5.

## 11. Alternatives considered

| Alternative | Why not |
|---|---|
| Keep the CVE table, add a separate `rule_definitions` table | Two catalogs, two FKs per finding, every Issues/dashboard query a UNION; Tenable plugins and nuclei CVE templates sit in both |
| Only add `group_by=rule_id` | Cheap and included in P0, but gives no shared text, no aliasing, no cross-scanner view, no per-kind priority |
| New `issue_definitions` table, copy the CVEs, map old→new ids | Rewrites every `findings.vulnerability_id`; extending in place keeps ids (D1) |
| Flat `aliases TEXT[]` including upstream/related | Over-merges; distro advisories would swallow library CVEs |
| CWE as a definition | A weakness class is not an issue instance definition; kept as taxonomy |
| Store definitions nested per finding (OCSF-style) | No catalog lifecycle, no aggregation key |
| Per-tenant copy of the global catalog | Duplication; feeds would write N copies |

## 12. Decisions (approved 2026-10-03, all as recommended)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Extend `vulnerabilities` in place (keep ids; rename in P6 with a compat view) or create a new table and remap ids? | **Extend in place** |
| D2 | Scanner rules: global only for platform-curated packs, tenant-scoped otherwise? | **Yes** — a sensor-reported rule never becomes global content |
| D3 | Kinds: the seven of §4.1; `finding_type` takes the same values; `web3` becomes a domain (SWC → weakness) | **Yes** |
| D4 | A CVE becomes rejected/withdrawn: findings stay open, flagged, excluded from P0–P1 and metrics, owner notified — or auto-close as false positive? | **Flag, demote, notify; no auto-close** |
| D5 | Per-kind P0 evidence (§6): verified live secret, validated exposure, KEV for CVEs; SAST never P0 unvalidated. Does a sensor's "verified" count, or only a platform/retest verification? | **Yes to §6; sensor claim counts only when signed (RFC-040), else P1 max** |
| D6 | Trusted sources: CVE List v5 + OSV bulk first; NVD API optional | **CVE v5 + OSV** |
| D7 | RFC-043's `vulnerability_aliases` is this RFC's `definition_identifiers` (one table) | **Yes** — coordinate before either implements |
| D8 | Issues page with kind tabs replaces the source-partitioned exposure pages | **Yes** |
| D9 | Drop catalog `status` and `aliases` in P6 | **Yes** |

## 13. Research

Reviewed 2026-10-03, each claim checked against its source (24 of 25
confirmed). Primary sources: OSV schema (ids, `x_` local
prefix, `aliases`/`upstream`/`related` semantics), GitHub Advisory Database
(GHSA independent of CVE; malware advisories), the finding shape of the
network scanners we ingest (asset + plugin + port + protocol), OCSF 1.3–1.9
finding classes and the `vulnerability` object (CWE-only and advisory-only
entries). Caveats: the misconfiguration →
Compliance Finding mapping passed 2–1; the CVE lifecycle states and the
per-kind prioritization model (§6) are design choices, not external facts.
