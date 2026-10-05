# Finding source interoperability (CTIS 1.4)

A finding reported by a scanner, a connector or an imported file often carries
more than the normalized CTIS finding: the source's own check id and severity
scale, several scores, a VEX statement, the source's own lifecycle, solution
metadata and fields nothing maps to. CTIS 1.4 carries them in optional members
([ctis spec section 4.10](https://github.com/openctemio/ctis/blob/main/docs/spec.md));
this page describes what the API does with them.

The rule throughout: the normalized value stays in the existing member and
column (`severity`, `status`, `cve_id`, `rule_id`), and the source's own value
is kept beside it. Nothing here replaces the platform's own lifecycle, priority
or identity recipes.

## What is stored

Migration `001065_finding_source_interop` adds nullable columns to `findings`,
written per sighting by fingerprint (`FindingRepository.UpdateInteropBatch`)
and read only by the finding detail (`GET /api/v1/findings/{id}`, field
`source_data`):

| Column | CTIS member | Notes |
|---|---|---|
| `native_vuln_id`, `native_scheme` | `native.vuln_id`, `native.scheme` | Plugin ID, QID, rule id; indexed per tenant for correlation |
| `source_meta` (jsonb) | `native`, `source_lifecycle`, `remediation.solution_type` / `patch_published_at` / `advisories` | Detail view only |
| `scores` (jsonb array) | `scores[]` plus the legacy `cvss_*`, `epss_*`, `vpr_score` (`ctis.AllScores`) | Every score with system, version, vector, value, source, date |
| `vulnerability_ids` (jsonb array) | `cve_id`, `cve_ids`, `vulnerability.ids[]` (`ctis.VulnerabilityIDs`) | Canonical, typed (cve, ghsa, osv, vendor) |
| `source_extra` (jsonb object) | `source_extra` | Strings only, at most 64 entries and 32 KiB |
| `location_key` | derived (`ctis.LocationKey`) | Never taken from the report |
| `vex_status`, `vex_justification`, `vex_statement`, `vex_source`, `vex_at` | `vex` | Latest statement, replaced as a whole |

A later sighting replaces each member it carries and keeps the others.

## Identity and correlation

The server identity recipes ([RFC-043](../rfcs/RFC-043-deduplication-and-identity.md))
stay the dedup key: *(tenant, asset, vulnerability or rule, normalized
location)*. CTIS 1.4 feeds them without changing any stored key:

- `fillFromInterop` (`internal/app/ingest/interop.go`) runs before the CVE
  catalog step. When a report leaves `cve_id` and `cve_ids` empty, the CVEs of
  `vulnerability.ids` fill them (the smallest CVE first, as
  `networkVACVEKey` already orders them); when `rule_id` is empty,
  `native.vuln_id` fills it, else the preferred non-CVE id (GHSA, OSV,
  vendor). A report that sets `cve_id` or `rule_id` keeps exactly the key it
  had, so no fingerprint stored before 1.4 changes
  (`TestInterop_IdentityUnchanged`).
- Cross-tool correlation therefore happens on the CVE (network and SCA
  recipes key on the canonical vulnerability id, so Nessus, Qualys and an
  agent that name the same CVE on the same host and port merge), on the
  version-less package URL (SCA recipe), and on the host identity: asset
  `identity_hints` count in asset matching like the same value under its
  usual property name. FQDN and NetBIOS name are host names, MACs and the
  cloud resource id are identifiers, and a typed `identifiers` block still
  wins ([asset identity resolution](asset-identity-resolution.md)). The OS CPE
  and agent id are kept in the asset property `identity_hints` for display.
- `native_vuln_id` and `vulnerability_ids` are stored for correlation queries;
  they are never used as a producer-chosen key.

## VEX

A sighting with `vex.status = not_affected` and a justification or statement
can close the matching finding. `INGEST_VEX` sets the mode:

| Mode | Effect |
|---|---|
| `dry_run` (default) | count, log and audit (`ingest.vex_dry_run`) what would close; no state change |
| `enforce` | the finding becomes `false_positive`, `resolution_method = 'vex_not_affected'`, `resolution` = the justification and the source of the statement; audited as `ingest.vex_applied` with the finding ids |
| `off` | statements are stored, nothing else |

Guards, the same as source-asserted resolve (RFC-047 §7.6): the report is bound
to a command assigned to the submitting sensor; the finding is the tenant's, on
the stated asset, under the stated key, open (`new`, `open`, `confirmed`,
`in_progress`, `fix_applied`) and not from a human source (pentest, manual, bug
bounty, red team). `accepted`, `false_positive` and `resolved` findings are
never touched. Other VEX statuses are stored for the detail view only. Applying
VEX documents uploaded by a user (CSAF, OpenVEX, CycloneDX VEX) is the importer
phase and reuses this path.

## Security

- Every value is producer-supplied (RFC-040). `vulnerability.SanitizeInteropData`
  bounds it before storage: text lengths, entry counts, known enums, finite
  scores in range per system, control characters removed, keys with control
  characters dropped, advisory links only `http(s)`. The column CHECK
  constraints are the backstop for any other writer.
- Only the finding detail reads the columns. Lists, exports, tickets and
  notifications work from `Finding` and cannot carry them. The web console
  renders the values as escaped text.
- Every read and write is scoped by `tenant_id`; the detail read happens after
  `GetFindingWithScope` has authorized the finding (tenant, data scope,
  pentest membership). `TestFindingInterop_DB` and `TestApplyVEXNotAffected_DB`
  check that another tenant's finding under the same fingerprint is neither
  written, read nor closed.
- A forged VEX statement from a hostile sensor needs `enforce` (an operator
  opt-in) and a command assigned to that sensor, and leaves an audit record
  listing every finding it closed.
