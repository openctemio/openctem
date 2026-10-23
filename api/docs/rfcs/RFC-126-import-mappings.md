# RFC-126: Import mappings

| | |
|---|---|
| Status | Accepted (2026-10-23). API shipped with this RFC; the web editor follows in its own pull request ([import-mappings.md](../architecture/import-mappings.md) says what is shipped) |
| Scope | api (`pkg/domain/importmapping`, `internal/app/importmapping`, `internal/app/findingimport`, findings import and CI upload routes, migration `003360_import_mappings`), web (settings, mapping editor), ctis (`importer/mapping` CSV and XML inputs, identity), openctem-ci (`upload --format mapping:<name>`) |
| Architecture | [import-mappings.md](../architecture/import-mappings.md), [finding-import.md](../architecture/finding-import.md) |
| Related | RFC-043 (deduplication and identity), RFC-051 (CI runs), RFC-055 (tool contract and declarative mappings), RFC-122 (receipts) |

## 1. Summary

Organizations hold findings in exports that no importer reads: a legacy
vulnerability-management tool's CSV, a spreadsheet kept by hand, an in-house
scanner's JSON, a check runner's JUnit XML. An **import mapping** turns any
such CSV, JSON, JSON Lines or XML file into CTIS with no code. It is a
document in the CTIS mapping language (`openctem.io/mapping/v1`, ctis
`docs/mapping.md`). The organization writes it in the console on a sample,
sees the result and each finding's identity before saving, and keeps it in
immutable versions. An import names the mapping in its format,
`format=mapping:<name>[@<version>]`, on the same upload path every other
format uses.

## 2. Decisions

| ID | Decision |
|---|---|
| D1 | The mapping runs as data. It uses the closed CTIS mapping language: predicates and transforms from a fixed list, no expressions, loops, code, file or network access, linear cost. CSV and XML inputs are added to that language in ctis, so sensors' custom tools get them too. |
| D2 | Versions are immutable and numbered. An import names a version, or takes the latest. The receipt's format is `mapping:<name>@<n>`, so every finding's import is traceable to the exact document. |
| D3 | A mapping that makes findings declares its **identity**: 1 to 8 finding members from the members the server's identity recipes read (RFC-043). A constant identity, or a constant fingerprint, is refused at save, because it would make every finding of a rule one finding. So is a near-constant identity member: one with a default (every record without the value would share it) or a map with a single output. The server still decides identity from the CTIS members; the mapping never sets a fingerprint. |
| D4 | A new version that changes the identity is never saved silently. A change counts when it alters the identity list, or how an identity member, the finding's asset or any member the server keys findings on (type, rule, title, location, network port and protocol, CVE, package, ecosystem, misconfiguration policy and resource) is mapped, or adds or removes the misconfiguration or network block that picks the identity recipe; the declared identity does not have to name them. The save answers 409 `identity_change_unconfirmed` until the caller confirms. The version is then marked `identity_changed`. Findings imported with earlier versions keep their keys. New imports key apart from them, the receipt shows them as created, and an operator re-keys stored findings with the refingerprint tool when the recipe allows it. |
| D5 | Reserved members: a mapping sets only members on an allow-list (finding description, location, network, vulnerability, misconfiguration and remediation members; asset type, value, name, description, tags). Everything else is reserved. That covers the organization, asset ownership, criticality, exposure and identity hints, statuses, baseline state, provenance (`source_extra`), fingerprints, KEV and EPSS flags, branch and commit. Only finding and asset rules are accepted. A finding's type is `vulnerability` or `misconfiguration`, for every value the type spec can produce (a map decides the output even of a constant, and a default is checked too): a secret's identity needs the producer's keyed hash, which a mapped file cannot carry. |
| D6 | An import through a mapping is always partial coverage. It never closes a finding, and `coverage=full` is refused with it. The tool is `mapped:<name>` and the asset source is `mapped:<name>`, never a name taken from the file. |
| D7 | Preview: a sample of at most 5 MiB is mapped and nothing is stored. The answer has at most 50 CTIS records, each finding's identity key, warnings, issues, the sample's fields and the unmapped ones. The identity key is the key ingest would compute, on a stand-in asset per asset type and value. The warnings are `identity_collision`, `no_records`, `unmapped_fields` and `truncated`. Preview is rate-limited per organization (20 per minute, burst 5). |
| D8 | Permissions: reading mappings needs `integrations:read` or `assets:import`, because an uploader picks one. Writing, validating and previewing need `integrations:manage`, and deleting also needs step-up. Every write is audited (`import_mapping.*`). Importing keeps the import route's own permissions. No new permission. |
| D9 | Starter templates are built in: generic findings CSV, generic findings JSON, and JUnit-style XML. They are the ctis samples, checked by the same goldens. |
| D10 | CI: `POST /ci/runs/{id}/results?format=mapping:<name>[@<version>]` resolves the mapping in the run's organization (from its token). The run's repository is the asset of every record that names none, and the usual run scoping applies. `openctem-ci upload --format mapping:<name>` sends it. The upload is applied by the ingest worker with the version pinned at accept; if that version is gone when the worker runs, the upload fails with `mapping_unavailable`. |

## 3. Threat model

| Threat | Control | Test |
|---|---|---|
| Cross-organization read or use of a mapping | Every query carries `tenant_id`. The version table's foreign key is `(tenant_id, mapping_id)`. Another organization's mapping, by id or by name, is 404 on every route and `unknown_mapping` on import. Names are unique per organization only. | `TestTenantIsolation`, `TestImportMappings_DB`, `TestCIUpload_MappingFormat` |
| A mapping that forges trusted fields (owner, criticality, status, provenance, fingerprint) | allow-list of targets (D5), re-checked when a stored version is resolved | `TestCompilePolicy` |
| Identity collapse (constant identity, identity on a member the server ignores) | refused at save (D3), collisions warned in preview | `TestIdentity` (ctis), `TestCompilePolicy`, `TestPreview` |
| Silent re-keying | 409 until confirmed, `identity_changed` stored and audited (D4) | `TestCreateVersionsAndIdentityConfirm` |
| Hostile sample or upload: XXE, billion laughs, deep nesting, huge CSV, unterminated quotes, UTF-16 | ctis reader: no DTD of any kind, depth, element, text, cell, row, column and input caps. Platform: 5 MiB sample, upload limits, 10 s preview timeout, rate limit. | ctis `TestXMLHostile` and `TestCSVHostile`, `TestPreview` |
| CSV formula injection | cells stay text; every CSV export runs `sanitizeCSVCell` | ctis `formula cells stay text`, the findings export tests |
| SSRF or file read | the language has no I/O; the XML reader never resolves an external identifier | — |
| Resource abuse | 200 mappings per organization, 500 versions per mapping, 256 KiB document, body limits, preview rate limit | — |

## 4. API

Base `/api/v1/import-mappings`: `GET /`, `POST /`, `GET /templates`,
`POST /verify` (validate a document), `POST /preview` (multipart: `mapping` or `mapping_id` +
`version`, then `file`), `GET /{id}`, `PATCH /{id}`, `DELETE /{id}`,
`POST /{id}/versions`, `GET /{id}/versions/{version_id}`. The OpenAPI spec is
generated from the handlers.

## 5. Not in scope

- A mapping over a ZIP of several files (one file per import).
- Dependency rules (components) through tenant mappings.
- Status mapping from a legacy tool's state column: findings arrive open.
  Statuses stay with the platform's own workflow.
