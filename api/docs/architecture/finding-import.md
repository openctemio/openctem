# Finding import: results exported by other tools

`POST /api/v1/findings/import` takes a file another security tool exported,
converts it to a CTIS 1.4 report with the ctis `importer` package, and ingests
it with the uploader's rights. VEX documents are applied to the tenant's
matching findings. The web console's **Findings → Import results** dialog
drives it.

Related: [finding-source-interop.md](finding-source-interop.md) (what a
finding keeps of its source, and `INGEST_VEX`), [deduplication.md](deduplication.md).

## Formats

The pinned ctis module decides which formats are read
(`importer.AllFormats()`; the response lists them as `supported_formats`):
Nessus v2 XML, Qualys host detection XML with an optional KnowledgeBase,
SARIF 2.1.0, trivy, grype, semgrep, gitleaks (and betterleaks), nuclei, ZAP
(JSON and XML), vuls, CycloneDX (SBOM, VDR, VEX), SPDX, osv-scanner results,
CSAF 2.0, OpenVEX and DefectDojo Generic Findings JSON. Each importer has a mapping spec, golden
fixtures and a field-coverage test in the ctis repository
(`docs/importers/`). The API never branches on the format: it calls
`importer.Detect`, `importer.Parse` and `importer.OpenZip` only, through one entry
point, `findingimport.Convert` (content sniffing, archive limits, KnowledgeBase
pairing), which any other caller that accepts exported files reuses.

## Request

Multipart form:

| Part / query | Meaning |
|---|---|
| `file` (up to 10) | An exported file or a ZIP of them |
| `knowledge_base` | The Qualys KnowledgeBase XML; it must come **before** `file`, because the parser needs it first |
| `?dry_run=true` | Preview: parse and count; nothing is written |
| `?format=` | Force the format of a single file |
| `?min_severity=` | Drop findings below `info`, `low`, `medium`, `high` or `critical` |

The format is read from the content (`importer.IsZip`, `importer.Detect` on
the first 64 KiB). The client's `Content-Type` and file name are never used
for anything but a label.

A ZIP is spooled to a private temporary file (removed after the request) and
listed with `importer.OpenZip`: at most 50 files, 100 MiB per file, 400 MiB in
all, a decompression ratio of 200, no path traversal, absolute paths, links,
encrypted entries or nested archives. A KnowledgeBase in the archive is paired
with the archive's Qualys detection files.

## Response

One entry per file: the detected format, the counts (records, assets,
findings by severity, components, VEX statements, skipped), the problems with
their line and column, the source fields the format's spec does not list
(up to 100), the VEX summary and, outside a preview, what ingest changed. A
single file that cannot be read is the request's error (400, or 413 over a
limit) with the same details; inside an archive each file reports its own
error.

## Rights and isolation

- Gate: `findings:write`, `assets:write` and `assets:import`. Rate limited
  **per organization** (6 per minute, burst 3), not per client address. Body
  limit 110 MiB; 10 minutes per request.
- The report is ingested through
  `ingest.Service` with the uploader's data scope as `Options.Actor`, so a
  restricted uploader only adds findings to existing assets in their scope
  and creates none. Coverage is always **partial**: an import never
  auto-resolves anything, whatever the file says.
- The tenant comes from the authenticated request, never from the file.

## VEX documents

A statement names vulnerabilities and products, not assets. Each statement is
matched against the tenant's findings:

- the vulnerability: one of its ids is the finding's CVE, one of its CVEs,
  its rule id or one of its typed vulnerability ids;
- the product: the package URL of the finding's component, version-less when
  the statement gives no version. Statements whose products have no package
  URL (CPE-only, name-only) are counted as `unmatchable`;
- a product with **subcomponents** (an OpenVEX subcomponent, a CSAF
  relationship) is a statement about those components inside that product
  only: the subcomponents are matched only on findings whose asset is named
  like the product (its name, name:version, package URL, or an OCI image's
  `repository_url`). A product that cannot be identified makes the statement
  unmatchable; it is never applied product-wide;
- the candidates are filtered by the uploader's data scope.

Then, outside a preview, the statement is stored on every matched finding
(the `vex_*` columns of migration 001105). A `not_affected` statement closes
a finding (`false_positive`, `resolution_method = vex_not_affected`, the
justification and source as the resolution) only when all of these hold:

- `INGEST_VEX=enforce`;
- the uploader holds `findings:approve` (the permission a false positive
  needs everywhere else);
- the finding is open and not from a human source (pentest, manual, bug
  bounty, red team).

Otherwise the findings it would close are counted (`would_close`). One
statement touches at most 5,000 findings.

## Producer record

Every committed file gets a row in `finding_imports` (migration 001142)
before anything is written: tenant, uploader (`actor_user_id`), format, the
SHA-256 of the file name (the name itself is only in the audit log) and,
when the file is done, the counts (assets and findings created and updated,
components, VEX statements, skipped, VEX stored and closed). A preview
writes none. The record's id is:

- the report id of the ingest, so the findings the import created or updated
  carry it as `scan_id`, as a scan's findings carry the scan;
- stamped on the assets the import created or updated, within the uploader's
  scope, as `assets.import_id` (the last import that wrote the asset);
- returned per file as `import_id` and listed in the audit records.

So everything one import produced can be found (and purged) by its id. The
record is read by `(tenant_id, id)` only.

## Audit

Every import and every preview is recorded as `asset.imported` with
`source = finding_import`: file names (labels only), formats, counts, VEX
counts and whether the uploader was restricted. File content is never
logged. A VEX document that closed findings, or would have, adds an
`ingest.vex_applied` or `ingest.vex_dry_run` record listing up to 100 of the
finding ids.

## Threat model

| Threat | Control |
|---|---|
| XXE, entity expansion, external DTD fetch | ctis importer: no internal subset or entity declaration, predefined entities only, external identifiers never read |
| Huge or deeply nested files, many records | body limit; importer limits (100 MiB per file, depth, elements, text, 100,000 findings and assets, 200,000 components, 20,000 statements) |
| ZIP bombs, path traversal, links, nested archives | `importer.OpenZip` limits and refusals; entries are never written under their own names |
| Malformed encodings | UTF-8, US-ASCII and ISO-8859-1 only; invalid UTF-8 refused with its line |
| Cross-tenant write | tenant from the request; every query `tenant_id = $1` first; `TestFindingVEXDocument_DB`, `TestFindingImport_VEXDocument_DB` |
| Out-of-scope write by a restricted member | ingest `Actor`; VEX candidates filtered by the data scope |
| Forged VEX closing findings | operator opt-in (`enforce`) plus `findings:approve`; human-source findings never closed; audited with ids |
| Abuse of the parser | per-organization rate limit; request timeout |
| Credentials or account names in reports | the importers skip the Nessus scan policy and login accounts and redact credentials in scanner output |
