### Security: tenant reports no longer write text into the shared CVE catalog

- The first report naming a CVE used to create its shared catalog row with
  that report's title, description, CVSS, references, fixed versions and
  dates, and every organization read them through the CVE catalog. A report
  now creates only an identity stub (the CVE id); the CVE's content comes from
  the vulnerability feed's corpus, which fills the stub on its next import.
  The reporting organization keeps its scanner's text on its own findings.
- The CVE catalog API (`GET /api/v1/vulnerabilities`, `/{id}`,
  `/cve/{cveId}`, and the CVE lookup of `/cve/{cveId}/affected-assets`) shows
  a stub only to an organization whose findings link to it; for any other it
  answers 404, like an unknown CVE. Catalog responses no longer carry
  `created_at`/`updated_at`, and sorting by them sorts by `published_at` /
  `modified_at`.
- Migration 002934 (`catalog_report_stubs`) archives the report-written
  content of existing report-created rows, resets them to stubs and fills
  those the corpus already holds. No operator step; its down migration
  restores the archived content.
