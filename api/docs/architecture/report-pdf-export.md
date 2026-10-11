# Report PDF Export

> Server-side PDF generation for pentest reports, rendered **directly from the
> structured report data** with a pure-Go library — no headless browser, no
> external rendering service, no system dependency.

## Why pure-Go (not HTML→PDF)

Converting the existing HTML report to PDF would require a headless browser
(chromedp/wkhtmltopdf) bundled in the API image, or an external render service.
Instead, the PDF is built from the same `report.ReportInput` the HTML generator
consumes, using `github.com/go-pdf/fpdf` (BSD-3, pure Go, no cgo). Same data,
two renderers.

```
PentestService.buildReportInput(...)  ──►  report.ReportInput
                                              ├─► report.GenerateHTML(input)  → HTML
                                              └─► report.GeneratePDF(input)   → PDF (fpdf)
```

## Endpoint

`GET /api/v1/pentest/campaigns/{id}/reports/download` (JWT, campaign membership)

| Query param | Values | Default |
|-------------|--------|---------|
| `format` | `html` \| `pdf` | `html` |
| `classification` | `public`/`internal`/`confidential`/`restricted` | `internal` |
| `watermark` | text (≤50 chars) | — |
| `report_type` | `executive_summary` \| `technical_report` \| `finding_report` \| `compliance_report` \| `remediation_report` \| `retest_report` | `technical_report` |
| `include_poc` | `true` \| `false` | `true` |
| `include_unpublished` | `true` \| `false` | `false` |
| `statuses` | comma list of finding statuses | published statuses |
| `severities` | comma list of severities | all |

## What a report contains

The same options are stored on a report created with
`POST /api/v1/pentest/campaigns/{id}/reports` (`options` object, same keys)
and apply when it is downloaded.

- **Published findings only by default.** `draft`, `in_review`,
  `false_positive` and `duplicate` findings are left out: drafts and findings
  under peer review are not results yet, false positives and duplicates are
  not findings of the target. `include_unpublished=true` includes every
  status; `statuses` lists exactly which statuses to include.
- `severities` keeps only those severities. Unknown statuses or severities are
  refused (400), so a typo never produces a silently different report.
- Findings are ordered most severe first, then by CVSS score, then oldest
  first. The summary counts describe the findings in the report, never the
  campaign's unpublished ones.
- `include_poc=false` leaves proofs of concept out (for client-facing copies).
- Retest results are listed only for findings the report includes.
- A campaign above 2,000 findings is refused; narrow by severity or status.

`format=pdf` returns `application/pdf` (`Content-Disposition: attachment;
filename="pentest-report.pdf"`). The classification and watermark render in the
footer of every page.

## Layout

`pkg/report/pdf.go` renders: title block, engagement details, team, severity
summary (coloured badges + progress/CVSS), and a section per finding (severity
badge, title, CVSS/CWE/CVE/OWASP meta, description, numbered repro steps,
business/technical impact, remediation, PoC when `include_poc`, targets,
references). Pagination is automatic (`SetAutoPageBreak`).

Text is mapped to the core-font cp1252 charset via fpdf's unicode translator —
characters outside it are dropped rather than mojibake'd. Embedding a Unicode
TTF for full multilingual coverage is a future enhancement.

## Code map

| Piece | Where |
|-------|-------|
| PDF renderer | `pkg/report/pdf.go` (`GeneratePDF`) |
| Data builder (shared HTML/PDF) | `internal/app/compliance/pentest.go` (`buildReportInput`) |
| Service method | `PentestService.GenerateReportPDF` |
| Handler format switch | `internal/infra/http/handler/pentest_handler.go` (`DownloadReport`) |

## Stored reports and delivery

A report created with `POST /api/v1/pentest/campaigns/{id}/reports` is
generated once and its bytes are stored (`pentest_report_files`, in the
tenant's rows, at most 50 MiB, erased with the report and the tenant).
`GET /api/v1/pentest/reports/{id}/download` returns those bytes, so a report
never changes when the campaign does; the report carries their SHA-256.
Reports created before reports were stored answer 409 (generate a new one).
The live download (`/campaigns/{id}/reports/download`) still renders current
data and stores nothing.

The campaign lead marks a stored report delivered
(`POST /api/v1/pentest/reports/{id}/deliver`, audited
`pentest_report.delivered`); a delivered report cannot be deleted.
