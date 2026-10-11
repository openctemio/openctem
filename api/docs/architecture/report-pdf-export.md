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

## Markdown and evidence images

Finding fields are written in Markdown (description, impacts, remediation,
steps, campaign description). The HTML and PDF reports render it through
`pkg/report/markdown`: paragraphs, headings, lists, quotes, code blocks,
bold, italic, code and links. Every text is escaped, raw HTML stays text, and
links are kept only for http(s) and mailto.

Screenshots referenced as `![alt](/api/v1/attachments/{id})` are embedded
(data URI in HTML, image in PDF) when the attachment is evidence of that
finding, of its retests or of the campaign, in the same tenant; when it is
PNG, JPEG or GIF and decodes as one; and within 5 MiB per image, 40 MiB and
200 images per report. Anything else renders as its alt text in brackets: a
report never fetches a URL. `include_evidence=false` leaves images out.
