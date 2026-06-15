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

`GET /api/v1/pentest/campaigns/{id}/report/download` (JWT, campaign membership)

| Query param | Values | Default |
|-------------|--------|---------|
| `format` | `html` \| `pdf` | `html` |
| `classification` | `public`/`internal`/`confidential`/`restricted` | `internal` |
| `watermark` | text (≤50 chars) | — |

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
