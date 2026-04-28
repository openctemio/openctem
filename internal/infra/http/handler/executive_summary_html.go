package handler

import (
	"html/template"
	"io"

	"github.com/openctemio/api/internal/app"
)

// Print-ready HTML export of the executive summary.
//
// Shipped as HTML rather than server-generated PDF for two reasons:
//
//   - No new heavy dependency (headless Chrome / wkhtmltopdf / gofpdf)
//     — the browser already knows how to render HTML to PDF, and
//     tenants keep their own branding by styling the downloaded file.
//   - Consistent with the existing CSV / JSON exports that leave
//     rendering to the client.
//
// The @media print block sets page breaks + hides navigation chrome
// so the output looks like a report rather than a web page when
// saved as PDF via Ctrl-P → Save as PDF.

// execSummaryFuncs — the helper functions the template needs. Must
// be registered on the template BEFORE Parse or Go html/template
// complains about "function not defined" at parse time.
var execSummaryFuncs = template.FuncMap{
	"add":   func(a, b int) int { return a + b },
	"lower": lowerASCII,
	"deref": func(p *float64) float64 {
		if p == nil {
			return 0
		}
		return *p
	},
}

//nolint:gochecknoglobals // template is constant; parsed once at package init
var executiveSummaryTemplate = template.Must(
	template.New("exec-summary").Funcs(execSummaryFuncs).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Executive Summary — {{.Period}}</title>
  <style>
    :root {
      --ink: #111827;
      --muted: #6b7280;
      --rule: #e5e7eb;
      --accent: #1d4ed8;
      --danger: #dc2626;
      --ok: #059669;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: var(--ink);
      margin: 2rem auto;
      max-width: 960px;
      line-height: 1.5;
    }
    h1 { margin: 0 0 .25rem; font-size: 1.75rem; }
    h2 { margin: 2rem 0 .75rem; font-size: 1.125rem; border-bottom: 1px solid var(--rule); padding-bottom: .25rem; }
    .meta { color: var(--muted); margin-bottom: 2rem; font-size: .9rem; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem 1.5rem; }
    .card { border: 1px solid var(--rule); border-radius: 8px; padding: 1rem 1.25rem; background: #fafafa; }
    .card .label { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
    .card .value { font-size: 1.5rem; font-weight: 600; margin-top: .25rem; }
    .card .delta { font-size: .85rem; color: var(--muted); margin-top: .25rem; }
    .card.up .value { color: var(--danger); }
    .card.down .value { color: var(--ok); }
    table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
    th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid var(--rule); font-size: .9rem; }
    th { font-weight: 600; color: var(--muted); text-transform: uppercase; font-size: .75rem; letter-spacing: .04em; }
    .sev-critical { color: var(--danger); font-weight: 600; }
    .sev-high { color: #ea580c; font-weight: 600; }
    .sev-medium { color: #ca8a04; }
    .sev-low { color: var(--muted); }
    .badge { display: inline-block; padding: .1rem .4rem; border-radius: 4px; font-size: .75rem; background: var(--rule); }
    .badge.kev { background: #fee2e2; color: var(--danger); }
    footer { margin-top: 3rem; color: var(--muted); font-size: .8rem; border-top: 1px solid var(--rule); padding-top: 1rem; }
    @media print {
      body { margin: 0; padding: 1cm; max-width: none; }
      h2 { page-break-after: avoid; }
      .card { break-inside: avoid; }
      tr { break-inside: avoid; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Executive Summary</h1>
    <div class="meta">Period: {{.Period}} &middot; Generated: {{.GeneratedAt}}</div>
  </header>

  <h2>Headline Metrics</h2>
  <div class="grid">
    <div class="card {{if gt .Summary.RiskScoreChange 0.0}}up{{else}}down{{end}}">
      <div class="label">Risk Score (current)</div>
      <div class="value">{{printf "%.1f" .Summary.RiskScoreCurrent}}</div>
      <div class="delta">Δ {{printf "%+.1f" .Summary.RiskScoreChange}} vs previous period</div>
    </div>
    <div class="card">
      <div class="label">Findings (total)</div>
      <div class="value">{{.Summary.FindingsTotal}}</div>
      <div class="delta">{{.Summary.FindingsNew}} new &middot; {{.Summary.FindingsResolved}} resolved in period</div>
    </div>
    <div class="card">
      <div class="label">SLA Compliance</div>
      <div class="value">{{printf "%.1f%%" .Summary.SLACompliancePct}}</div>
      <div class="delta">{{.Summary.SLABreached}} breached in period</div>
    </div>
    <div class="card">
      <div class="label">P0 Open</div>
      <div class="value">{{.Summary.P0Open}}</div>
      <div class="delta">{{.Summary.P0Resolved}} resolved in period</div>
    </div>
    <div class="card">
      <div class="label">P1 Open</div>
      <div class="value">{{.Summary.P1Open}}</div>
      <div class="delta">{{.Summary.P1Resolved}} resolved in period</div>
    </div>
    <div class="card">
      <div class="label">Crown Jewels at Risk</div>
      <div class="value">{{.Summary.CrownJewelsAtRisk}}</div>
      <div class="delta">assets flagged as high-value &amp; exposed</div>
    </div>
    <div class="card">
      <div class="label">MTTR Critical</div>
      <div class="value">{{printf "%.1fh" .Summary.MTTRCriticalHrs}}</div>
      <div class="delta">mean time to remediate</div>
    </div>
    <div class="card">
      <div class="label">MTTR High</div>
      <div class="value">{{printf "%.1fh" .Summary.MTTRHighHrs}}</div>
      <div class="delta">mean time to remediate</div>
    </div>
    <div class="card">
      <div class="label">Regression Rate</div>
      <div class="value">{{printf "%.1f%%" .Summary.RegressionRatePct}}</div>
      <div class="delta">{{.Summary.RegressionCount}} regressions recorded</div>
    </div>
  </div>

  {{if .Summary.TopRisks}}
  <h2>Top Risks</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Title</th>
        <th>Priority</th>
        <th>Severity</th>
        <th>Asset</th>
        <th>EPSS</th>
        <th>KEV</th>
      </tr>
    </thead>
    <tbody>
    {{range $i, $r := .Summary.TopRisks}}
      <tr>
        <td>{{add $i 1}}</td>
        <td>{{$r.FindingTitle}}</td>
        <td><span class="badge">{{$r.PriorityClass}}</span></td>
        <td class="sev-{{lower $r.Severity}}">{{$r.Severity}}</td>
        <td>{{$r.AssetName}}</td>
        <td>{{if $r.EPSSScore}}{{printf "%.2f" (deref $r.EPSSScore)}}{{else}}—{{end}}</td>
        <td>{{if $r.IsInKEV}}<span class="badge kev">YES</span>{{else}}—{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <footer>
    OpenCTEM · This report is generated from tenant data. Save as PDF with your browser's Print dialog.
  </footer>
</body>
</html>`),
)

// renderExecutiveSummaryHTML writes the print-ready HTML report.
// The writer is flushed by the caller (ResponseWriter) — this function
// does not buffer.
func renderExecutiveSummaryHTML(w io.Writer, summary *app.ExecutiveSummary, generatedAt string) error {
	data := struct {
		Period      string
		GeneratedAt string
		Summary     *app.ExecutiveSummary
	}{
		Period:      summary.Period,
		GeneratedAt: generatedAt,
		Summary:     summary,
	}
	return executiveSummaryTemplate.Execute(w, data)
}

// lowerASCII lowercases an ASCII string. Used by the template to
// compute severity CSS class names without pulling in the strings
// package inside the template FuncMap (kept simple on purpose).
func lowerASCII(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
