// Package report provides HTML report generation for pentest campaigns.
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// FindingData represents a finding for report rendering.
type FindingData struct {
	Number      string
	Title       string
	Severity    string
	Status      string
	CVSSScore   float64
	CVSSVector  string
	CWE         string
	CVE         string
	OWASP       string
	Description string
	Steps       []string
	POC         string
	Impact      string
	TechImpact  string
	Remediation string
	References  []string
	Targets     []string
	AssignedTo  string
	CreatedAt   time.Time
}

// CampaignData represents campaign data for report rendering.
type CampaignData struct {
	Name          string
	Description   string
	ClientName    string
	ClientContact string
	Type          string
	Priority      string
	Status        string
	StartDate     string
	EndDate       string
	Methodology   string
	Team          []TeamMemberData
}

// TeamMemberData represents a team member for report rendering.
type TeamMemberData struct {
	Name  string
	Email string
	Role  string
}

// StatsData represents campaign statistics for report rendering.
type StatsData struct {
	Total    int64
	Critical int64
	High     int64
	Medium   int64
	Low      int64
	Info     int64
	Progress float64
	AvgCVSS  float64
	MaxCVSS  float64
}

// ReportInput contains all data needed to generate a report.
type ReportInput struct {
	Campaign        CampaignData
	Findings        []FindingData
	Stats           StatsData
	GeneratedAt     time.Time
	Classification  string
	Watermark       string
	ReportType      string
	IncludePOC      bool
	IncludeEvidence bool
}

// GenerateHTML renders a pentest report as an HTML document.
func GenerateHTML(input ReportInput) (string, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityColor": severityColor,
		"upper":         strings.ToUpper,
		"formatDate": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("2006-01-02")
		},
		"add": func(a, b int) int { return a + b },
	}).Parse(reportTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse report template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, input); err != nil {
		return "", fmt.Errorf("failed to execute report template: %w", err)
	}

	return buf.String(), nil
}

func severityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "#dc2626"
	case "high":
		return "#ea580c"
	case "medium":
		return "#ca8a04"
	case "low":
		return "#2563eb"
	case "info":
		return "#6b7280"
	default:
		return "#6b7280"
	}
}

const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Campaign.Name}} - Penetration Test Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a2e; line-height: 1.6; background: #fff; }
  .container { max-width: 900px; margin: 0 auto; padding: 40px; }
  h1 { font-size: 28px; margin-bottom: 8px; color: #1a1a2e; }
  h2 { font-size: 22px; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; color: #1a1a2e; }
  h3 { font-size: 16px; margin: 16px 0 8px; color: #374151; }
  p { margin-bottom: 8px; }
  .header { text-align: center; padding: 40px 0; border-bottom: 3px solid #1a1a2e; margin-bottom: 32px; }
  .header .subtitle { color: #6b7280; font-size: 14px; }
  .classification { display: inline-block; padding: 4px 12px; background: #fee2e2; color: #dc2626; font-weight: 600; font-size: 12px; text-transform: uppercase; border-radius: 4px; margin-top: 12px; }
  .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 16px 0; }
  .meta-item { padding: 12px; background: #f9fafb; border-radius: 8px; border: 1px solid #e5e7eb; }
  .meta-label { font-size: 11px; text-transform: uppercase; color: #6b7280; font-weight: 600; letter-spacing: 0.5px; }
  .meta-value { font-size: 14px; font-weight: 500; margin-top: 2px; }
  .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 16px 0; }
  .stat-box { text-align: center; padding: 16px 8px; border-radius: 8px; border: 1px solid #e5e7eb; }
  .stat-box .count { font-size: 28px; font-weight: 700; }
  .stat-box .label { font-size: 11px; text-transform: uppercase; color: #6b7280; font-weight: 600; }
  .severity-critical { background: #fef2f2; color: #dc2626; }
  .severity-high { background: #fff7ed; color: #ea580c; }
  .severity-medium { background: #fefce8; color: #ca8a04; }
  .severity-low { background: #eff6ff; color: #2563eb; }
  .severity-info { background: #f9fafb; color: #6b7280; }
  .finding { margin: 24px 0; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; page-break-inside: avoid; }
  .finding-header { padding: 12px 16px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid #e5e7eb; }
  .finding-header .number { font-weight: 700; font-size: 13px; color: #6b7280; }
  .finding-header .title { flex: 1; font-weight: 600; font-size: 15px; }
  .severity-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; color: #fff; }
  .finding-body { padding: 16px; }
  .finding-body .section { margin-bottom: 12px; }
  .finding-body .section-title { font-size: 12px; text-transform: uppercase; color: #6b7280; font-weight: 600; margin-bottom: 4px; }
  .finding-body pre { background: #f9fafb; padding: 12px; border-radius: 6px; font-size: 13px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
  .finding-body ol, .finding-body ul { padding-left: 20px; margin: 4px 0; }
  .finding-body li { margin: 2px 0; font-size: 14px; }
  .team-table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  .team-table th, .team-table td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; font-size: 14px; }
  .team-table th { background: #f9fafb; font-weight: 600; font-size: 12px; text-transform: uppercase; color: #6b7280; }
  .footer { text-align: center; margin-top: 48px; padding-top: 16px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 12px; }
  .progress-bar { width: 100%; height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; margin: 8px 0; }
  .progress-fill { height: 100%; background: #22c55e; border-radius: 4px; }
  @media print { body { padding: 0; } .container { padding: 20px; } }
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <h1>{{.Campaign.Name}}</h1>
    <p class="subtitle">Penetration Test Report</p>
    <p class="subtitle">{{.Campaign.ClientName}}{{if .Campaign.ClientContact}} &mdash; {{.Campaign.ClientContact}}{{end}}</p>
    <p class="subtitle">Generated: {{formatDate .GeneratedAt}}</p>
    {{if .Classification}}<span class="classification">{{upper .Classification}}</span>{{end}}
  </div>

  <!-- Executive Summary -->
  <h2>1. Executive Summary</h2>
  {{if .Campaign.Description}}<p>{{.Campaign.Description}}</p>{{end}}

  <div class="meta-grid">
    <div class="meta-item"><div class="meta-label">Campaign Type</div><div class="meta-value">{{.Campaign.Type}}</div></div>
    <div class="meta-item"><div class="meta-label">Priority</div><div class="meta-value">{{.Campaign.Priority}}</div></div>
    <div class="meta-item"><div class="meta-label">Testing Period</div><div class="meta-value">{{.Campaign.StartDate}} &mdash; {{.Campaign.EndDate}}</div></div>
    <div class="meta-item"><div class="meta-label">Methodology</div><div class="meta-value">{{if .Campaign.Methodology}}{{.Campaign.Methodology}}{{else}}-{{end}}</div></div>
  </div>

  <!-- Statistics -->
  <h2>2. Findings Overview</h2>
  <p>A total of <strong>{{.Stats.Total}}</strong> vulnerabilities were identified during this engagement.</p>

  <div class="stats-grid">
    <div class="stat-box severity-critical"><div class="count">{{.Stats.Critical}}</div><div class="label">Critical</div></div>
    <div class="stat-box severity-high"><div class="count">{{.Stats.High}}</div><div class="label">High</div></div>
    <div class="stat-box severity-medium"><div class="count">{{.Stats.Medium}}</div><div class="label">Medium</div></div>
    <div class="stat-box severity-low"><div class="count">{{.Stats.Low}}</div><div class="label">Low</div></div>
    <div class="stat-box severity-info"><div class="count">{{.Stats.Info}}</div><div class="label">Info</div></div>
  </div>

  {{if gt .Stats.AvgCVSS 0.0}}
  <p>Average CVSS Score: <strong>{{printf "%.1f" .Stats.AvgCVSS}}</strong> | Maximum: <strong>{{printf "%.1f" .Stats.MaxCVSS}}</strong></p>
  {{end}}

  <div>
    <p style="font-size:13px;color:#6b7280;">Resolution Progress: {{printf "%.0f" .Stats.Progress}}%</p>
    <div class="progress-bar"><div class="progress-fill" style="width:{{printf "%.0f" .Stats.Progress}}%"></div></div>
  </div>

  <!-- Team -->
  {{if .Campaign.Team}}
  <h2>3. Testing Team</h2>
  <table class="team-table">
    <thead><tr><th>Name</th><th>Email</th><th>Role</th></tr></thead>
    <tbody>
    {{range .Campaign.Team}}
    <tr><td>{{.Name}}</td><td>{{.Email}}</td><td>{{.Role}}</td></tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <!-- Findings -->
  <h2>{{if .Campaign.Team}}4{{else}}3{{end}}. Detailed Findings</h2>

  {{range $i, $f := .Findings}}
  <div class="finding">
    <div class="finding-header">
      <span class="number">{{if $f.Number}}{{$f.Number}}{{else}}#{{add $i 1}}{{end}}</span>
      <span class="title">{{$f.Title}}</span>
      <span class="severity-badge" style="background-color:{{severityColor $f.Severity}}">{{upper $f.Severity}}</span>
    </div>
    <div class="finding-body">
      {{if $f.CVSSScore}}<div class="section"><span class="section-title">CVSS</span> {{printf "%.1f" $f.CVSSScore}}{{if $f.CVSSVector}} ({{$f.CVSSVector}}){{end}}</div>{{end}}
      {{if $f.CWE}}<div class="section"><span class="section-title">CWE</span> {{$f.CWE}}</div>{{end}}
      {{if $f.CVE}}<div class="section"><span class="section-title">CVE</span> {{$f.CVE}}</div>{{end}}
      {{if $f.OWASP}}<div class="section"><span class="section-title">OWASP</span> {{$f.OWASP}}</div>{{end}}

      {{if $f.Description}}
      <div class="section"><div class="section-title">Description</div><p>{{$f.Description}}</p></div>
      {{end}}

      {{if $f.Targets}}
      <div class="section"><div class="section-title">Affected Targets</div><ul>{{range $f.Targets}}<li>{{.}}</li>{{end}}</ul></div>
      {{end}}

      {{if $f.Steps}}
      <div class="section"><div class="section-title">Steps to Reproduce</div><ol>{{range $f.Steps}}<li>{{.}}</li>{{end}}</ol></div>
      {{end}}

      {{if $f.POC}}
      <div class="section"><div class="section-title">Proof of Concept</div><pre>{{$f.POC}}</pre></div>
      {{end}}

      {{if $f.Impact}}
      <div class="section"><div class="section-title">Business Impact</div><p>{{$f.Impact}}</p></div>
      {{end}}

      {{if $f.TechImpact}}
      <div class="section"><div class="section-title">Technical Impact</div><p>{{$f.TechImpact}}</p></div>
      {{end}}

      {{if $f.Remediation}}
      <div class="section"><div class="section-title">Remediation</div><p>{{$f.Remediation}}</p></div>
      {{end}}

      {{if $f.References}}
      <div class="section"><div class="section-title">References</div><ul>{{range $f.References}}<li>{{.}}</li>{{end}}</ul></div>
      {{end}}
    </div>
  </div>
  {{end}}

  {{if eq (len .Findings) 0}}
  <p style="color:#6b7280;">No findings to display.</p>
  {{end}}

  <!-- Footer -->
  <div class="footer">
    <p>This report was generated by OpenCTEM Platform on {{formatDate .GeneratedAt}}</p>
    {{if .Watermark}}<p style="font-size:18px;font-weight:700;color:#e5e7eb;margin-top:8px;">{{upper .Watermark}}</p>{{end}}
  </div>
</div>
</body>
</html>`
