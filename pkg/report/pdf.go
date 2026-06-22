package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// translator maps UTF-8 text to the cp1252 charset of the core PDF fonts.
type translator func(string) string

// GeneratePDF renders a pentest report as a PDF directly from the structured
// report data — pure Go, no headless browser. The layout mirrors the sections
// of the HTML report (engagement details, team, summary, findings).
func GeneratePDF(input ReportInput) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 18)
	tr := translator(pdf.UnicodeTranslatorFromDescriptor("")) // cp1252

	classification := strings.ToUpper(strings.TrimSpace(input.Classification))
	if classification == "" {
		classification = "INTERNAL"
	}

	// Footer: classification + optional watermark + page number on every page.
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(140, 140, 140)
		foot := classification
		if strings.TrimSpace(input.Watermark) != "" {
			foot += "  -  " + input.Watermark
		}
		pdf.CellFormat(0, 6, tr(foot), "", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "R", false, 0, "")
	})

	pdf.AddPage()

	// Title block.
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(20, 20, 20)
	pdf.MultiCell(0, 10, tr("Penetration Test Report"), "", "L", false)
	if input.Campaign.Name != "" {
		pdf.SetFont("Helvetica", "B", 14)
		pdf.SetTextColor(70, 70, 70)
		pdf.MultiCell(0, 8, tr(input.Campaign.Name), "", "L", false)
	}
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(120, 120, 120)
	pdf.CellFormat(0, 6, tr(fmt.Sprintf("Classification: %s     Generated: %s",
		classification, input.GeneratedAt.Format("2006-01-02 15:04 MST"))), "", 1, "L", false, 0, "")
	pdf.Ln(4)

	// Engagement details.
	sectionHeading(pdf, tr, "Engagement Details")
	for _, row := range [][2]string{
		{"Client", input.Campaign.ClientName},
		{"Contact", input.Campaign.ClientContact},
		{"Type", input.Campaign.Type},
		{"Priority", input.Campaign.Priority},
		{"Status", input.Campaign.Status},
		{"Start date", input.Campaign.StartDate},
		{"End date", input.Campaign.EndDate},
		{"Methodology", input.Campaign.Methodology},
	} {
		if strings.TrimSpace(row[1]) != "" {
			kvRow(pdf, tr, row[0], row[1])
		}
	}
	if strings.TrimSpace(input.Campaign.Description) != "" {
		pdf.Ln(2)
		bodyText(pdf, tr, input.Campaign.Description)
	}

	// Team.
	if len(input.Campaign.Team) > 0 {
		pdf.Ln(3)
		sectionHeading(pdf, tr, "Team")
		for _, m := range input.Campaign.Team {
			line := m.Name
			if m.Role != "" {
				line += " (" + m.Role + ")"
			}
			if m.Email != "" {
				line += " - " + m.Email
			}
			bulletLine(pdf, tr, line)
		}
	}

	// Summary stats.
	pdf.Ln(3)
	sectionHeading(pdf, tr, "Summary")
	statsTable(pdf, tr, input.Stats)

	// Findings.
	pdf.Ln(4)
	sectionHeading(pdf, tr, fmt.Sprintf("Findings (%d)", len(input.Findings)))
	if len(input.Findings) == 0 {
		bodyText(pdf, tr, "No findings recorded for this campaign.")
	}
	for i, f := range input.Findings {
		renderFinding(pdf, tr, i+1, f, input.IncludePOC)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("render pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func sectionHeading(pdf *fpdf.Fpdf, tr translator, text string) {
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(30, 30, 30)
	pdf.CellFormat(0, 8, tr(text), "", 1, "L", false, 0, "")
	x, y := pdf.GetX(), pdf.GetY()
	pdf.SetDrawColor(200, 200, 200)
	pdf.Line(x, y, x+180, y)
	pdf.Ln(2)
}

func kvRow(pdf *fpdf.Fpdf, tr translator, label, value string) {
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.CellFormat(38, 6, tr(label), "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(40, 40, 40)
	pdf.MultiCell(0, 6, tr(value), "", "L", false)
}

func bulletLine(pdf *fpdf.Fpdf, tr translator, text string) {
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(40, 40, 40)
	pdf.CellFormat(5, 6, tr("-"), "", 0, "L", false, 0, "")
	pdf.MultiCell(0, 6, tr(text), "", "L", false)
}

func bodyText(pdf *fpdf.Fpdf, tr translator, text string) {
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(40, 40, 40)
	pdf.MultiCell(0, 5, tr(text), "", "L", false)
}

func statsTable(pdf *fpdf.Fpdf, tr translator, s StatsData) {
	cells := []struct {
		label   string
		count   int64
		r, g, b int
	}{
		{"Critical", s.Critical, 153, 27, 27},
		{"High", s.High, 194, 65, 12},
		{"Medium", s.Medium, 180, 130, 9},
		{"Low", s.Low, 21, 128, 61},
		{"Info", s.Info, 75, 85, 99},
	}
	w := 36.0
	for _, c := range cells {
		pdf.SetFillColor(c.r, c.g, c.b)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(w, 8, tr(fmt.Sprintf("%s: %d", c.label, c.count)), "", 0, "C", true, 0, "")
		pdf.CellFormat(2, 8, "", "", 0, "C", false, 0, "")
	}
	pdf.Ln(10)
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(40, 40, 40)
	pdf.MultiCell(0, 6, tr(fmt.Sprintf("Total findings: %d     Remediation progress: %.0f%%     Avg CVSS: %.1f     Max CVSS: %.1f",
		s.Total, s.Progress, s.AvgCVSS, s.MaxCVSS)), "", "L", false)
}

func renderFinding(pdf *fpdf.Fpdf, tr translator, n int, f FindingData, includePOC bool) {
	pdf.Ln(3)

	// Severity badge + title.
	sr, sg, sb := severityRGB(f.Severity)
	sev := strings.ToUpper(f.Severity)
	if sev == "" {
		sev = "UNSPECIFIED"
	}
	pdf.SetFillColor(sr, sg, sb)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(28, 7, tr(sev), "", 0, "C", true, 0, "")
	pdf.CellFormat(2, 7, "", "", 0, "L", false, 0, "")
	pdf.SetTextColor(20, 20, 20)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.MultiCell(0, 7, tr(fmt.Sprintf("%d. %s", n, f.Title)), "", "L", false)

	// Meta line.
	meta := []string{}
	if f.Status != "" {
		meta = append(meta, "Status: "+f.Status)
	}
	if f.CVSSScore > 0 {
		meta = append(meta, fmt.Sprintf("CVSS: %.1f", f.CVSSScore))
	}
	if f.CVSSVector != "" {
		meta = append(meta, f.CVSSVector)
	}
	if f.CWE != "" {
		meta = append(meta, "CWE: "+f.CWE)
	}
	if f.CVE != "" {
		meta = append(meta, "CVE: "+f.CVE)
	}
	if f.OWASP != "" {
		meta = append(meta, "OWASP: "+f.OWASP)
	}
	if len(meta) > 0 {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(110, 110, 110)
		pdf.MultiCell(0, 5, tr(strings.Join(meta, "   |   ")), "", "L", false)
	}

	findingField(pdf, tr, "Description", f.Description)
	if len(f.Steps) > 0 {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(80, 80, 80)
		pdf.CellFormat(0, 6, tr("Steps to reproduce"), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(40, 40, 40)
		for i, step := range f.Steps {
			pdf.CellFormat(8, 5, tr(fmt.Sprintf("%d.", i+1)), "", 0, "L", false, 0, "")
			pdf.MultiCell(0, 5, tr(step), "", "L", false)
		}
	}
	findingField(pdf, tr, "Business impact", f.Impact)
	findingField(pdf, tr, "Technical impact", f.TechImpact)
	findingField(pdf, tr, "Remediation", f.Remediation)
	if includePOC {
		findingField(pdf, tr, "Proof of concept", f.POC)
	}
	if len(f.Targets) > 0 {
		findingField(pdf, tr, "Affected targets", strings.Join(f.Targets, ", "))
	}
	if len(f.References) > 0 {
		findingField(pdf, tr, "References", strings.Join(f.References, "\n"))
	}
}

func findingField(pdf *fpdf.Fpdf, tr translator, label, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.CellFormat(0, 6, tr(label), "", 1, "L", false, 0, "")
	bodyText(pdf, tr, value)
}

func severityRGB(severity string) (int, int, int) {
	switch strings.ToLower(severity) {
	case "critical":
		return 153, 27, 27
	case "high":
		return 194, 65, 12
	case "medium":
		return 180, 130, 9
	case "low":
		return 21, 128, 61
	case "info", "informational":
		return 75, 85, 99
	default:
		return 100, 100, 100
	}
}
