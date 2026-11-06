package docx

import (
	"archive/zip"
	"bytes"
	"sort"
	"strconv"
	"strings"
)

// Starter templates. Organizations download one, restyle it in Word or
// LibreOffice and upload it as their own template. Each is a complete Word
// package: named styles (Title, Heading 1-3, Code, List Bullet…) so a
// restyle changes every heading at once, a header and footer with the
// classification and page number, and only tags of the report data model.
// Static text comes from labels.*, so a starter works in every template
// language. The tests render each starter with the sample data.

// Starter variants.
const (
	StarterStandard  = "standard"  // cover, contents, summary, findings with evidence, remediation plan, appendix
	StarterExecutive = "executive" // one page for management: severity counts and key findings
	StarterTechnical = "technical" // one finding per page with every field, severity-colored
)

// StarterVariants lists the starter templates, the default first.
var StarterVariants = []string{StarterStandard, StarterExecutive, StarterTechnical}

// IsStarterVariant reports whether v names a starter template.
func IsStarterVariant(v string) bool {
	for _, s := range StarterVariants {
		if s == v {
			return true
		}
	}
	return false
}

// StarterTemplate returns the standard starter template.
func StarterTemplate() []byte { return Starter(StarterStandard) }

// Starter returns a starter template (the standard one for an unknown name).
func Starter(variant string) []byte {
	var b strings.Builder
	cover := true
	switch variant {
	case StarterExecutive:
		cover = false
		executiveBody(&b)
	case StarterTechnical:
		technicalBody(&b)
	default:
		standardBody(&b)
	}
	return buildStarterPackage(b.String(), cover)
}

// Page geometry: A4, 2 cm margins.
const (
	pageW     = 11906
	pageH     = 16838
	margin    = 1134
	textWidth = pageW - 2*margin
)

// Severity colors (cell shading, text color).
var severityColor = map[string][2]string{
	"critical": {"7B1E1E", "FFFFFF"},
	"high":     {"C0504D", "FFFFFF"},
	"medium":   {"F2A93B", "000000"},
	"low":      {"4F81BD", "FFFFFF"},
	"info":     {"A6A6A6", "000000"},
}

var severities = []string{"critical", "high", "medium", "low", "info"}

// --- building blocks ---

const (
	runBold   = "<w:b/>"
	runItalic = "<w:i/>"
	monoRun   = monoFont + `<w:sz w:val="18"/>`
)

func runSize(halfPoints int) string {
	return `<w:sz w:val="` + strconv.Itoa(halfPoints) + `"/>`
}

func run(text, rPr string) string {
	props := ""
	if rPr != "" {
		props = "<w:rPr>" + rPr + "</w:rPr>"
	}
	return "<w:r>" + props + `<w:t xml:space="preserve">` + escapeText(text) + "</w:t></w:r>"
}

// para is a paragraph of one run with run properties.
func para(text, rPr string) string {
	return "<w:p>" + run(text, rPr) + "</w:p>"
}

// sp is a paragraph in a named style.
func sp(style, text string) string {
	return `<w:p><w:pPr><w:pStyle w:val="` + style + `"/></w:pPr>` + run(text, "") + "</w:p>"
}

// tag is a paragraph holding only a section tag, kept small and hidden from
// the layout ({#x}, {/x} paragraphs are removed when the report renders).
func tag(t string) string { return sp("TemplateTag", t) }

func heading(level int, text string) string { return sp("Heading"+strconv.Itoa(level), text) }

func pageBreak() string { return `<w:p><w:r><w:br w:type="page"/></w:r></w:p>` }

// labeled is "<label>: value" with the label bold.
func labeled(label, value string) string {
	return `<w:p>` + run(label+": ", runBold) + run(value, "") + `</w:p>`
}

type tcell struct {
	text  string
	rPr   string
	fill  string // shading color, "" for none
	color string // text color
	style string // paragraph style
	width int    // twips
}

func (c tcell) xml() string {
	var b strings.Builder
	b.WriteString(`<w:tc><w:tcPr>`)
	if c.width > 0 {
		b.WriteString(`<w:tcW w:w="` + strconv.Itoa(c.width) + `" w:type="dxa"/>`)
	} else {
		b.WriteString(`<w:tcW w:w="0" w:type="auto"/>`)
	}
	if c.fill != "" {
		b.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="` + c.fill + `"/>`)
	}
	b.WriteString(`<w:vAlign w:val="center"/></w:tcPr><w:p>`)
	if c.style != "" {
		b.WriteString(`<w:pPr><w:pStyle w:val="` + c.style + `"/></w:pPr>`)
	}
	rPr := c.rPr
	if c.color != "" {
		rPr += `<w:color w:val="` + c.color + `"/>`
	}
	// Each section tag gets its own run so a restyle in Word keeps it whole.
	for _, part := range splitKeepTags(c.text) {
		b.WriteString(run(part, rPr))
	}
	b.WriteString(`</w:p></w:tc>`)
	return b.String()
}

// splitKeepTags splits text so each {#…}/{^…}/{/…} tag is its own piece.
func splitKeepTags(text string) []string {
	var out []string
	for text != "" {
		i := strings.IndexAny(text, "{")
		if i < 0 {
			out = append(out, text)
			break
		}
		j := strings.IndexByte(text[i:], '}')
		if j < 0 {
			out = append(out, text)
			break
		}
		if i > 0 {
			out = append(out, text[:i])
		}
		out = append(out, text[i:i+j+1])
		text = text[i+j+1:]
	}
	return out
}

func trow(cells ...tcell) string {
	var b strings.Builder
	b.WriteString(`<w:tr><w:trPr><w:cantSplit/></w:trPr>`)
	for _, c := range cells {
		b.WriteString(c.xml())
	}
	b.WriteString(`</w:tr>`)
	return b.String()
}

// headerRow is a repeated table header row.
func headerRow(cells ...tcell) string {
	var b strings.Builder
	b.WriteString(`<w:tr><w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>`)
	for _, c := range cells {
		c.rPr = runBold + c.rPr
		if c.fill == "" {
			c.fill = "1F3864"
			c.color = "FFFFFF"
		}
		b.WriteString(c.xml())
	}
	b.WriteString(`</w:tr>`)
	return b.String()
}

// tbl is a full-width bordered table with the given column widths (twips).
func tbl(widths []int, rows ...string) string {
	var b strings.Builder
	b.WriteString(`<w:tbl><w:tblPr><w:tblStyle w:val="ReportTable"/><w:tblW w:w="` + strconv.Itoa(textWidth) + `" w:type="dxa"/>` +
		`<w:tblLayout w:type="fixed"/><w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" w:noHBand="1" w:noVBand="1"/></w:tblPr><w:tblGrid>`)
	for _, w := range widths {
		b.WriteString(`<w:gridCol w:w="` + strconv.Itoa(w) + `"/>`)
	}
	b.WriteString(`</w:tblGrid>`)
	for _, r := range rows {
		b.WriteString(r)
	}
	b.WriteString(`</w:tbl>`)
	// A paragraph after a table keeps the next table from merging into it.
	b.WriteString(`<w:p><w:pPr><w:pStyle w:val="TableGap"/></w:pPr></w:p>`)
	return b.String()
}

func cols(widths ...int) []int { return widths }

func cl(text string, width int) tcell { return tcell{text: text, width: width} }

// severityCell is a cell colored for one severity.
func severityCell(sev, text string, width int) tcell {
	c := severityColor[sev]
	return tcell{text: text, width: width, fill: c[0], color: c[1], rPr: runBold}
}

// --- shared sections ---

func cover(b *strings.Builder) {
	b.WriteString(`<w:p><w:pPr><w:spacing w:before="3600"/></w:pPr></w:p>`)
	b.WriteString(sp("Title", "{report.title}"))
	b.WriteString(sp("Subtitle", "{campaign.name}"))
	b.WriteString(`<w:p><w:pPr><w:spacing w:before="1200"/></w:pPr></w:p>`)
	b.WriteString(labeled("{labels.prepared_for}", "{client.name}"))
	b.WriteString(labeled("{labels.period}", "{campaign.start_date} – {campaign.end_date}"))
	b.WriteString(labeled("{labels.classification}", "{report.classification_label}"))
	b.WriteString(labeled("{labels.generated_at}", "{report.generated_at}"))
	b.WriteString(pageBreak())
}

func contents(b *strings.Builder) {
	b.WriteString(sp("TOCHeading", "{labels.contents}"))
	// A table-of-contents field over Heading 1-2. Word fills it when the
	// report is opened (the field is marked dirty); in LibreOffice use
	// Tools > Update > Update All.
	b.WriteString(`<w:p><w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r>` +
		`<w:r><w:instrText xml:space="preserve"> TOC \o "1-2" \h \z \u </w:instrText></w:r>` +
		`<w:r><w:fldChar w:fldCharType="separate"/></w:r>` +
		run("Update this field to list the chapters (Word: right-click > Update Field; LibreOffice: Tools > Update > Update All).", runItalic) +
		`<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>`)
	b.WriteString(pageBreak())
}

func severityTable(b *strings.Builder) {
	w := cols(textWidth*2/3, textWidth-textWidth*2/3)
	rows := []string{headerRow(cl("{labels.severity}", w[0]), cl("{labels.count}", w[1]))}
	for _, s := range severities {
		rows = append(rows, trow(severityCell(s, "{labels."+s+"}", w[0]), cl("{stats."+s+"}", w[1])))
	}
	rows = append(rows, trow(tcell{text: "{labels.total}", rPr: runBold, width: w[0]}, tcell{text: "{stats.total}", rPr: runBold, width: w[1]}))
	b.WriteString(tbl(w, rows...))
}

func findingsSummaryTable(b *strings.Builder) {
	b.WriteString(tag("{^has_findings}"))
	b.WriteString(sp("Note", "{labels.no_findings}"))
	b.WriteString(tag("{/has_findings}"))
	w := cols(900, textWidth-900-1500-1000-1700, 1500, 1000, 1700)
	b.WriteString(tbl(w,
		headerRow(cl("#", w[0]), cl("{labels.title}", w[1]), cl("{labels.severity}", w[2]), cl("{labels.cvss}", w[3]), cl("{labels.status}", w[4])),
		trow(cl("{#findings}{number}", w[0]), cl("{title}", w[1]), cl("{severity_label}", w[2]), cl("{cvss_score}", w[3]), cl("{status_label}{/findings}", w[4])),
	))
}

// findingBody is the narrative of one finding (inside {#findings}).
func findingBody(b *strings.Builder, withTechnical bool) {
	b.WriteString(sp("Label", "{labels.description}"))
	b.WriteString(sp("Normal", "{@description}"))
	b.WriteString(tag("{#has_steps}"))
	b.WriteString(sp("Label", "{labels.steps}"))
	b.WriteString(tag("{/has_steps}"))
	b.WriteString(tag("{#steps}"))
	b.WriteString(sp("ListBullet", "• {.}"))
	b.WriteString(tag("{/steps}"))
	b.WriteString(tag("{#poc}"))
	b.WriteString(sp("Label", "{labels.poc}"))
	b.WriteString(sp("Code", "{poc}"))
	b.WriteString(tag("{/poc}"))
	if withTechnical {
		b.WriteString(tag("{#technical_impact}"))
		b.WriteString(sp("Label", "{labels.technical_impact}"))
		b.WriteString(sp("Normal", "{@technical_impact}"))
		b.WriteString(tag("{/technical_impact}"))
	}
	b.WriteString(tag("{#business_impact}"))
	b.WriteString(sp("Label", "{labels.business_impact}"))
	b.WriteString(sp("Normal", "{@business_impact}"))
	b.WriteString(tag("{/business_impact}"))
	b.WriteString(tag("{#remediation}"))
	b.WriteString(sp("Label", "{labels.remediation}"))
	b.WriteString(sp("Normal", "{@remediation}"))
	b.WriteString(tag("{/remediation}"))
	b.WriteString(tag("{#has_references}"))
	b.WriteString(sp("Label", "{labels.references}"))
	b.WriteString(tag("{/has_references}"))
	b.WriteString(tag("{#references}"))
	b.WriteString(sp("ListBullet", "• {.}"))
	b.WriteString(tag("{/references}"))
}

// findingMeta is the key/value table of one finding. Rows whose value is
// empty are left out ({#cwe}…{/cwe} around a whole row).
func findingMeta(b *strings.Builder, full bool) {
	w := cols(2600, textWidth-2600)
	rows := []string{}
	// The severity row: one colored row per severity, only the matching
	// one is kept.
	for _, s := range severities {
		c := severityColor[s]
		rows = append(rows, trow(
			tcell{text: "{#is_" + s + "}{labels.severity}", rPr: runBold, width: w[0]},
			tcell{text: "{severity_label}{/is_" + s + "}", rPr: runBold, width: w[1], fill: c[0], color: c[1]},
		))
	}
	rows = append(rows,
		trow(tcell{text: "{labels.status}", rPr: runBold, width: w[0]}, cl("{status_label}", w[1])),
		trow(tcell{text: "{#cvss_score}{labels.cvss}", rPr: runBold, width: w[0]}, cl("{cvss_score}{#cvss_vector} ({cvss_vector}){/cvss_vector}{/cvss_score}", w[1])),
	)
	if full {
		rows = append(rows,
			trow(tcell{text: "{#cwe}CWE", rPr: runBold, width: w[0]}, cl("{cwe}{/cwe}", w[1])),
			trow(tcell{text: "{#cve}CVE", rPr: runBold, width: w[0]}, cl("{cve}{/cve}", w[1])),
			trow(tcell{text: "{#owasp}OWASP", rPr: runBold, width: w[0]}, cl("{owasp}{/owasp}", w[1])),
			trow(tcell{text: "{labels.reported}", rPr: runBold, width: w[0]}, cl("{created_at}", w[1])),
		)
	} else {
		rows = append(rows, trow(tcell{text: "{#cwe}CWE", rPr: runBold, width: w[0]}, cl("{cwe}{#cve} · {cve}{/cve}{#owasp} · {owasp}{/owasp}{/cwe}", w[1])))
	}
	rows = append(rows, trow(tcell{text: "{#has_targets}{labels.affected_targets}", rPr: runBold, width: w[0]}, cl("{targets}{/has_targets}", w[1])))
	b.WriteString(tbl(w, rows...))
}

func retestsSection(b *strings.Builder, level int) {
	b.WriteString(tag("{#has_retests}"))
	b.WriteString(heading(level, "{labels.retests}"))
	w := cols(textWidth-1700-1500-2600, 1700, 1500, 2600)
	b.WriteString(tbl(w,
		headerRow(cl("{labels.finding}", w[0]), cl("{labels.result}", w[1]), cl("{labels.tested_at}", w[2]), cl("{labels.notes}", w[3])),
		trow(cl("{#retests}{finding_title}", w[0]), cl("{status_label}", w[1]), cl("{tested_at}", w[2]), cl("{notes}{/retests}", w[3])),
	))
	b.WriteString(tag("{/has_retests}"))
}

func appendix(b *strings.Builder) {
	b.WriteString(heading(1, "{labels.appendix}"))
	b.WriteString(tag("{#campaign.methodology}"))
	b.WriteString(heading(2, "{labels.methodology}"))
	b.WriteString(sp("Normal", "{campaign.methodology}"))
	b.WriteString(tag("{/campaign.methodology}"))
	w := cols(textWidth/2, textWidth-textWidth/2)
	b.WriteString(heading(2, "{labels.team}"))
	b.WriteString(tbl(w,
		headerRow(cl("{labels.name}", w[0]), cl("{labels.role}", w[1])),
		trow(cl("{#team}{name}", w[0]), cl("{role}{/team}", w[1])),
	))
	b.WriteString(heading(2, "{labels.severity_ratings}"))
	w = cols(2000, textWidth-2000)
	rows := []string{headerRow(cl("{labels.severity}", w[0]), cl("{labels.description}", w[1]))}
	for _, s := range severities {
		rows = append(rows, trow(severityCell(s, "{labels."+s+"}", w[0]), cl("{labels."+s+"_desc}", w[1])))
	}
	b.WriteString(tbl(w, rows...))
}

// --- variants ---

func standardBody(b *strings.Builder) {
	cover(b)
	contents(b)
	b.WriteString(heading(1, "{labels.summary}"))
	b.WriteString(sp("Normal", "{@campaign.description}"))
	severityTable(b)
	b.WriteString(heading(1, "{labels.findings}"))
	findingsSummaryTable(b)
	b.WriteString(tag("{#findings}"))
	b.WriteString(heading(2, "{number}. {title}"))
	findingMeta(b, false)
	findingBody(b, false)
	b.WriteString(tag("{/findings}"))
	b.WriteString(tag("{#has_findings}"))
	b.WriteString(heading(1, "{labels.remediation_plan}"))
	w := cols(900, textWidth-900-1700-2000, 1700, 2000)
	b.WriteString(tbl(w,
		headerRow(cl("#", w[0]), cl("{labels.title}", w[1]), cl("{labels.severity}", w[2]), cl("{labels.status}", w[3])),
		trow(cl("{#findings}{number}", w[0]), cl("{title}", w[1]), cl("{severity_label}", w[2]), cl("{status_label}{/findings}", w[3])),
	))
	b.WriteString(tag("{/has_findings}"))
	retestsSection(b, 1)
	appendix(b)
}

func executiveBody(b *strings.Builder) {
	b.WriteString(sp("Title", "{labels.executive_summary}"))
	b.WriteString(sp("Subtitle", "{campaign.name} · {client.name}"))
	b.WriteString(`<w:p>` + run("{labels.period}: ", runBold) + run("{campaign.start_date} – {campaign.end_date}", "") +
		run("     {labels.classification}: ", runBold) + run("{report.classification_label}", "") + `</w:p>`)
	b.WriteString(heading(1, "{labels.overview}"))
	b.WriteString(sp("Normal", "{@campaign.description}"))
	// Severity at a glance: one colored column per severity.
	cw := textWidth / 6
	w := cols(cw, cw, cw, cw, cw, textWidth-5*cw)
	head := make([]tcell, 0, 6)
	vals := make([]tcell, 0, 6)
	for i, s := range severities {
		c := severityColor[s]
		head = append(head, tcell{text: "{labels." + s + "}", width: w[i], fill: c[0], color: c[1], style: "Centered"})
		vals = append(vals, tcell{text: "{stats." + s + "}", width: w[i], rPr: runBold + runSize(32), style: "Centered"})
	}
	head = append(head, tcell{text: "{labels.total}", width: w[5], style: "Centered"})
	vals = append(vals, tcell{text: "{stats.total}", width: w[5], rPr: runBold + runSize(32), style: "Centered"})
	b.WriteString(tbl(w, headerRow(head...), trow(vals...)))
	b.WriteString(heading(1, "{labels.key_findings}"))
	b.WriteString(`<w:p><w:pPr><w:pStyle w:val="Note"/></w:pPr>` + run("{^stats.has_critical}", "") + run("{^stats.has_high}", "") +
		run("{labels.no_key_findings}", "") + run("{/stats.has_high}", "") + run("{/stats.has_critical}", "") + `</w:p>`)
	w = cols(900, textWidth-900-1600-1900, 1600, 1900)
	rows := []string{headerRow(cl("#", w[0]), cl("{labels.title}", w[1]), cl("{labels.severity}", w[2]), cl("{labels.status}", w[3]))}
	for _, s := range []string{"critical", "high"} {
		list := "findings_by_severity." + s
		rows = append(rows, trow(cl("{#"+list+"}{number}", w[0]), cl("{title}", w[1]), severityCell(s, "{severity_label}", w[2]), cl("{status_label}{/"+list+"}", w[3])))
	}
	b.WriteString(tbl(w, rows...))
	retestsSection(b, 1)
	b.WriteString(sp("Small", "{labels.generated_at}: {report.generated_at}"))
}

func technicalBody(b *strings.Builder) {
	cover(b)
	contents(b)
	b.WriteString(heading(1, "{labels.summary}"))
	b.WriteString(sp("Normal", "{@campaign.description}"))
	severityTable(b)
	b.WriteString(tag("{#campaign.methodology}"))
	b.WriteString(labeled("{labels.methodology}", "{campaign.methodology}"))
	b.WriteString(tag("{/campaign.methodology}"))
	b.WriteString(heading(1, "{labels.findings}"))
	findingsSummaryTable(b)
	b.WriteString(tag("{#findings}"))
	b.WriteString(sp("FindingHeading", "{number}. {title}"))
	findingMeta(b, true)
	findingBody(b, true)
	b.WriteString(tag("{/findings}"))
	retestsSection(b, 1)
	appendix(b)
}

// --- package ---

const nsW = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"`

func buildStarterPackage(body string, titlePage bool) []byte {
	sect := `<w:sectPr><w:headerReference w:type="default" r:id="rIdHeader"/><w:footerReference w:type="default" r:id="rIdFooter"/>` +
		`<w:pgSz w:w="` + strconv.Itoa(pageW) + `" w:h="` + strconv.Itoa(pageH) + `"/>` +
		`<w:pgMar w:top="1418" w:right="` + strconv.Itoa(margin) + `" w:bottom="1418" w:left="` + strconv.Itoa(margin) + `" w:header="567" w:footer="567" w:gutter="0"/>`
	if titlePage {
		sect += `<w:titlePg/>`
	}
	sect += `</w:sectPr>`
	doc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ` + nsW + `><w:body>` + body + sect + `</w:body></w:document>`

	right := `<w:tabs><w:tab w:val="right" w:pos="` + strconv.Itoa(textWidth) + `"/></w:tabs>`
	header := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr ` + nsW + `>` +
		`<w:p><w:pPr><w:pStyle w:val="Header"/>` + right + `</w:pPr>` + run("{client.name} · {report.title}", "") +
		`<w:r><w:tab/></w:r>` + run("{report.classification_label}", runBold) + `</w:p></w:hdr>`
	footer := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr ` + nsW + `>` +
		`<w:p><w:pPr><w:pStyle w:val="Footer"/>` + right + `</w:pPr>` + run("{campaign.name}", "") +
		`<w:r><w:tab/></w:r><w:fldSimple w:instr=" PAGE "><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p></w:ftr>`

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
		`<Relationship Id="rIdSettings" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>` +
		`<Relationship Id="rIdHeader" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>` +
		`<Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>` +
		`</Relationships>`
	settings := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:defaultTabStop w:val="720"/><w:characterSpacingControl w:val="doNotCompress"/><w:updateFields w:val="true"/><w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat></w:settings>`
	return buildPackage(map[string]string{
		"word/document.xml":            doc,
		"word/styles.xml":              starterStyles,
		"word/settings.xml":            settings,
		"word/header1.xml":             header,
		"word/footer1.xml":             footer,
		"word/_rels/document.xml.rels": rels,
	})
}

func pStyle(id, name, basedOn, pPr, rPr string, extra string) string {
	s := `<w:style w:type="paragraph" w:customStyle="0" w:styleId="` + id + `"><w:name w:val="` + name + `"/>`
	if basedOn != "" {
		s += `<w:basedOn w:val="` + basedOn + `"/>`
	}
	s += extra + `<w:qFormat/>`
	if pPr != "" {
		s += `<w:pPr>` + pPr + `</w:pPr>`
	}
	if rPr != "" {
		s += `<w:rPr>` + rPr + `</w:rPr>`
	}
	return s + `</w:style>`
}

const brand = "1F3864"

var starterStyles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
	`<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-US"/></w:rPr></w:rPrDefault>` +
	`<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>` +
	`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>` +
	pStyle("Title", "Title", "Normal", `<w:spacing w:after="240"/>`, `<w:b/><w:color w:val="`+brand+`"/><w:sz w:val="56"/><w:szCs w:val="56"/>`, `<w:next w:val="Subtitle"/>`) +
	pStyle("Subtitle", "Subtitle", "Normal", `<w:spacing w:after="240"/>`, `<w:color w:val="595959"/><w:sz w:val="32"/><w:szCs w:val="32"/>`, "") +
	pStyle("Heading1", "heading 1", "Normal", `<w:keepNext/><w:keepLines/><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="1" w:color="`+brand+`"/></w:pBdr><w:spacing w:before="360" w:after="160"/><w:outlineLvl w:val="0"/>`, `<w:b/><w:color w:val="`+brand+`"/><w:sz w:val="32"/><w:szCs w:val="32"/>`, `<w:next w:val="Normal"/>`) +
	pStyle("Heading2", "heading 2", "Normal", `<w:keepNext/><w:keepLines/><w:spacing w:before="280" w:after="120"/><w:outlineLvl w:val="1"/>`, `<w:b/><w:color w:val="`+brand+`"/><w:sz w:val="26"/><w:szCs w:val="26"/>`, `<w:next w:val="Normal"/>`) +
	pStyle("Heading3", "heading 3", "Normal", `<w:keepNext/><w:keepLines/><w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="2"/>`, `<w:b/><w:sz w:val="22"/><w:szCs w:val="22"/>`, `<w:next w:val="Normal"/>`) +
	pStyle("FindingHeading", "Finding Heading", "Heading2", `<w:pageBreakBefore/>`, "", "") +
	pStyle("TOCHeading", "TOC Heading", "Normal", `<w:spacing w:after="240"/>`, `<w:b/><w:color w:val="`+brand+`"/><w:sz w:val="32"/><w:szCs w:val="32"/>`, "") +
	pStyle("Label", "Label", "Normal", `<w:keepNext/><w:spacing w:before="160" w:after="40"/>`, `<w:b/><w:color w:val="404040"/>`, "") +
	pStyle("Code", "Code", "Normal", `<w:pBdr><w:left w:val="single" w:sz="12" w:space="4" w:color="BFBFBF"/></w:pBdr><w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/><w:spacing w:after="120" w:line="240" w:lineRule="auto"/><w:ind w:left="113"/>`, monoFont+`<w:sz w:val="17"/><w:szCs w:val="17"/>`, "") +
	pStyle("ListBullet", "List Bullet", "Normal", `<w:spacing w:after="60"/><w:ind w:left="397" w:hanging="227"/>`, "", "") +
	pStyle("Note", "Note", "Normal", "", `<w:i/><w:color w:val="595959"/>`, "") +
	pStyle("Small", "Small", "Normal", "", `<w:color w:val="7F7F7F"/><w:sz w:val="16"/><w:szCs w:val="16"/>`, "") +
	pStyle("Centered", "Centered", "Normal", `<w:spacing w:before="40" w:after="40"/><w:jc w:val="center"/>`, "", "") +
	pStyle("TableGap", "Table Gap", "Normal", `<w:spacing w:after="0" w:line="120" w:lineRule="exact"/>`, `<w:sz w:val="8"/><w:szCs w:val="8"/>`, "") +
	pStyle("TemplateTag", "Template Tag", "Normal", `<w:spacing w:after="0"/>`, `<w:color w:val="8064A2"/><w:sz w:val="16"/><w:szCs w:val="16"/>`, "") +
	pStyle("Header", "header", "Normal", `<w:spacing w:after="0"/>`, `<w:color w:val="7F7F7F"/><w:sz w:val="16"/><w:szCs w:val="16"/>`, "") +
	pStyle("Footer", "footer", "Normal", `<w:spacing w:after="0"/>`, `<w:color w:val="7F7F7F"/><w:sz w:val="16"/><w:szCs w:val="16"/>`, "") +
	`<w:style w:type="table" w:customStyle="1" w:styleId="ReportTable"><w:name w:val="Report Table"/><w:pPr><w:spacing w:after="0"/></w:pPr><w:tblPr><w:tblBorders>` +
	`<w:top w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:left w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>` +
	`<w:bottom w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:right w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>` +
	`<w:insideH w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>` +
	`</w:tblBorders><w:tblCellMar><w:top w:w="57" w:type="dxa"/><w:left w:w="108" w:type="dxa"/><w:bottom w:w="57" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr>` +
	`</w:style>` +
	`</w:styles>`

// buildPackage zips a Word package around the given parts, declaring the
// content type of each known part.
func buildPackage(parts map[string]string) []byte {
	overrides := map[string]string{
		"word/document.xml": contentTypeDocument,
		"word/styles.xml":   "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
		"word/settings.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
		"word/header1.xml":  "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml",
		"word/footer1.xml":  "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",
	}
	var ct strings.Builder
	ct.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>`)
	names := make([]string, 0, len(parts))
	for k := range parts {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if t, ok := overrides[k]; ok {
			ct.WriteString(`<Override PartName="/` + k + `" ContentType="` + t + `"/>`)
		}
	}
	ct.WriteString(`</Types>`)
	all := map[string]string{
		"[Content_Types].xml": ct.String(),
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`</Relationships>`,
	}
	for k, v := range parts {
		all[k] = v
	}
	order := append([]string{"[Content_Types].xml", "_rels/.rels"}, names...)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range order {
		f, err := zw.Create(name)
		if err != nil {
			panic(err) // in-memory writer: cannot fail
		}
		_, _ = f.Write([]byte(all[name]))
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// SimpleDocument is a minimal .docx with one paragraph per string (for
// tests and examples).
func SimpleDocument(paragraphs ...string) []byte {
	var b strings.Builder
	for _, p := range paragraphs {
		b.WriteString(para(p, ""))
	}
	return buildPackage(map[string]string{"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ` + nsW + `><w:body>` +
		b.String() + `<w:sectPr/></w:body></w:document>`})
}
