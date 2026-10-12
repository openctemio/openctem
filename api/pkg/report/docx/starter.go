package docx

import (
	"archive/zip"
	"bytes"
	"strconv"
	"strings"
)

// StarterTemplate returns a small .docx that uses the main tags of the report
// data model. Organizations download it, restyle it in Word and upload it as
// their own template. It is also the template the tests render.
func StarterTemplate() []byte {
	var body strings.Builder
	w := func(s ...string) {
		for _, x := range s {
			body.WriteString(x)
		}
	}
	w(para("{report.title}", runBold+runSize(40)))
	w(para("{campaign.name}", runBold+runSize(28)))
	w(para("{client.name}", ""))
	w(para("{campaign.start_date} – {campaign.end_date}", ""))
	w(para("{report.classification_label}", runItalic))
	w(heading("{labels.summary}"))
	w(para("{@campaign.description}", ""))
	w(table(
		row(cell("{labels.severity}", runBold), cell("{labels.count}", runBold)),
		row(cell("{labels.critical}", ""), cell("{stats.critical}", "")),
		row(cell("{labels.high}", ""), cell("{stats.high}", "")),
		row(cell("{labels.medium}", ""), cell("{stats.medium}", "")),
		row(cell("{labels.low}", ""), cell("{stats.low}", "")),
		row(cell("{labels.info}", ""), cell("{stats.info}", "")),
		row(cell("{labels.total}", runBold), cell("{stats.total}", runBold)),
	))
	w(heading("{labels.findings}"))
	w(para("{^findings}", ""), para("{labels.no_findings}", runItalic), para("{/findings}", ""))
	w(table(
		row(cell("#", runBold), cell("{labels.title}", runBold), cell("{labels.severity}", runBold), cell("CVSS", runBold), cell("{labels.status}", runBold)),
		row(cell("{#findings}{number}", ""), cell("{title}", ""), cell("{severity_label}", ""), cell("{cvss_score}", ""), cell("{status_label}{/findings}", "")),
	))
	w(para("{#findings}", ""))
	w(heading("{number}. {title}"))
	w(para("{labels.severity}: {severity_label}    CVSS: {cvss_score} {cvss_vector}", ""))
	w(para("{#cwe}CWE: {cwe}    {/cwe}{#cve}CVE: {cve}    {/cve}{#owasp}OWASP: {owasp}{/owasp}", ""))
	w(para("{#has_targets}", ""), para("{labels.affected_targets}", runBold), para("{/has_targets}", ""))
	w(para("{#targets}", ""), para("• {.}", ""), para("{/targets}", ""))
	w(para("{labels.description}", runBold), para("{@description}", ""))
	w(para("{#has_steps}", ""), para("{labels.steps}", runBold), para("{/has_steps}", ""))
	w(para("{#steps}", ""), para("• {.}", ""), para("{/steps}", ""))
	w(para("{#poc}", ""), para("{labels.poc}", runBold), para("{poc}", monoRun), para("{/poc}", ""))
	w(para("{#business_impact}", ""), para("{labels.business_impact}", runBold), para("{@business_impact}", ""), para("{/business_impact}", ""))
	w(para("{#remediation}", ""), para("{labels.remediation}", runBold), para("{@remediation}", ""), para("{/remediation}", ""))
	w(para("{#has_references}", ""), para("{labels.references}", runBold), para("{/has_references}", ""))
	w(para("{#references}", ""), para("• {.}", ""), para("{/references}", ""))
	w(para("{/findings}", ""))
	w(para("{#has_retests}", ""))
	w(heading("{labels.retests}"))
	w(table(
		row(cell("{labels.finding}", runBold), cell("{labels.result}", runBold), cell("{labels.tested_at}", runBold), cell("{labels.notes}", runBold)),
		row(cell("{#retests}{finding_title}", ""), cell("{status_label}", ""), cell("{tested_at}", ""), cell("{notes}{/retests}", "")),
	))
	w(para("{/has_retests}", ""))
	w(para("{labels.generated_at}: {report.generated_at}", runItalic+runSize(16)))

	doc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		body.String() +
		`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr>` +
		`</w:body></w:document>`
	return buildPackage(map[string]string{"word/document.xml": doc})
}

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

func para(text, rPr string) string {
	return "<w:p>" + run(text, rPr) + "</w:p>"
}

func heading(text string) string {
	return `<w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>` + run(text, runBold+runSize(28)) + "</w:p>"
}

func cell(text, rPr string) string {
	return `<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>` + para(text, rPr) + "</w:tc>"
}

func row(cells ...string) string {
	return "<w:tr>" + strings.Join(cells, "") + "</w:tr>"
}

func table(rows ...string) string {
	return `<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>` +
		`<w:top w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:left w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>` +
		`<w:bottom w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:right w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>` +
		`<w:insideH w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>` +
		`</w:tblBorders></w:tblPr>` + strings.Join(rows, "") + "</w:tbl>"
}

// buildPackage zips a minimal Word package around the given parts.
func buildPackage(parts map[string]string) []byte {
	all := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="` + contentTypeDocument + `"/>` +
			`</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`</Relationships>`,
	}
	for k, v := range parts {
		all[k] = v
	}
	order := []string{"[Content_Types].xml", "_rels/.rels"}
	for k := range all {
		if k != order[0] && k != order[1] {
			order = append(order, k)
		}
	}
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
