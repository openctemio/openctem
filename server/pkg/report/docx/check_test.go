package docx

import (
	"errors"
	"strings"
	"testing"
)

func issueByCode(info *Info, code string) *Issue {
	for i := range info.Issues {
		if info.Issues[i].Code == code {
			return &info.Issues[i]
		}
	}
	return nil
}

// Every structural problem is reported at once, each with where it is and
// the tag that fixes it.
func TestCheck_CollectsEveryErrorWithLocationAndFix(t *testing.T) {
	body := para("Intro", "") +
		para("{#findings}", "") + para("{title}", "") + // never closed
		para("{/retests}", "") + // closes nothing open
		para("Text {@description}", "") + // Markdown not alone
		para("{%logo}", "") + // image tag
		para("{#a}", "") + table(row(cell("{/a}", ""))) // crosses a table boundary
	info, err := Inspect(docWith(body))
	if !errors.Is(err, ErrInvalidTemplate) {
		t.Fatalf("err = %v, want ErrInvalidTemplate", err)
	}
	if info == nil {
		t.Fatal("no info returned with the error")
	}
	want := map[string]struct{ tag, sugg, ctx string }{
		CodeUnclosedSection:  {"{#findings}", "{/findings}", "{#findings}"},
		CodeMismatchedClose:  {"{/retests}", "{/findings}", "{/retests}"},
		CodeMarkdownNotAlone: {"{@description}", "", "Text {@description}"},
		CodeImageTag:         {"{%logo}", "", "{%logo}"},
		CodeSectionPlacement: {"{#a}", "{/a}", "{#a}"},
	}
	for code, w := range want {
		is := issueByCode(info, code)
		if is == nil {
			t.Errorf("missing %s; got %+v", code, info.Issues)
			continue
		}
		if is.Level != LevelError || is.Tag != w.tag || is.Suggestion != w.sugg || is.Context != w.ctx || is.Part != "body" || is.Message == "" {
			t.Errorf("%s: got %+v", code, *is)
		}
	}
}

func TestCheck_StrayCloseAndUnclosedInHeader(t *testing.T) {
	tpl := buildPackage(map[string]string{
		"word/document.xml": docOpen + para("{/findings}", "") + docClose,
		"word/header1.xml":  `<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` + para("{#has_findings}x", "") + `</w:hdr>`,
	})
	info, err := Inspect(tpl)
	if !errors.Is(err, ErrInvalidTemplate) {
		t.Fatalf("err = %v", err)
	}
	if is := issueByCode(info, CodeStrayClose); is == nil || is.Suggestion != "{#findings}" || is.Part != "body" {
		t.Errorf("stray close: %+v", info.Issues)
	}
	if is := issueByCode(info, CodeUnclosedSection); is == nil || is.Part != "header" || is.Context != "{#has_findings}x" {
		t.Errorf("unclosed in header: %+v", info.Issues)
	}
}

func TestCheck_WarningsDoNotFail(t *testing.T) {
	body := para("Price {campaign name} and {{x}}", "") + // literal braces
		para("Broken {campaign.na", "") + // brace never closed in the paragraph
		`<w:p><w:ins w:id="1" w:author="a" w:date="2026-01-01T00:00:00Z">` + run("{client.name}", "") + `</w:ins></w:p>`
	info, err := Inspect(docWith(body))
	if err != nil {
		t.Fatalf("warnings must not fail: %v", err)
	}
	lit := issueByCode(info, CodeLiteralBrace)
	if lit == nil || lit.Level != LevelWarning || lit.Tag != "{campaign name}" || lit.Suggestion != "{campaign_name}" {
		t.Errorf("literal brace: %+v", info.Issues)
	}
	if is := issueByCode(info, CodeUnclosedBrace); is == nil || is.Context != "Broken {campaign.na" {
		t.Errorf("unclosed brace: %+v", info.Issues)
	}
	if issueByCode(info, CodeTrackedChanges) == nil {
		t.Errorf("tracked changes not reported: %+v", info.Issues)
	}
	if len(info.Warnings) != len(info.Issues) {
		t.Errorf("warnings %d != issues %d", len(info.Warnings), len(info.Issues))
	}
}

func TestCheck_LiteralSuggestionUsesSchema(t *testing.T) {
	schema := &Schema{Kind: KindObject, Fields: map[string]*Schema{
		"campaign": {Kind: KindObject, Fields: map[string]*Schema{"name": {Kind: KindText}}},
	}}
	info, err := Check(docWith(para("{campaign-name}", "")), schema)
	if err != nil {
		t.Fatal(err)
	}
	if is := issueByCode(info, CodeLiteralBrace); is == nil || is.Suggestion != "{campaign.name}" {
		t.Errorf("got %+v", info.Issues)
	}
}

func TestCheck_ContextIsShortened(t *testing.T) {
	long := strings.Repeat("word ", 40) + "{/x}"
	info, _ := Inspect(docWith(para(long, "")))
	is := issueByCode(info, CodeStrayClose)
	if is == nil || len([]rune(is.Context)) > maxContext || !strings.HasSuffix(is.Context, "…") {
		t.Fatalf("context not shortened: %+v", is)
	}
}

func TestRender_FailsOnFirstErrorWithItsMessage(t *testing.T) {
	_, _, err := Render(docWith(para("{#a}", "")), Data{}, false)
	if !errors.Is(err, ErrInvalidTemplate) || !strings.Contains(err.Error(), "{#a} is never closed") {
		t.Fatalf("err = %v", err)
	}
}

// Word splits text into runs for spell check, edits, language and
// formatting changes, with proofErr, bookmarks and rsid attributes between
// them. Tags split that way are merged before parsing.
func TestRender_WordStyleSplitRuns(t *testing.T) {
	r := func(text, rsid string) string {
		return `<w:r w:rsidR="` + rsid + `"><w:rPr><w:lang w:val="en-GB"/></w:rPr><w:t xml:space="preserve">` + text + `</w:t></w:r>`
	}
	body := `<w:p w:rsidR="00A1"><w:pPr><w:pStyle w:val="Heading1"/></w:pPr>` +
		r("{", "01") + `<w:proofErr w:type="spellStart"/>` + r("campaign", "02") + `<w:proofErr w:type="spellEnd"/>` +
		r(".", "03") + `<w:bookmarkStart w:id="0" w:name="_Toc1"/>` + r("na", "04") + `<w:bookmarkEnd w:id="0"/>` + r("me} for {client.", "05") +
		r("name}", "06") + `</w:p>` +
		`<w:p>` + r("{#fin", "07") + r("dings}", "08") + `</w:p>` +
		`<w:p>` + r("{tit", "09") + r("le}", "10") + `</w:p>` +
		`<w:p>` + r("{/findi", "11") + r("ngs", "12") + r("}", "13") + `</w:p>`
	data := Data{
		"campaign": map[string]any{"name": "Acme"}, "client": map[string]any{"name": "Client Co"},
		"findings": []map[string]any{{"title": "SQLi"}, {"title": "XSS"}},
	}
	doc := render(t, docWith(body), data)
	for _, want := range []string{"Acme", " for ", "Client Co", "SQLi", "XSS", `w:pStyle w:val="Heading1"`, `w:lang w:val="en-GB"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("rendered document lacks %q", want)
		}
	}
	if strings.Contains(doc, "{campaign") || strings.Contains(doc, "findings}") || strings.Contains(doc, "{tit") {
		t.Errorf("a split tag was left in the output")
	}
}

func TestCheck_SchemaScopesFollowSections(t *testing.T) {
	item := map[string]*Schema{"title": {Kind: KindText}, "steps": {Kind: KindTextList}}
	schema := &Schema{Kind: KindObject, Fields: map[string]*Schema{
		"findings": {Kind: KindList, Fields: item},
		"client":   {Kind: KindObject, Fields: map[string]*Schema{"name": {Kind: KindText}}},
	}}
	ok := docWith(para("{#findings}", "") + para("{title} {client.name}", "") + para("{#steps}{.}{/steps}", "") + para("{/findings}", "") +
		para("{#client}{name}{/client}", ""))
	info, err := Check(ok, schema)
	if err != nil || len(info.Issues) > 0 {
		t.Fatalf("valid template reported: %v %+v", err, info.Issues)
	}
	bad := docWith(para("{.}", "") + para("{client}", ""))
	info, err = Check(bad, schema)
	if err != nil {
		t.Fatal(err)
	}
	if issueByCode(info, CodeItemOutsideList) == nil {
		t.Errorf("{.} outside a list not reported: %+v", info.Issues)
	}
	if is := issueByCode(info, CodeListAsValue); is == nil || !strings.Contains(is.Message, "{client.name}") {
		t.Errorf("group used as a value not reported: %+v", info.Issues)
	}
}
