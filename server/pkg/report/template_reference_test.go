package report

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/report/docx"
)

// kindOf maps a TemplateData value to its reference type.
func kindOf(v any) docx.Kind {
	switch v.(type) {
	case string:
		return docx.KindText
	case int, int64, float64:
		return docx.KindNumber
	case bool:
		return docx.KindBool
	case []string:
		return docx.KindTextList
	case []map[string]any:
		return docx.KindList
	case map[string]any:
		return docx.KindObject
	}
	return ""
}

// leaves flattens the data into key -> kind, item fields keyed as
// "<group>.<field>" like the reference.
func leaves(t *testing.T, data map[string]any) map[string]docx.Kind {
	t.Helper()
	listGroup := map[string]string{}
	for g, l := range itemGroupList {
		listGroup[l] = g
	}
	out := map[string]docx.Kind{}
	var visit func(prefix string, m map[string]any)
	visit = func(prefix string, m map[string]any) {
		for k, v := range m {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			kind := kindOf(v)
			if kind == docx.KindObject {
				visit(full, v.(map[string]any))
				continue
			}
			out[full] = kind
			if items, ok := v.([]map[string]any); ok && len(items) > 0 {
				if g, ok := listGroup[full]; ok {
					for f, iv := range items[0] {
						out[g+"."+f] = kindOf(iv)
					}
				}
			}
		}
	}
	visit("", data)
	return out
}

func TestTemplateReference_MatchesTemplateData(t *testing.T) {
	for _, lang := range TemplateLanguages {
		data := leaves(t, TemplateData(SampleReportInput(), lang))
		ref := map[string]TemplateField{}
		for _, f := range TemplateReference(lang, "en") {
			if _, dup := ref[f.Key]; dup {
				t.Fatalf("duplicate reference key %s", f.Key)
			}
			ref[f.Key] = f
		}
		var missing, extra []string
		for k, kind := range data {
			f, ok := ref[k]
			if !ok {
				missing = append(missing, k)
				continue
			}
			want := f.Type
			if want == docx.KindMarkdown {
				want = docx.KindText
			}
			if want != kind {
				t.Errorf("%s: reference type %s, data type %s", k, f.Type, kind)
			}
		}
		for k := range ref {
			if _, ok := data[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 || len(extra) > 0 {
			t.Fatalf("%s: reference and TemplateData differ: not in reference %v, not in data %v", lang, missing, extra)
		}
	}
}

func TestTemplateReference_ExamplesDescriptionsAndTags(t *testing.T) {
	en := map[string]TemplateField{}
	for _, f := range TemplateReference("en", "en") {
		en[f.Key] = f
		if f.Description == "" || f.Tag == "" {
			t.Errorf("%s: empty description or tag", f.Key)
		}
	}
	checks := map[string][2]string{
		"campaign.name":         {"Example Corp external assessment", "{campaign.name}"},
		"finding.cwe":           {"CWE-89", "{cwe}"},
		"finding.description":   {"The `username` parameter", "{@description}"},
		"finding.steps":         {"Open https://portal.example.com/login | ", "{#steps}{.}{/steps}"},
		"findings":              {"", "{#findings}…{/findings}"},
		"stats.avg_cvss":        {"7.6", "{stats.avg_cvss}"},
		"labels.severity":       {"Severity", "{labels.severity}"},
		"retest.status_label":   {"Passed", "{status_label}"},
		"team_member.name":      {"Alex Tester", "{name}"},
		"stats.has_critical":    {"true", "{#stats.has_critical}…{/stats.has_critical}"},
		"report.classification": {"confidential", "{report.classification}"},
	}
	for key, want := range checks {
		f, ok := en[key]
		if !ok {
			t.Errorf("%s missing", key)
			continue
		}
		if !strings.HasPrefix(f.Example, want[0]) || f.Tag != want[1] {
			t.Errorf("%s: example %q tag %q, want prefix %q tag %q", key, f.Example, f.Tag, want[0], want[1])
		}
	}
	if en["finding.title"].Within != "findings" || en["campaign.name"].Within != "" {
		t.Error("within is wrong")
	}

	vi := map[string]TemplateField{}
	for _, f := range TemplateReference("vi", "vi") {
		vi[f.Key] = f
	}
	if vi["labels.severity"].Example != "Mức độ" || vi["campaign.name"].Description == en["campaign.name"].Description {
		t.Errorf("vi reference not localized: %+v", vi["labels.severity"])
	}
	// Unsupported languages fall back to English.
	if TemplateReference("xx", "xx")[0].Description != TemplateReference("en", "en")[0].Description {
		t.Error("unsupported locale did not fall back to en")
	}
}

func TestTemplateSchema_StartersHaveNoIssues(t *testing.T) {
	for _, v := range docx.StarterVariants {
		info, err := docx.Check(docx.Starter(v), TemplateSchema())
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if len(info.Issues) > 0 {
			t.Fatalf("%s starter has issues: %+v", v, info.Issues)
		}
	}
}

func TestTemplateSchema_StartersRenderSampleData(t *testing.T) {
	for _, v := range docx.StarterVariants {
		for _, lang := range TemplateLanguages {
			out, info, err := docx.Render(docx.Starter(v), TemplateData(SampleReportInput(), lang), true)
			if err != nil {
				t.Fatalf("%s/%s: %v", v, lang, err)
			}
			if len(info.Warnings) > 0 {
				t.Fatalf("%s/%s: warnings %v", v, lang, info.Warnings)
			}
			if len(out) == 0 {
				t.Fatal("empty output")
			}
		}
	}
}

func TestTemplateSchema_FindsMisspelledAndMisplacedTags(t *testing.T) {
	tpl := docx.SimpleDocument(
		"{campaign.nmae}",
		"{title}",
		"{#findings}", "{severity_labl} {description}", "{/findings}",
		"{findings}",
		"{#steps}{.}{/steps}",
	)
	info, err := docx.Check(tpl, TemplateSchema())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]docx.Issue{}
	for _, is := range info.Issues {
		got[is.Tag] = is
	}
	want := map[string][2]string{
		"{campaign.nmae}": {docx.CodeUnknownTag, "{campaign.name}"},
		"{title}":         {docx.CodeFieldOutsideList, "{#findings}"},
		"{severity_labl}": {docx.CodeUnknownTag, "{severity_label}"},
		"{description}":   {docx.CodeMarkdownAsText, "{@description}"},
		"{findings}":      {docx.CodeListAsValue, "{#findings}…{/findings}"},
		"{#steps}":        {docx.CodeFieldOutsideList, "{#findings}"},
	}
	for tag, w := range want {
		is, ok := got[tag]
		if !ok {
			t.Errorf("no issue for %s; got %+v", tag, info.Issues)
			continue
		}
		if is.Code != w[0] || is.Suggestion != w[1] || is.Level != docx.LevelWarning || is.Part != "body" || is.Context == "" {
			t.Errorf("%s: got %+v, want code %s suggestion %s", tag, is, w[0], w[1])
		}
	}
	if is := got["{title}"]; is.Within != "findings" {
		t.Errorf("within = %q", is.Within)
	}
}

// The data reference in the architecture doc is generated: rerun with
// UPDATE_TEMPLATE_REFERENCE=1 after changing the data model.
func TestTemplateReferenceMarkdown_DocIsCurrent(t *testing.T) {
	const doc = "../../docs/architecture/pentest-report-templates.md"
	const begin, end = "<!-- BEGIN GENERATED TAG REFERENCE -->\n", "<!-- END GENERATED TAG REFERENCE -->"
	raw, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatalf("%s lacks the generated reference markers", doc)
	}
	want := s[:i+len(begin)] + "\n" + TemplateReferenceMarkdown() + "\n" + s[j:]
	if want == s {
		return
	}
	if os.Getenv("UPDATE_TEMPLATE_REFERENCE") == "1" {
		if err := os.WriteFile(doc, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("%s is out of date: run UPDATE_TEMPLATE_REFERENCE=1 go test ./pkg/report/ -run DocIsCurrent", doc)
}
