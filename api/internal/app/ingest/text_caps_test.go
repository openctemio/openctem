package ingest

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/openctemio/ctis"
)

func TestTextCapper_Str(t *testing.T) {
	c := &textCapper{}
	if got := c.str("short", 10); got != "short" || c.changed != 0 {
		t.Fatalf("short value changed: %q (%d)", got, c.changed)
	}
	exact := strings.Repeat("é", 10)
	if got := c.str(exact, 10); got != exact || c.changed != 0 {
		t.Fatalf("value at the cap changed: %q", got)
	}

	long := strings.Repeat("é", 1000) // 2 bytes per rune
	got := c.str(long, 100)
	if utf8.RuneCountInString(got) != 100 || !strings.HasSuffix(got, TruncationMarker) || !utf8.ValidString(got) {
		t.Fatalf("cut value: %d runes, valid %v, %q", utf8.RuneCountInString(got), utf8.ValidString(got), got[len(got)-20:])
	}
	if c.changed != 1 {
		t.Fatalf("changed = %d, want 1", c.changed)
	}

	if got := c.str("ab\xffcd", 100); !utf8.ValidString(got) || got != "ab\uFFFDcd" {
		t.Fatalf("invalid UTF-8 kept: %q", got)
	}
	if got := c.str(strings.Repeat("x", 50), 5); got != "xxxxx" {
		t.Fatalf("cap below the marker length: %q, want a plain cut", got)
	}
}

func TestCapReportText_EveryFieldAndList(t *testing.T) {
	huge := strings.Repeat("A", 2_000_000)
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = huge[:5000]
		}
		return out
	}
	report := &ctis.Report{Findings: []ctis.Finding{{
		Title: huge, Description: huge, Message: huge, Evidence: huge, RuleName: huge, Category: huge,
		References: many(1000), Tags: many(1000), VulnerabilityClass: many(1000), Subcategory: many(1000),
		Location:         &ctis.FindingLocation{Snippet: huge, ContextSnippet: huge},
		Remediation:      &ctis.Remediation{Recommendation: huge, FixCode: huge, Steps: many(1000), References: many(1000)},
		Misconfiguration: &ctis.MisconfigurationDetails{Expected: huge, Actual: huge, Cause: huge, Query: huge},
	}, {Title: "untouched", Tags: []string{"a"}}}}

	if n := capReportText(report); n == 0 {
		t.Fatal("nothing capped")
	}
	f := report.Findings[0]
	for name, c := range map[string]struct {
		v   string
		max int
	}{
		"title": {f.Title, MaxFindingTitleLen}, "description": {f.Description, MaxFindingDescriptionLen},
		"message": {f.Message, MaxFindingMessageLen}, "evidence": {f.Evidence, MaxFindingEvidenceLen},
		"rule_name": {f.RuleName, MaxFindingRuleNameLen}, "category": {f.Category, MaxFindingCategoryLen},
		"snippet": {f.Location.Snippet, MaxFindingSnippetLen}, "context_snippet": {f.Location.ContextSnippet, MaxFindingSnippetLen},
		"recommendation": {f.Remediation.Recommendation, MaxRemediationTextLen}, "fix_code": {f.Remediation.FixCode, MaxRemediationTextLen},
		"expected": {f.Misconfiguration.Expected, MaxMisconfigTextLen}, "actual": {f.Misconfiguration.Actual, MaxMisconfigTextLen},
		"cause": {f.Misconfiguration.Cause, MaxMisconfigTextLen}, "query": {f.Misconfiguration.Query, MaxMisconfigTextLen},
	} {
		if utf8.RuneCountInString(c.v) != c.max || !strings.HasSuffix(c.v, TruncationMarker) {
			t.Errorf("%s: %d runes, want %d ending with the marker", name, utf8.RuneCountInString(c.v), c.max)
		}
	}
	for name, c := range map[string]struct {
		v          []string
		items, max int
	}{
		"references": {f.References, MaxFindingReferences, MaxFindingReferenceLen},
		"tags":       {f.Tags, MaxFindingTags, MaxFindingTagLen},
		"classes":    {f.VulnerabilityClass, MaxFindingClasses, MaxFindingClassLen},
		"subcats":    {f.Subcategory, MaxFindingClasses, MaxFindingClassLen},
		"steps":      {f.Remediation.Steps, MaxRemediationSteps, MaxRemediationStepLen},
		"rem refs":   {f.Remediation.References, MaxFindingReferences, MaxFindingReferenceLen},
	} {
		if len(c.v) != c.items {
			t.Errorf("%s: %d items, want %d", name, len(c.v), c.items)
		}
		for _, s := range c.v {
			if utf8.RuneCountInString(s) > c.max {
				t.Errorf("%s: item of %d runes, cap %d", name, utf8.RuneCountInString(s), c.max)
				break
			}
		}
	}
	if g := report.Findings[1]; g.Title != "untouched" || len(g.Tags) != 1 {
		t.Fatalf("a finding within the caps changed: %+v", g)
	}
}

// A report may send a certificate's facts as free-form properties too; they
// win over the (capped) technical block, so they are capped as well.
func TestCapCertificateProperties(t *testing.T) {
	sans := make([]any, 500)
	for i := range sans {
		sans[i] = "h.example.com"
	}
	props := map[string]any{
		"subject_cn": strings.Repeat("x", 10_000) + "\x1b[31m",
		"issuer_cn":  "evil\nINFO forged",
		"sans":       sans,
		"not_after":  "2027-01-01T00:00:00Z",
	}
	if n := capCertificateProperties(props); n == 0 {
		t.Fatal("nothing changed")
	}
	if l := utf8.RuneCountInString(props["subject_cn"].(string)); l > MaxCertNameLen {
		t.Errorf("subject_cn %d runes", l)
	}
	if strings.ContainsAny(props["issuer_cn"].(string), "\n\x1b") {
		t.Errorf("issuer_cn kept control characters: %q", props["issuer_cn"])
	}
	if l := len(props["sans"].([]any)); l > MaxCertSANs {
		t.Errorf("%d SANs", l)
	}
	if props["not_after"] != "2027-01-01T00:00:00Z" {
		t.Error("an untouched key changed")
	}
}
