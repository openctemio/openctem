package bountyprogram

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func patterns(items []Item, inScope bool) []string {
	var out []string
	for _, it := range items {
		if it.InScope == inScope && it.Scannable() {
			out = append(out, it.Pattern)
		}
	}
	return out
}

func TestParseScopeFile_Burp(t *testing.T) {
	burp := `{"target":{"scope":{"advanced_mode":true,
	  "include":[
	    {"enabled":true,"host":"^.*\\.example\\.com$","protocol":"any"},
	    {"enabled":true,"host":"^api\\.example\\.org$","protocol":"https"},
	    {"enabled":true,"host":".*","protocol":"any"},
	    {"enabled":true,"host":"^.*$","protocol":"any"},
	    {"enabled":true,"host":"^10\\.0\\..*$","protocol":"any"},
	    {"enabled":true,"host":"^(www|app)\\.example\\.net$","protocol":"any"},
	    {"enabled":false,"host":"^disabled\\.example\\.com$"},
	    {"enabled":true,"prefix":"https://shop.example.io/api/"}
	  ],
	  "exclude":[{"enabled":true,"host":"^admin\\.example\\.com$"}]}}}`
	items, err := ParseScopeFile(ScopeFile{Format: FileFormatAuto, Content: burp})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	in := strings.Join(patterns(items, true), " ")
	for _, want := range []string{"*.example.com", "api.example.org", "https://shop.example.io/api*"} {
		if !strings.Contains(in, want) {
			t.Errorf("in scope %q lacks %q", in, want)
		}
	}
	// Never widened: ".*", "^.*$", an address expression and an
	// alternation are not entries; a disabled rule is dropped.
	for _, bad := range []string{"*", "10.0", "example.net", "disabled"} {
		for _, p := range patterns(items, true) {
			if p == bad || strings.Contains(p, bad) && bad != "*" {
				t.Errorf("widened to %q from %q", p, bad)
			}
		}
	}
	if got := patterns(items, false); len(got) != 1 || got[0] != "admin.example.com" {
		t.Errorf("out of scope = %v", got)
	}
	var other int
	for _, it := range items {
		if !it.Scannable() {
			other++
		}
	}
	if other != 4 {
		t.Errorf("not scannable = %d, want 4", other)
	}
}

func TestParseScopeFile_BurpMalformed(t *testing.T) {
	for _, c := range []string{`{`, `{"target":{}}`, `[]`} {
		if _, err := ParseScopeFile(ScopeFile{Format: FileFormatBurpJSON, Content: c}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q: err = %v, want validation", c, err)
		}
	}
}

func TestParseScopeFile_GenericCSV(t *testing.T) {
	csv := "Target,Kind,Eligible\nexample.com,domain,yes\n*.example.org,wildcard,true\ncom.example.app,android,yes\nold.example.com,domain,no\n"
	items, err := ParseScopeFile(ScopeFile{Format: FileFormatGenericCSV, Content: csv,
		Mapping: &ColumnMapping{Identifier: "target", Type: "Kind", InScope: "eligible"}})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := strings.Join(patterns(items, true), ","); got != "example.com,*.example.org" {
		t.Errorf("in scope = %s", got)
	}
	if got := patterns(items, false); len(got) != 1 || got[0] != "old.example.com" {
		t.Errorf("out of scope = %v", got)
	}
	// A mapping that names a missing column, or no mapping, is refused.
	for _, m := range []*ColumnMapping{nil, {Identifier: ""}, {Identifier: "nope"}, {Identifier: "target", Type: "missing"}} {
		if _, err := ParseScopeFile(ScopeFile{Format: FileFormatGenericCSV, Content: csv, Mapping: m}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("mapping %+v: err = %v", m, err)
		}
	}
}

func TestParseScopeFile_Bounds(t *testing.T) {
	big := strings.Repeat("a.example.com\n", MaxScopeTextBytes/14+10)
	if _, err := ParseScopeFile(ScopeFile{Format: FileFormatText, Content: big}); !errors.Is(err, ErrScopeTooLarge) {
		t.Errorf("oversized: err = %v", err)
	}
	var b strings.Builder
	b.WriteString(`{"target":{"scope":{"include":[`)
	for i := 0; i <= MaxScopeItems; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"host":"^h\\.example\\.com$"}`)
	}
	b.WriteString(`]}}}`)
	if _, err := ParseScopeFile(ScopeFile{Format: FileFormatBurpJSON, Content: b.String()}); !errors.Is(err, ErrScopeTooLarge) {
		t.Errorf("too many rules: err = %v", err)
	}
	if _, err := ParseScopeFile(ScopeFile{Format: "xlsx", Content: "x"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown format: err = %v", err)
	}
	if _, err := ParseScopeFile(ScopeFile{Format: FileFormatPlatformCSV, Content: "just.example.com\n"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("platform csv without header: err = %v", err)
	}
	// Only out-of-scope items: empty.
	if _, err := ParseScopeFile(ScopeFile{Format: FileFormatBurpJSON, Content: `{"target":{"scope":{"exclude":[{"host":"^a\\.example\\.com$"}]}}}`}); !errors.Is(err, ErrScopeEmpty) {
		t.Errorf("no in-scope: err = %v", err)
	}
}

func TestParseVisibilityAndTerms(t *testing.T) {
	if v, err := ParseVisibility(""); err != nil || v != VisibilityPrivate {
		t.Errorf("default visibility = %v %v", v, err)
	}
	if _, err := ParseVisibility("internal"); err == nil {
		t.Error("unknown visibility accepted")
	}
	if err := ValidateDetails("P", "", "", ""); err != nil {
		t.Errorf("empty program URL refused: %v", err)
	}
	if err := ValidateDetails("P", "", "", "http://x.example"); err == nil {
		t.Error("http program URL accepted")
	}
	base := NewTerms("", Rules{}, nil)
	if base.SHA256() != base.WithText("  ").SHA256() {
		t.Error("empty terms text changed the hash")
	}
	if base.SHA256() == base.WithText("NDA v2").SHA256() {
		t.Error("terms text not part of the hash")
	}
	if err := ValidateTermsText(strings.Repeat("x", MaxTermsText+1)); err == nil {
		t.Error("oversized terms accepted")
	}
}
