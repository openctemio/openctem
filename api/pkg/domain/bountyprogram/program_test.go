package bountyprogram

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func find(items []Item, raw string) (Item, bool) {
	for _, it := range items {
		if it.Raw == raw {
			return it, true
		}
	}
	return Item{}, false
}

func TestParseScope_Text(t *testing.T) {
	text := `In scope:
* *.example.com
- legacy.example.com   # retired
https://app.example.org/
https://example.org/api/*
192.0.2.10
198.51.100.0/24
203.0.113.1-203.0.113.9
com.example.android
api-*.example.net
• shop.example.net

Out of scope
admin.example.com
`
	items, err := ParseScope(text)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		raw     string
		in      bool
		kind    Kind
		typ     scope.TargetType
		pattern string
	}{
		{"*.example.com", true, KindWildcard, scope.TargetTypeDomain, "*.example.com"},
		{"legacy.example.com", false, KindDomain, scope.TargetTypeDomain, "legacy.example.com"},
		{"https://app.example.org/", true, KindDomain, scope.TargetTypeDomain, "app.example.org"},
		{"https://example.org/api/*", true, KindURL, scope.TargetTypeURL, "https://example.org/api*"},
		{"192.0.2.10", true, KindIP, scope.TargetTypeIPAddress, "192.0.2.10"},
		{"198.51.100.0/24", true, KindCIDR, scope.TargetTypeCIDR, "198.51.100.0/24"},
		{"203.0.113.1-203.0.113.9", true, KindCIDR, scope.TargetTypeIPRange, "203.0.113.1-203.0.113.9"},
		{"shop.example.net", true, KindDomain, scope.TargetTypeDomain, "shop.example.net"},
		{"admin.example.com", false, KindDomain, scope.TargetTypeDomain, "admin.example.com"},
	}
	for _, c := range cases {
		it, ok := find(items, c.raw)
		if !ok {
			t.Fatalf("%s not parsed: %+v", c.raw, items)
		}
		if it.InScope != c.in || it.Kind != c.kind || it.TargetType != c.typ || it.Pattern != c.pattern {
			t.Errorf("%s: got %+v", c.raw, it)
		}
	}
	// A wildcard inside a name is kept but not scannable. A dotted app id
	// without a type reads as a name (the CSV type decides otherwise).
	if it, _ := find(items, "api-*.example.net"); it.Scannable() {
		t.Errorf("a mid-name wildcard must not be scannable: %+v", it)
	}
}

func TestParseScope_CSV(t *testing.T) {
	csv := "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission\n" +
		"*.example.com,WILDCARD,,true,true\n" +
		"com.example.app,GOOGLE_PLAY_APP_ID,,true,true\n" +
		"https://github.com/example/repo,SOURCE_CODE,,true,true\n" +
		"status.example.com,URL,,false,false\n"
	items, err := ParseScope(csv)
	if err != nil {
		t.Fatal(err)
	}
	if it, _ := find(items, "*.example.com"); !it.InScope || it.Kind != KindWildcard {
		t.Errorf("wildcard: %+v", it)
	}
	if it, _ := find(items, "com.example.app"); it.Scannable() || it.AssetType != "GOOGLE_PLAY_APP_ID" {
		t.Errorf("an app id must stay not scannable: %+v", it)
	}
	if it, _ := find(items, "https://github.com/example/repo"); it.Scannable() {
		t.Errorf("source code must stay not scannable: %+v", it)
	}
	if it, _ := find(items, "status.example.com"); it.InScope {
		t.Errorf("eligible_for_submission=false is out of scope: %+v", it)
	}
}

func TestParseScope_TSVAndBounds(t *testing.T) {
	tsv := "asset_identifier\tasset_type\teligible_for_submission\nexample.com\tURL\ttrue\n"
	items, err := ParseScope(tsv)
	if err != nil || len(items) != 1 || items[0].Pattern != "example.com" {
		t.Fatalf("tsv: %+v %v", items, err)
	}
	if _, err := ParseScope("Out of scope\nexample.com\n"); !errors.Is(err, ErrScopeEmpty) {
		t.Fatalf("no in-scope item: %v", err)
	}
	if _, err := ParseScope(strings.Repeat("a.example.com\n", MaxScopeTextBytes/14+10)); !errors.Is(err, ErrScopeTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	if _, err := ParseScope("identifier,asset_type\n"); !errors.Is(err, ErrScopeEmpty) {
		t.Fatalf("header only: %v", err)
	}
	if _, err := ParseScope("name,asset_type\nx.example.com,URL\n"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a CSV without an identifier column must be refused: %v", err)
	}
	// Duplicates collapse; the same name in and out stays twice.
	items, _ = ParseScope("a.example.com\na.example.com\n-a.example.com\n")
	if len(items) != 2 {
		t.Fatalf("dedupe: %+v", items)
	}
}

func TestPlanScope_ApexAndExclusions(t *testing.T) {
	items, err := ParseScope("*.example.com\n*.example.org\nexample.org\n-dev.example.org\n")
	if err != nil {
		t.Fatal(err)
	}
	p := PlanScope(items)
	if len(p.Entries) != 3 {
		t.Fatalf("entries: %+v", p.Entries)
	}
	var apex, oos bool
	for _, e := range p.Exclusions {
		switch {
		case e.Pattern == "example.com" && e.Reason == ReasonApexNotListed:
			apex = true
		case e.Pattern == "example.org":
			t.Errorf("a listed apex must not be excluded")
		case e.Pattern == "dev.example.org" && e.Reason == ReasonOutOfScope:
			oos = true
		}
	}
	if !apex || !oos {
		t.Fatalf("exclusions: %+v", p.Exclusions)
	}
}

func TestRules_Validate(t *testing.T) {
	ok := Rules{RateLimitRPS: 5, RequiredHeaders: []Header{{Name: "X-Bug-Bounty", Value: "jdoe"}},
		UserAgent: "jdoe-research", Forbidden: []string{"dos"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Rules{
		{RateLimitRPS: -1},
		{RateLimitRPS: MaxRateLimitRPS + 1},
		{RequiredHeaders: []Header{{Name: "X-A\r\nX-Injected", Value: "v"}}},
		{RequiredHeaders: []Header{{Name: "X-A", Value: "v\r\nSet-Cookie: x"}}},
		{RequiredHeaders: []Header{{Name: "", Value: "v"}}},
		{UserAgent: "ua\nX: y"},
		{Forbidden: []string{"everything"}},
		{Notes: strings.Repeat("n", MaxNotes+1)},
	}
	for i, r := range bad {
		if err := r.Normalize().Validate(); err == nil {
			t.Errorf("case %d must be refused: %+v", i, r)
		}
	}
	if got := (Rules{Forbidden: []string{"automated_scanning"}}).MaxTier(); got != scope.TierPassive {
		t.Errorf("automated scanning forbidden: tier %v", got)
	}
	if got := (Rules{}).MaxTier(); got != scope.TierActive {
		t.Errorf("default tier %v", got)
	}
}

func TestTerms_Hash(t *testing.T) {
	items, _ := ParseScope("a.example.com\nb.example.com\n-c.example.com\n")
	reordered, _ := ParseScope("b.example.com\n-c.example.com\na.example.com\n")
	r1 := Rules{Forbidden: []string{"dos", "physical"}}
	r2 := Rules{Forbidden: []string{"physical", "dos", "DOS"}}
	h1 := NewTerms("https://p.example/policy", r1, items).SHA256()
	if h2 := NewTerms("https://p.example/policy", r2, reordered).SHA256(); h1 != h2 {
		t.Fatal("the hash must not depend on order or case of the forbidden list")
	}
	changed, _ := ParseScope("a.example.com\nb.example.com\n")
	if NewTerms("https://p.example/policy", r1, changed).SHA256() == h1 {
		t.Fatal("dropping an out-of-scope item must change the hash")
	}
	if NewTerms("https://p.example/policy", Rules{RateLimitRPS: 1, Forbidden: r1.Forbidden}, items).SHA256() == h1 {
		t.Fatal("changing the rules must change the hash")
	}
	if NewTerms("https://other.example/policy", r1, items).SHA256() == h1 {
		t.Fatal("changing the program URL must change the hash")
	}
	if len(h1) != 64 {
		t.Fatalf("hash %q", h1)
	}
}

func TestValidateDetails(t *testing.T) {
	if err := ValidateDetails("Acme", "self-hosted", "jdoe", "https://acme.example/security"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"http://acme.example/", "javascript:alert(1)", "https://user:pw@acme.example/", "", "https://"} {
		if err := ValidateDetails("Acme", "", "", u); err == nil {
			t.Errorf("url %q must be refused", u)
		}
	}
	if err := ValidateDetails(" ", "", "", "https://a.example/"); err == nil {
		t.Error("an empty name must be refused")
	}
}
