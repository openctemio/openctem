package scanident

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func uaList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("scanner/%d", i)
	}
	return out
}

// A list is validated by the shared contract rule; a layer sets a single
// User-Agent or a list, never both; CR/LF and other control characters,
// duplicates and more than 200 values are refused.
func TestCheckUserAgents(t *testing.T) {
	if err := CheckUserAgents("", uaList(200)); err != nil {
		t.Fatalf("200 values refused: %v", err)
	}
	bad := map[string]struct {
		single string
		list   []string
	}{
		"201 values":   {list: uaList(201)},
		"CR/LF":        {list: []string{"ok", "evil\r\nX-Injected: 1"}},
		"LF":           {list: []string{"a\nb"}},
		"NUL":          {list: []string{"a\x00"}},
		"non-ASCII":    {list: []string{"Ünicode"}},
		"too long":     {list: []string{strings.Repeat("u", 257)}},
		"duplicate":    {list: []string{"a", "b", "a"}},
		"empty value":  {list: []string{"a", ""}},
		"both":         {single: "one", list: []string{"a", "b"}},
		"single CR/LF": {single: "a\r\nb"},
	}
	for name, c := range bad {
		if err := CheckUserAgents(c.single, c.list); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s accepted (%v)", name, err)
		}
	}
	if err := CheckUserAgents("one", []string{"a", "b"}); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("the both-set error does not name the fix: %v", err)
	}
}

func TestCheckQuery(t *testing.T) {
	for _, q := range []*Query{nil, {Name: "scan", Value: "corp-42"}, {Name: "a.b_c~d-e", Value: strings.Repeat("v", 64)}} {
		if err := CheckQuery(q); err != nil {
			t.Errorf("%+v: %v", q, err)
		}
	}
	for _, q := range []*Query{{Name: "", Value: "v"}, {Name: "n", Value: ""}, {Name: "a b", Value: "v"}, {Name: "n", Value: "a&b=c"},
		{Name: "n", Value: "x\r\ny"}, {Name: strings.Repeat("n", 65), Value: "v"}, {Name: "n", Value: "%41"}} {
		if err := CheckQuery(q); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v accepted (%v)", q, err)
		}
	}
}

func TestPlatformLayerNormalizeValidate(t *testing.T) {
	p := PlatformLayer{UserAgents: []string{" a ", "", "b"}, UserAgentEnforced: true, Query: &Query{Name: " scan ", Value: " 1 "}, QueryEnforced: true}.Normalized()
	if !slices.Equal(p.UserAgents, []string{"a", "b"}) || !p.UserAgentEnforced || p.Query.Name != "scan" || p.Query.Value != "1" {
		t.Fatalf("normalized %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	// Nothing to enforce: the lock drops.
	if n := (PlatformLayer{UserAgentEnforced: true, QueryEnforced: true, Query: &Query{}}).Normalized(); n.UserAgentEnforced || n.QueryEnforced || n.Query != nil {
		t.Fatalf("empty layer keeps locks: %+v", n)
	}
	if err := (PlatformLayer{UserAgent: "x", UserAgents: []string{"a", "b"}}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("both accepted: %v", err)
	}
	if err := (PlatformLayer{Query: &Query{Name: "a b", Value: "v"}}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad query accepted: %v", err)
	}
}

// The winning layer's list is used whole; precedence enforced platform >
// organization > platform default; the query follows the same order without
// programs; required is the OR of the layers and records who asked.
func TestMergeRotationQueryRequired(t *testing.T) {
	plat := PlatformLayer{UserAgents: []string{"p1", "p2"}, Query: &Query{Name: "scan", Value: "plat"}, IdentificationRequired: true}
	org := OrganizationLayer{UserAgents: []string{"o1", "o2", "o3"}, Query: &Query{Name: "scan", Value: "org"}}
	e := Merge(plat, org)
	if !slices.Equal(e.UserAgents, []string{"o1", "o2", "o3"}) || e.UserAgent != "o1" || e.UserAgentSource != SourceOrganization || e.UserAgentLocked {
		t.Fatalf("organization list not used whole: %+v", e)
	}
	if e.Query == nil || e.Query.Value != "org" || e.QuerySource != SourceOrganization || e.QueryLocked {
		t.Fatalf("query %+v", e)
	}
	if !e.IdentificationRequired || !slices.Equal(e.RequiredBy, []string{SourcePlatform}) {
		t.Fatalf("required %+v", e)
	}

	// Enforced: the platform's list and query win and are locked.
	plat.UserAgentEnforced, plat.QueryEnforced = true, true
	e = Merge(plat, org)
	if !slices.Equal(e.UserAgents, []string{"p1", "p2"}) || e.UserAgentSource != SourcePlatformEnforced || !e.UserAgentLocked {
		t.Fatalf("enforced list %+v", e)
	}
	if e.Query.Value != "plat" || e.QuerySource != SourcePlatformEnforced || !e.QueryLocked {
		t.Fatalf("enforced query %+v", e)
	}

	// An organization's single value still beats a platform default list,
	// and is carried as a one-value list.
	e = Merge(PlatformLayer{UserAgents: []string{"p1", "p2"}}, OrganizationLayer{UserAgent: "corp"})
	if e.UserAgent != "corp" || !slices.Equal(e.UserAgents, []string{"corp"}) {
		t.Fatalf("single %+v", e)
	}
	// Platform default used when the organization sets nothing.
	e = Merge(PlatformLayer{UserAgents: []string{"p1", "p2"}, Query: &Query{Name: "s", Value: "p"}}, OrganizationLayer{IdentificationRequired: true})
	if !slices.Equal(e.UserAgents, []string{"p1", "p2"}) || e.UserAgentSource != SourcePlatform || e.QuerySource != SourcePlatform {
		t.Fatalf("default %+v", e)
	}
	if !e.IdentificationRequired || !slices.Equal(e.RequiredBy, []string{SourceOrganization}) {
		t.Fatalf("organization required %+v", e)
	}
	// Both require it: both are named.
	e = Merge(PlatformLayer{IdentificationRequired: true}, OrganizationLayer{IdentificationRequired: true})
	if !slices.Equal(e.RequiredBy, []string{SourcePlatform, SourceOrganization}) {
		t.Fatalf("required by %v", e.RequiredBy)
	}
	if e.HasIdentification() {
		t.Fatal("no header and no query reported as identification")
	}
	if !Merge(PlatformLayer{Query: &Query{Name: "s", Value: "v"}}, OrganizationLayer{}).HasIdentification() {
		t.Fatal("a query parameter is identification")
	}
}

// A program's list replaces the merged one whole (unless enforced) and
// locks it; its required flag can only add, never clear.
func TestOverlayProgramListAndRequired(t *testing.T) {
	base := Merge(PlatformLayer{IdentificationRequired: true}, OrganizationLayer{UserAgents: []string{"o1", "o2"}})
	got, err := base.Overlay(OverlayLayer{UserAgents: []string{"b1", "b2"}}, SourceProgram)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.UserAgents, []string{"b1", "b2"}) || got.UserAgent != "b1" || !got.UserAgentLocked || got.UserAgentSource != SourceProgram {
		t.Fatalf("program list %+v", got)
	}
	if !got.IdentificationRequired {
		t.Fatal("a program without the flag cleared the requirement")
	}
	got, _ = Merge(PlatformLayer{}, OrganizationLayer{}).Overlay(OverlayLayer{IdentificationRequired: true}, SourceProgram)
	if !got.IdentificationRequired || !slices.Equal(got.RequiredBy, []string{SourceProgram}) {
		t.Fatalf("program required %+v", got)
	}
	enforced := Merge(PlatformLayer{UserAgents: []string{"p1", "p2"}, UserAgentEnforced: true}, OrganizationLayer{})
	got, _ = enforced.Overlay(OverlayLayer{UserAgents: []string{"b1"}}, SourceProgram)
	if !slices.Equal(got.UserAgents, []string{"p1", "p2"}) {
		t.Fatalf("program replaced an enforced list: %+v", got)
	}
	// The receiver is unchanged.
	if !slices.Equal(base.UserAgents, []string{"o1", "o2"}) {
		t.Fatal("overlay changed its receiver")
	}
}
