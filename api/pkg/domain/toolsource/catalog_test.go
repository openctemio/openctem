package toolsource

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Source ids are credential names of the tool contract.
var credName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	cat := Catalog()
	if len(cat) == 0 || len(cat) > 64 {
		t.Fatalf("catalog has %d sources (a manifest declares at most 64 credentials)", len(cat))
	}
	for _, s := range cat {
		if !credName.MatchString(s.ID) || seen[s.ID] || s.Name == "" || len(s.Tools) == 0 {
			t.Errorf("source %+v", s)
		}
		if (s.Format == FormatPair) != (s.PairHint != "") {
			t.Errorf("source %s: format %s hint %q", s.ID, s.Format, s.PairHint)
		}
		seen[s.ID] = true
	}
	if len(ForTool(ToolSubfinder)) != len(cat) || len(ForTool("nuclei")) != 0 {
		t.Fatal("ForTool")
	}
	// Catalog returns copies.
	cat[0].Tools[0] = "changed"
	if Catalog()[0].Tools[0] == "changed" {
		t.Fatal("catalog mutable through Catalog")
	}
}

func TestValidateValue(t *testing.T) {
	single, _ := Lookup("securitytrails")
	pairSrc, _ := Lookup("censys")
	for _, c := range []struct {
		src Source
		v   string
		ok  bool
	}{
		{single, "abcDEF0123456789", true},
		{single, "with:colon:ok", true},
		{single, "", false},
		{single, "has space", false},
		{single, "line\nbreak", false},
		{single, "tab\tkey", false},
		{single, "ünicode", false},
		{single, strings.Repeat("a", MaxValueLen+1), false},
		{pairSrc, "token:org", true},
		{pairSrc, "token", false},
		{pairSrc, ":org", false},
		{pairSrc, "token:", false},
		{pairSrc, "a:b:c", false},
	} {
		err := c.src.ValidateValue(c.v)
		if (err == nil) != c.ok {
			t.Errorf("%s %q: %v", c.src.ID, c.v, err)
		}
		if err != nil && !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q: not a validation error: %v", c.v, err)
		}
		if err != nil && c.v != "" && strings.Contains(err.Error(), c.v) {
			t.Errorf("the error repeats the key: %v", err)
		}
	}
}

func TestLast4(t *testing.T) {
	if Last4("short-key") != "" || Last4("0123456789abcdef") != "cdef" {
		t.Fatal("Last4")
	}
}

func TestJobMayUse(t *testing.T) {
	for _, c := range []struct {
		jobTool, capability, tool string
		want                      bool
	}{
		{"subfinder", "", "subfinder", true},
		{"subfinder", "", "nuclei", false},
		{"nuclei", "", "subfinder", false},
		{"", "discover.subdomains@1", "subfinder", true},
		{"", "scan.ports@1", "subfinder", false},
		{"", "", "subfinder", false},
		{"semgrep", "", "semgrep", false},
		{"", "discover.subdomains@1", "", false},
	} {
		if got := JobMayUse(c.jobTool, c.capability, c.tool); got != c.want {
			t.Errorf("JobMayUse(%q, %q, %q) = %v", c.jobTool, c.capability, c.tool, got)
		}
	}
}
