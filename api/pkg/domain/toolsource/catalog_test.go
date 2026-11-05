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
		{single, "short7c", false},
		{single, "", false},
		{single, "has space", false},
		{single, "line\nbreak", false},
		{single, "tab\tkey", false},
		{single, "ünicode", false},
		{single, strings.Repeat("a", MaxValueLen+1), false},
		{pairSrc, "token:org-0001", true},
		{pairSrc, "token:org", false}, // secret part shorter than 8
		{pairSrc, "token", false},
		{pairSrc, ":org-0001", false},
		{pairSrc, "token:", false},
		{pairSrc, "a:b:c-0001", false},
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
	single, _ := Lookup("shodan")
	pairSrc, _ := Lookup("domainsproject")
	if single.Last4("short-key-01") != "y-01" || single.Last4("short-key") != "" || single.Last4("0123456789abcdef") != "cdef" {
		t.Fatal("Last4 of a key")
	}
	// A pair shows only the tail of its secret part, and only a long one.
	if got := pairSrc.Last4("someuser-name-long:pass-word"); got != "" {
		t.Fatalf("short secret part shown: %q", got)
	}
	if got := pairSrc.Last4("u:0123456789abcdef"); got != "cdef" {
		t.Fatalf("pair Last4 %q", got)
	}
	if got := pairSrc.Last4("long-user-name-1234:x2345678"); got != "" {
		t.Fatalf("user name tail shown: %q", got)
	}
}

// Sources whose first part names where the tool connects accept their own
// service only: never an IP address, a port, user information or another
// host (a shared sensor must not be pointed at an address of a tenant's
// choice).
func TestEndpointSources(t *testing.T) {
	intelx, _ := Lookup("intelx")
	zoomeye, _ := Lookup("zoomeyeapi")
	rhl, _ := Lookup("redhuntlabs")
	const k = "abcdef0123456789"
	for _, c := range []struct {
		src Source
		v   string
		ok  bool
	}{
		{intelx, "2.intelx.io:" + k, true},
		{intelx, "free.intelx.io:" + k, true},
		{intelx, "intelx.io:" + k, true},
		{intelx, "10.0.0.5:" + k, false},
		{intelx, "127.0.0.1:" + k, false},
		{intelx, "[::1]:" + k, false},
		{intelx, "169.254.169.254:" + k, false},
		{intelx, "evil.com:" + k, false},
		{intelx, "intelx.io.evil.com:" + k, false},
		{intelx, "evilintelx.io:" + k, false},
		{intelx, "user@2.intelx.io:" + k, false},
		{intelx, "2.intelx.io:8443:" + k, false},
		{intelx, "2.INTELX.IO:" + k, false},
		{intelx, "localhost:" + k, false},
		{zoomeye, "zoomeye.ai:" + k, true},
		{zoomeye, "zoomeye.hk:" + k, true},
		{zoomeye, "evil.zoomeye.ai:" + k, false},
		{zoomeye, "10.0.0.5:" + k, false},
		{rhl, "https://reconapi.redhuntlabs.com/community/v1/domains/subdomains:" + k, true},
		{rhl, "http://reconapi.redhuntlabs.com/x:" + k, false},
		{rhl, "https://10.0.0.5/x:" + k, false},
		{rhl, "https://evil.com/x:" + k, false},
		{rhl, "https://reconapi.redhuntlabs.com.evil.com/x:" + k, false},
		{rhl, "https://reconapi.redhuntlabs.com:8443/x:" + k, false},
		{rhl, "https://user@reconapi.redhuntlabs.com/x:" + k, false},
		{rhl, "https://reconapi.redhuntlabs.com/x?u=1:" + k, false},
		{rhl, "https://reconapi.redhuntlabs.com/x#f:" + k, false},
		{rhl, "https://reconapi.redhuntlabs.com/x", false},
	} {
		if err := c.src.ValidateValue(c.v); (err == nil) != c.ok {
			t.Errorf("%s %q: %v", c.src.ID, c.v, err)
		}
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
