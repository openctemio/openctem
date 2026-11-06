package scope

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/contract/webpath"
)

// pathTable is one table the platform's PathUnder and the sensor's
// webpath.Denied both run on: every path PathUnder puts under an
// exclusion must be refused by the sensor, for the deny path the job
// carries (cut at "*", for sensors before contract 1.3.1) and for the
// prefix itself (sensors with segment wildcards).
var pathTable = []struct {
	path, prefix string
	under        bool
}{
	{"/admin", "/admin", true},
	{"/admin/x", "/admin", true},
	{"/administrator", "/admin", false},
	{"/public", "/admin", false},
	{"/tenants/acme/admin", "/tenants/*/admin", true},
	{"/tenants/acme/admin/x/y", "/tenants/*/admin", true},
	{"/tenants/acme/users", "/tenants/*/admin", false},
	{"/tenants/admin", "/tenants/*/admin", false},
	{"/a/b/c/d", "/a/*/*/d", true},
	{"/a/b/d", "/a/*/*/d", false},
	{"/files/My Docs/a.bak", "/files/My Docs", true},
	{"/files/Other", "/files/My Docs", false},
	{"/x", "/", true},
	{"/api/v1/users", "/*/v1", true},
}

func TestPathUnderAndSensorDeniedAgree(t *testing.T) {
	for _, c := range pathTable {
		if got := PathUnder(c.path, c.prefix); got != c.under {
			t.Errorf("PathUnder(%q, %q) = %v, want %v", c.path, c.prefix, got, c.under)
		}
		if !c.under {
			continue
		}
		clean, err := webpath.CleanPath(c.path)
		if err != nil {
			t.Fatalf("CleanPath(%q): %v", c.path, err)
		}
		if _, ok := webpath.Denied(clean, JobDenyPaths(c.prefix)); !ok {
			t.Errorf("job deny paths %q of %q let the sensor send %q", JobDenyPaths(c.prefix), c.prefix, c.path)
		}
		if _, ok := webpath.Denied(clean, []string{c.prefix}); !ok {
			t.Errorf("deny path %q lets the sensor send %q", c.prefix, c.path)
		}
		// Every spelling a server reads as the path is refused as well.
		for _, raw := range []string{strings.ToUpper(c.path), strings.ReplaceAll(c.path, " ", "%20"), c.path + "./x"} {
			if v, err := webpath.CleanPath(raw); err == nil {
				if _, ok := webpath.Denied(v, JobDenyPaths(c.prefix)); !ok {
					t.Errorf("%q (a spelling of %q) passes %q", raw, c.path, JobDenyPaths(c.prefix))
				}
			}
		}
	}
}

// An exclusion written with a percent-escape is stored decoded, so it
// denies what the sensor compares: the decoded request path.
func TestNormalizePathPrefixDecodes(t *testing.T) {
	ok := map[string]string{
		"/files/My%20Docs":  "/files/My Docs",
		"/%61dmin/":         "/admin",
		"/tenants/*/admin":  "/tenants/*/admin",
		"/tenants/%2A/x":    "/tenants/*/x",
		"/files/My Docs/":   "/files/My Docs",
		"/caf%C3%A9/menu/*": "/café/menu",
	}
	for in, want := range ok {
		got, err := NormalizePathPrefix(in)
		if err != nil || got != want {
			t.Errorf("NormalizePathPrefix(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"/a/%2e%2e/b", "/a/%2E/b", "/a%zz", "/a%0d%0a", "/adm%2An", "/a%FF", "/100%25", "/x/%2561"} {
		if _, err := NormalizePathPrefix(bad); err == nil {
			t.Errorf("NormalizePathPrefix(%q) accepted", bad)
		}
	}
}

func TestJobDenyPaths(t *testing.T) {
	cases := map[string][]string{
		"/admin":            {"/admin"},
		"/tenants/*/admin":  {"/tenants/"},
		"/*/admin":          {"/"},
		"/files/My%20Docs":  {"/files/My%20Docs", "/files/My Docs"},
		"/files/My Docs":    {"/files/My Docs"},
		"/100%":             {"/100%"},
		"/x/%2561":          {"/x/%2561"},
		"/a%2Fb":            {"/a%2Fb"},
		"/x/100%41/*/admin": {"/x/100%41/", "/x/100A/"},
	}
	for in, want := range cases {
		if got := JobDenyPaths(in); !slices.Equal(got, want) {
			t.Errorf("JobDenyPaths(%q) = %q, want %q", in, got, want)
		}
	}
}

// The ingest check reads an endpoint path as written and decoded, and a
// prefix stored escaped before prefixes were decoded still holds.
func TestBlocksReadsDecodedAndCase(t *testing.T) {
	now := time.Now()
	for _, prefix := range []string{"/files/My Docs", "/files/My%20Docs"} {
		r := &WebRule{PathPrefix: prefix, Testing: TestingBlocked}
		for _, p := range []string{"/files/My Docs/a.bak", "/files/My%20Docs/a.bak", "/FILES/my docs"} {
			if !r.Blocks("GET", p, now) {
				t.Errorf("rule %q does not block %q", prefix, p)
			}
		}
		if r.Blocks("GET", "/files/other", now) {
			t.Errorf("rule %q blocks /files/other", prefix)
		}
	}
	w := &WebRule{PathPrefix: "/tenants/*/admin", Testing: TestingBlocked}
	if !w.Blocks("GET", "/Tenants/acme/Admin/x", now) || w.Blocks("GET", "/tenants/acme/users", now) {
		t.Error("wildcard rule")
	}
}
