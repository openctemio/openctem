package scope_test

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNormalizeConstraint(t *testing.T) {
	c, err := scope.NormalizeConstraint(scope.TargetTypeDomain, []string{"8443", "80,443", "442-444"}, "TCP")
	if err != nil || c.Ports != "80,442-444,8443" || c.Protocol != "tcp" {
		t.Fatalf("got %+v %v", c, err)
	}
	if c, err := scope.NormalizeConstraint(scope.TargetTypeDomain, nil, ""); err != nil || !c.IsZero() {
		t.Fatalf("empty: %+v %v", c, err)
	}
	for name, in := range map[string]struct {
		t     scope.TargetType
		ports []string
		proto string
	}{
		"port 0":          {scope.TargetTypeDomain, []string{"0"}, ""},
		"port too high":   {scope.TargetTypeDomain, []string{"65536"}, ""},
		"reversed range":  {scope.TargetTypeDomain, []string{"90-80"}, ""},
		"named list":      {scope.TargetTypeDomain, []string{"top-100"}, ""},
		"bad protocol":    {scope.TargetTypeDomain, []string{"80"}, "sctp"},
		"url entry":       {scope.TargetTypeURL, []string{"443"}, ""},
		"repository type": {scope.TargetTypeRepository, nil, "tcp"},
	} {
		if _, err := scope.NormalizeConstraint(in.t, in.ports, in.proto); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A port-limited entry covers only targets that name an allowed port: never
// the bare host, so a full port scan of the host is refused.
func TestEntryMatches_PortLimited(t *testing.T) {
	c := scope.Constraint{Ports: "8443", Protocol: "tcp"}
	cases := map[string]bool{
		"api.example.com":              false, // the whole host
		"api.example.com:8443":         true,
		"api.example.com:8443/tcp":     true,
		"api.example.com:8443/udp":     false,
		"api.example.com:22":           false,
		"https://api.example.com:8443": true,
		"https://api.example.com/":     false, // 443
		"other.example.com:8443":       false,
	}
	for target, want := range cases {
		if got := scope.EntryMatches(scope.TargetTypeDomain, "api.example.com", c, target); got != want {
			t.Errorf("%s: got %v, want %v", target, got, want)
		}
	}
	wild := scope.Constraint{Ports: "443"}
	if !scope.EntryMatches(scope.TargetTypeDomain, "*.example.com", wild, "https://www.example.com/x") {
		t.Error("wildcard with default https port not covered")
	}
	ip := scope.Constraint{Ports: "22"}
	if scope.EntryMatches(scope.TargetTypeIPAddress, "203.0.113.5", ip, "203.0.113.5") ||
		!scope.EntryMatches(scope.TargetTypeIPAddress, "203.0.113.5", ip, "203.0.113.5:22") {
		t.Error("ip port limit")
	}
	cidr := scope.Constraint{Ports: "80"}
	if scope.EntryMatches(scope.TargetTypeCIDR, "203.0.113.0/24", cidr, "203.0.113.0/24") ||
		!scope.EntryMatches(scope.TargetTypeCIDR, "203.0.113.0/24", cidr, "203.0.113.9:80") {
		t.Error("cidr port limit")
	}
	udp := scope.Constraint{Protocol: "udp"}
	if scope.EntryMatches(scope.TargetTypeDomain, "dns.example.com", udp, "dns.example.com:53") ||
		!scope.EntryMatches(scope.TargetTypeDomain, "dns.example.com", udp, "dns.example.com:53/udp") {
		t.Error("udp-only limit")
	}
}

// A URL entry with a path covers only URLs under the path, segment by
// segment, without dot segments.
func TestEntryMatches_PathLimited(t *testing.T) {
	const pattern = "https://shop.example.com/api*"
	if !scope.URLPathLimited(scope.TargetTypeURL, pattern) || scope.URLPathLimited(scope.TargetTypeURL, "https://shop.example.com/*") {
		t.Fatal("path limit detection")
	}
	cases := map[string]bool{
		"https://shop.example.com/api":              true,
		"https://shop.example.com/api/":             true,
		"https://shop.example.com/api/v1/items?x=1": true,
		"https://shop.example.com/apiadmin":         false,
		"https://shop.example.com/admin":            false,
		"https://shop.example.com/api/../admin":     false,
		"https://shop.example.com/api/%2e%2e/admin": false,
		"https://shop.example.com/api/%2E%2E/admin": false,
		"https://shop.example.com":                  false,
		"shop.example.com":                          false,
		"http://shop.example.com/api":               false,
		"https://shop.example.com:8443/api":         false,
		"https://evil.example.com/api":              false,
		"https://user@shop.example.com/api":         false,
	}
	for target, want := range cases {
		if got := scope.EntryMatches(scope.TargetTypeURL, pattern, scope.Constraint{}, target); got != want {
			t.Errorf("%s: got %v, want %v", target, got, want)
		}
	}
}

func TestConstrainedJobRefusal(t *testing.T) {
	ports := []scope.Constraint{{Ports: "8443", Protocol: "tcp"}}
	cases := []struct {
		name     string
		tool     string
		cs       []scope.Constraint
		path     bool
		jobPorts string
		top      bool
		want     string
	}{
		{"port scan of the allowed port", "naabu", ports, false, "8443", false, ""},
		{"port scan without a list", "naabu", ports, false, "", false, scope.ConstrainedPortsOutside},
		{"full port scan", "naabu", ports, false, "1-65535", false, scope.ConstrainedPortsOutside},
		{"another port", "naabu", ports, false, "22", false, scope.ConstrainedPortsOutside},
		{"top ports", "naabu", ports, false, "", true, scope.ConstrainedPortsOutside},
		{"named list", "naabu", ports, false, "full", false, scope.ConstrainedPortsOutside},
		{"http probe", "httpx", ports, false, "", false, ""},
		{"template scanner", "nuclei", ports, false, "", false, scope.ConstrainedToolRefused},
		{"crawler on a path", "katana", nil, true, "", false, scope.ConstrainedToolRefused},
		{"http probe on a path", "httpx", nil, true, "", false, ""},
		{"port list on a path", "httpx", nil, true, "80", false, scope.ConstrainedPortsOutside},
		{"port scanner on a path", "naabu", nil, true, "443", false, scope.ConstrainedToolRefused},
	}
	for _, c := range cases {
		if got := scope.ConstrainedJobRefusal(c.tool, c.cs, c.path, c.jobPorts, c.top); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if !scope.ConstrainedToolAllowed("httpx", true, true) || scope.ConstrainedToolAllowed("nuclei", true, false) ||
		scope.ConstrainedToolAllowed("katana", false, true) || !scope.ConstrainedToolAllowed("nuclei", false, false) {
		t.Error("ConstrainedToolAllowed")
	}
}

func TestTargetConstraint(t *testing.T) {
	tid := shared.NewID()
	tg, err := scope.NewTarget(tid, scope.TargetTypeDomain, "api.example.com", "", "u")
	if err != nil {
		t.Fatal(err)
	}
	if err := tg.SetConstraint(scope.Constraint{Ports: "8443,80", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if tg.Constraint().Ports != "80,8443" || !tg.Constrained() {
		t.Fatalf("constraint = %+v", tg.Constraint())
	}
	if tg.Matches("api.example.com") || !tg.Matches("api.example.com:80") {
		t.Fatal("Target.Matches ignores the limit")
	}
	if err := tg.SetConstraint(scope.Constraint{Ports: "x"}); err == nil {
		t.Fatal("invalid limit accepted")
	}
}
