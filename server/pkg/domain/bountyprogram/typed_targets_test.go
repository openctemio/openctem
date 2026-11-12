package bountyprogram

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
)

// A target limited to a port becomes an entry of its host limited to that
// port; the port is never dropped (that would authorize the whole host).
func TestClassify_ServiceTargetsKeepTheirPort(t *testing.T) {
	cases := []struct {
		raw             string
		typ             scope.TargetType
		pattern         string
		ports, protocol string
	}{
		{"api.example.com:8443/tcp", scope.TargetTypeDomain, "api.example.com", "8443", "tcp"},
		{"api.example.com:8443", scope.TargetTypeDomain, "api.example.com", "8443", "tcp"},
		{"dns.example.com:53/udp", scope.TargetTypeDomain, "dns.example.com", "53", "udp"},
		{"203.0.113.5:22", scope.TargetTypeIPAddress, "203.0.113.5", "22", "tcp"},
		{"[2001:db8::1]:443", scope.TargetTypeIPAddress, "2001:db8::1", "443", "tcp"},
		{"https://api.example.com:8443", scope.TargetTypeDomain, "api.example.com", "8443", "tcp"},
		{"https://api.example.com:8443/", scope.TargetTypeDomain, "api.example.com", "8443", "tcp"},
		{"*.example.com:443", scope.TargetTypeDomain, "*.example.com", "443", "tcp"},
	}
	for _, c := range cases {
		it := Classify(c.raw)
		it.InScope = true
		if !it.Scannable() || it.TargetType != c.typ || it.Pattern != c.pattern || it.Ports != c.ports || it.Protocol != c.protocol {
			t.Errorf("%s: %+v", c.raw, it)
			continue
		}
		if it.Constraint().IsZero() {
			t.Errorf("%s: no constraint", c.raw)
		}
	}
	// Without a port: the whole host, as before.
	if it := Classify("api.example.com"); it.Ports != "" || it.Protocol != "" || it.Pattern != "api.example.com" {
		t.Fatalf("bare host: %+v", it)
	}
	// A URL with a port and a path keeps the port in its pattern.
	if it := Classify("https://api.example.com:8443/v1/"); it.TargetType != scope.TargetTypeURL || it.Pattern != "https://api.example.com:8443/v1*" {
		t.Fatalf("url with port and path: %+v", it)
	}
}

// The plan carries the limit to the entry; an out-of-scope service excludes
// its whole host (excluding more is the safe side, and out of scope wins).
func TestPlanScope_Constraints(t *testing.T) {
	items, err := ParseScope("In scope:\napi.example.com:8443/tcp\napi.example.com:9443\nOut of scope:\nadmin.example.com:8443\n")
	if err != nil {
		t.Fatal(err)
	}
	p := PlanScope(items)
	if len(p.Entries) != 2 || p.Entries[0].Constraint.Ports != "8443" || p.Entries[1].Constraint.Ports != "9443" {
		t.Fatalf("entries = %+v", p.Entries)
	}
	// admin.example.com is in scope through no entry: nothing to exclude.
	if len(p.Exclusions) != 0 {
		t.Fatalf("exclusions = %+v", p.Exclusions)
	}
	// Out of scope wins where an in-scope entry reaches the service: a
	// wildcard without a limit, or a port range that holds the port.
	for _, paste := range []string{
		"In scope:\n*.example.com\nOut of scope:\nadmin.example.com:8443\n",
		"In scope:\nadmin.example.com:8000-9000\nOut of scope:\nadmin.example.com:8443\n",
	} {
		its, err := ParseScope(paste)
		if err != nil {
			t.Fatal(err)
		}
		pl := PlanScope(its)
		found := false
		for _, x := range pl.Exclusions {
			if x.Pattern == "admin.example.com" && x.Reason == ReasonOutOfScope && x.Constraint.IsZero() {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q: exclusions = %+v", paste, pl.Exclusions)
		}
	}
	// The limit is part of the terms: changing a port asks for a new
	// acceptance.
	other, _ := ParseScope("In scope:\napi.example.com:8443/tcp\napi.example.com:9444\nOut of scope:\nadmin.example.com:8443\n")
	if NewTerms("", Rules{}, items).SHA256() == NewTerms("", Rules{}, other).SHA256() {
		t.Fatal("terms hash ignores the port limit")
	}
	// Unconstrained items keep their old terms key.
	if k := (Item{TargetType: scope.TargetTypeDomain, Pattern: "x.example.com", InScope: true}).EntryKey(); k != "domain:x.example.com" {
		t.Fatalf("key = %s", k)
	}
	// Widening a port limit to the whole host is a widening for sync.
	before := Plan{Entries: []Planned{{TargetType: scope.TargetTypeDomain, Pattern: "api.example.com", Constraint: scope.Constraint{Ports: "8443"}}}}
	after := Plan{Entries: []Planned{{TargetType: scope.TargetTypeDomain, Pattern: "api.example.com"}}}
	if d := DiffPlans(before, after); !d.Widens() || !d.Narrows() {
		t.Fatalf("diff = %+v", d)
	}
}

func TestLimitItem_InvalidLimitIsNotScannable(t *testing.T) {
	it := Classify("https://shop.example.com/api/")
	it.InScope = true
	if got := LimitItem(it, []string{"443"}, ""); got.Scannable() {
		t.Fatalf("a URL entry cannot carry a port limit, it must not become scannable: %+v", got)
	}
	host := Classify("api.example.com")
	host.InScope = true
	if got := LimitItem(host, []string{"top-100"}, ""); got.Scannable() {
		t.Fatalf("an unreadable port list must not authorize the whole host: %+v", got)
	}
}
