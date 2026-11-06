package scope

import "testing"

func TestLimitOfEntry(t *testing.T) {
	if l, ok := LimitOfEntry(TargetTypeURL, "https://Shop.example.com/API/v1*", Constraint{}); !ok || l != (EntryLimit{Ports: "443", Protocol: "tcp", PathPrefix: "/API/v1"}) {
		t.Fatalf("url path entry: %+v %v", l, ok)
	}
	if l, ok := LimitOfEntry(TargetTypeURL, "http://shop.example.com:8080/caf%C3%A9/", Constraint{}); !ok || l.Ports != "8080" || l.PathPrefix != "/café" {
		t.Fatalf("decoded path: %+v", l)
	}
	if l, ok := LimitOfEntry(TargetTypeURL, "https://shop.example.com/a%2fb/", Constraint{}); !ok || l != (EntryLimit{}) {
		t.Fatalf("an encoded separator gives an empty limit (allows nothing): %+v %v", l, ok)
	}
	if l, ok := LimitOfEntry(TargetTypeDomain, "api.example.com", Constraint{Ports: "8443", Protocol: "tcp"}); !ok || l.Ports != "8443" || l.PathPrefix != "" {
		t.Fatalf("port entry: %+v", l)
	}
	if _, ok := LimitOfEntry(TargetTypeDomain, "api.example.com", Constraint{}); ok {
		t.Fatal("an unlimited entry gives a limit")
	}
}

func TestLimitWithin(t *testing.T) {
	path := func(l EntryLimit) bool {
		return LimitWithin(l, TargetTypeURL, "https://shop.example.com/api*", Constraint{})
	}
	port := func(l EntryLimit) bool {
		return LimitWithin(l, TargetTypeDomain, "api.example.com", Constraint{Ports: "8443,9000-9010", Protocol: "tcp"})
	}
	cases := []struct {
		name string
		ok   bool
		got  bool
	}{
		{"same path", true, path(EntryLimit{Ports: "443", Protocol: "tcp", PathPrefix: "/api"})},
		{"narrower path", true, path(EntryLimit{Ports: "443", Protocol: "tcp", PathPrefix: "/API/v2"})},
		{"root", false, path(EntryLimit{Ports: "443", Protocol: "tcp", PathPrefix: "/"})},
		{"sibling", false, path(EntryLimit{Ports: "443", Protocol: "tcp", PathPrefix: "/apiadmin"})},
		{"dots", false, path(EntryLimit{Ports: "443", Protocol: "tcp", PathPrefix: "/api/../admin"})},
		{"no path", false, path(EntryLimit{Ports: "443", Protocol: "tcp"})},
		{"other port", false, path(EntryLimit{Ports: "8443", Protocol: "tcp", PathPrefix: "/api"})},
		{"subset ports", true, port(EntryLimit{Ports: "8443,9001-9002", Protocol: "tcp"})},
		{"wider ports", false, port(EntryLimit{Ports: "8000-9010", Protocol: "tcp"})},
		{"every port", false, port(EntryLimit{Protocol: "tcp"})},
		{"any protocol", false, port(EntryLimit{Ports: "8443"})},
		{"with a path", true, port(EntryLimit{Ports: "8443", Protocol: "tcp", PathPrefix: "/x"})},
		{"unlimited entry", true, LimitWithin(EntryLimit{Ports: "1"}, TargetTypeDomain, "api.example.com", Constraint{})},
	}
	for _, c := range cases {
		if c.got != c.ok {
			t.Errorf("%s: %v, want %v", c.name, c.got, c.ok)
		}
	}
}
