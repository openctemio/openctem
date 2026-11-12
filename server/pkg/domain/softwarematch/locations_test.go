package softwarematch

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestLocationLabel(t *testing.T) {
	for _, c := range []struct {
		name      string
		port      int
		transport string
		want      string
	}{
		{"http://example.com", 0, "", "http:80"},
		{"https://example.com", 0, "", "https:443"},
		{"http://example.com:8080", 0, "", "http:8080"},
		{"https://example.com", 8443, "tcp", "https:8443"},
		{"example.com:22:tcp", 0, "", "tcp:22"},
		{"203.0.113.5:53:udp", 0, "", "udp:53"},
		{"weird", 0, "", "tcp"},
	} {
		if got := LocationLabel(c.name, c.port, c.transport); got != c.want {
			t.Errorf("LocationLabel(%q, %d) = %q, want %q", c.name, c.port, got, c.want)
		}
	}
}

func TestLocatableAndHostKey(t *testing.T) {
	p, v := shared.NewID(), shared.NewID()
	m := func(name, typ string, pkg bool) Match {
		return Match{AssetName: name, AssetType: typ, Package: pkg, ProductID: p, VersionID: v, Result: VersionVuln{CVEID: "cve-2024-1"}}
	}
	if !Locatable(m("https://a.example.com", "service", false)) {
		t.Error("a web origin is locatable")
	}
	for _, c := range []Match{m("https://a.example.com", "service", true), m("a.example.com", "host", false), m("203.0.113.0/24", "service", false)} {
		if Locatable(c) {
			t.Errorf("not locatable: %+v", c)
		}
	}
	// The origins of one host share a key; the CVE is case-insensitive.
	if HostKey(m("http://A.example.com", "service", false)) != HostKey(m("https://a.example.com:8443", "service", false)) {
		t.Error("origins of one host have one key")
	}
	if HostKey(m("https://a.example.com", "service", false)) == HostKey(m("https://b.example.com", "service", false)) {
		t.Error("another host is another key")
	}
}

func TestLocationEvidence(t *testing.T) {
	got := LocationEvidence("Server: nginx admin@example.com " + strings.Repeat("x", 600))
	if strings.Contains(got, "admin@") || len(got) > maxEvidenceLen {
		t.Fatalf("evidence not masked or bounded: %d %q", len(got), got[:40])
	}
}
