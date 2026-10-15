package ticketlink

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestKeyFromURL_OnlyTheIntegrationsSite(t *testing.T) {
	site := "https://acme.atlassian.net"
	ok := map[string]string{
		"https://acme.atlassian.net/browse/SEC-12":  "SEC-12",
		"https://ACME.atlassian.net/browse/sec-12/": "SEC-12",
		"https://acme.atlassian.net/browse/PAY_X-7": "PAY_X-7",
	}
	for raw, want := range ok {
		got, err := KeyFromURL(site, raw)
		if err != nil || got != want {
			t.Errorf("%s: %q %v", raw, got, err)
		}
	}
	for _, raw := range []string{
		"https://evil.example/browse/SEC-12",           // another host
		"http://acme.atlassian.net/browse/SEC-12",      // another scheme
		"https://acme.atlassian.net.evil/browse/SEC-1", // suffix trick
		"https://acme.atlassian.net/projects/SEC",      // not an issue
		"https://acme.atlassian.net/browse/SEC",        // no number
		"https://acme.atlassian.net/browse/SEC-1/x",
	} {
		if _, err := KeyFromURL(site, raw); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s accepted", raw)
		}
	}
	// A site served under a path (Data Center context path).
	if k, err := KeyFromURL("https://jira.acme.test/jira/", "https://jira.acme.test/jira/browse/OPS-3"); err != nil || k != "OPS-3" {
		t.Fatalf("context path: %q %v", k, err)
	}
}

func TestNew_Rules(t *testing.T) {
	f, c := shared.NewID(), shared.NewID()
	if _, err := New(shared.NewID(), shared.NewID(), &f, &c, "SEC-1", "", "https://x/browse/SEC-1", RoleOwn, SourcePerson, nil); err == nil {
		t.Fatal("both objects accepted")
	}
	if _, err := New(shared.NewID(), shared.NewID(), nil, nil, "SEC-1", "", "https://x/browse/SEC-1", RoleOwn, SourcePerson, nil); err == nil {
		t.Fatal("no object accepted")
	}
	if _, err := New(shared.NewID(), shared.NewID(), &f, nil, "sec 1", "", "https://x", RoleOwn, SourcePerson, nil); err == nil {
		t.Fatal("bad key accepted")
	}
	if _, err := New(shared.NewID(), shared.NewID(), &f, nil, "SEC-1", "", "https://x", RoleOwn, SourceMigration, nil); err == nil {
		t.Fatal("migration source accepted from code")
	}
	l, err := New(shared.NewID(), shared.NewID(), &f, nil, "sec-1", "10001", "https://x/browse/SEC-1", RoleOwn, SourcePlatform, nil)
	if err != nil || l.ExternalKey != "SEC-1" || l.ProjectKey != "SEC" || l.State != StateActive {
		t.Fatalf("%+v %v", l, err)
	}
}
