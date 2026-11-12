package exposure

import (
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestTemplateMatchType(t *testing.T) {
	for _, tc := range []struct {
		id   string
		tags []string
		want EventType
	}{
		{"grafana-panel", []string{"panel", "grafana"}, EventTypeWebInterfaceExposed},
		{"weak-cipher-suites", []string{"ssl", "tls"}, EventTypeSSLIssue},
		{"http-missing-security-headers", []string{"misconfig", "generic"}, EventTypeHeaderMissing},
		{"dmarc-detect", []string{"dns", "dmarc"}, EventTypeEmailSecurityWeak},
		{"options-method", []string{"misconfig"}, EventTypeMisconfiguration},
		{"tech-detect", []string{"tech", "discovery"}, EventTypeCustom},
		{"waf-detect", []string{"waf", "tech"}, EventTypeCustom},
	} {
		if got := TemplateMatchType(tc.id, tc.tags); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.id, got, tc.want)
		}
	}
}

// One event per template, matcher and URL: the ten matchers of the header
// template are ten exposures, the same match seen again is the same one,
// and the asset is part of the identity.
func TestTemplateMatchEventIdentity(t *testing.T) {
	tenant, asset, other := shared.NewID(), shared.NewID(), shared.NewID()
	m := TemplateMatch{AssetID: asset, Tool: "nuclei", RuleID: "http-missing-security-headers",
		Title: "HTTP Missing Security Headers", Matcher: "x-frame-options", URL: "https://a.example/", Tags: []string{"misconfig"}}
	ev, err := NewTemplateMatchEvent(tenant, m)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Severity() != SeverityInfo || ev.EventType() != EventTypeHeaderMissing || ev.Source() != SourceTemplateScan {
		t.Fatalf("event %s %s %s", ev.Severity(), ev.EventType(), ev.Source())
	}
	again, _ := NewTemplateMatchEvent(tenant, m)
	m2 := m
	m2.Matcher = "content-security-policy"
	csp, _ := NewTemplateMatchEvent(tenant, m2)
	m3 := m
	m3.AssetID = other
	elsewhere, _ := NewTemplateMatchEvent(tenant, m3)
	if again.Fingerprint() != ev.Fingerprint() {
		t.Fatal("the same match is a new exposure")
	}
	if csp.Fingerprint() == ev.Fingerprint() || elsewhere.Fingerprint() == ev.Fingerprint() {
		t.Fatal("distinct matchers or assets share one exposure")
	}
	if _, err := NewTemplateMatchEvent(shared.ID{}, m); err == nil {
		t.Fatal("an event without a tenant was built")
	}
}

// The URL keeps scheme, host, port and path: user info, a query (a token
// can ride in it) and the fragment are dropped; values are single-line and
// capped.
func TestTemplateMatchEventCleansReportedValues(t *testing.T) {
	ev, err := NewTemplateMatchEvent(shared.NewID(), TemplateMatch{AssetID: shared.NewID(), RuleID: "tech-detect",
		Title: "Wappalyzer\nTechnology\x00 Detection", URL: "https://user:pw@a.example:8443/app?token=s3cret#x"})
	if err != nil {
		t.Fatal(err)
	}
	d := ev.Details()
	if d["url"] != "https://a.example:8443/app" || d["domain"] != "a.example" {
		t.Fatalf("details %v", d)
	}
	if ev.Title() != "Wappalyzer Technology Detection" {
		t.Fatalf("title %q", ev.Title())
	}
	for _, u := range []string{"javascript:alert(1)", "ftp://a.example/x", "/relative"} {
		if got := TemplateMatchURL(u); got != "" {
			t.Errorf("%q kept as %q", u, got)
		}
	}
}
