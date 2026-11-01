package exposure

import (
	"strings"
	"testing"
)

func TestEveryEventTypeHasADisplayCategory(t *testing.T) {
	valid := map[DisplayCategory]bool{}
	for _, c := range Categories() {
		valid[c.Key] = true
	}
	for _, et := range AllEventTypes() {
		c, ok := categoryOf[et]
		if !ok {
			t.Errorf("event type %s has no display category", et)
			continue
		}
		if !valid[c] {
			t.Errorf("event type %s maps to unknown category %s", et, c)
		}
	}
	if EventType("nope").Category() != CategoryOther {
		t.Error("an unknown type must fall back to other")
	}
}

func TestEveryCategoryHasEventTypes(t *testing.T) {
	for _, c := range Categories() {
		if len(EventTypesOf(c.Key)) == 0 {
			t.Errorf("category %s has no event type", c.Key)
		}
	}
}

func TestNewTypesAreValidAndPositive(t *testing.T) {
	for _, et := range []EventType{EventTypeWebInterfaceExposed, EventTypeMCPServerExposed, EventTypeMailServerBlocklisted} {
		if !et.IsValid() || !et.IsPositiveExposure() {
			t.Errorf("%s must be a valid, positive exposure type", et)
		}
	}
}

func TestParseDisplayCategory(t *testing.T) {
	if c, ok := ParseDisplayCategory(" Exposed_Ports "); !ok || c != CategoryExposedPorts {
		t.Errorf("got %q %v", c, ok)
	}
	if _, ok := ParseDisplayCategory("exposed_ports; DROP"); ok {
		t.Error("an unknown category must not parse")
	}
}

func TestSummaryOfPortOpen(t *testing.T) {
	cases := []struct {
		name    string
		details map[string]any
		want    string
		variant string
	}{
		{"known port from number", map[string]any{"port": float64(6379)}, "Port 6379 (Redis) is open to the internet", ""},
		{"named service wins", map[string]any{"port": "8080", "service": "Jenkins"}, "Port 8080 (Jenkins) is open to the internet", ""},
		{"unknown port", map[string]any{"port": 31337}, "Port 31337 is open to the internet", "port"},
		{"no port falls back to title", map[string]any{}, "Open port found", "title"},
		{"fractional port is not a port", map[string]any{"port": 1.5}, "Open port found", "title"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := SummaryOf(EventTypePortOpen, "Open port found", tc.details)
			if s.Text != tc.want || s.Variant != tc.variant {
				t.Errorf("got %q (%q), want %q (%q)", s.Text, s.Variant, tc.want, tc.variant)
			}
		})
	}
}

func TestSummaryCleansUntrustedValues(t *testing.T) {
	d := map[string]any{"domain": "evil\n.example.com\x00<script>", "provider": strings.Repeat("a", 500)}
	s := SummaryOf(EventTypeSubdomainTakeover, "t", d)
	if strings.ContainsAny(s.Text, "\n\x00") {
		t.Errorf("control characters leaked: %q", s.Text)
	}
	if len([]rune(s.Args["provider"])) > maxSummaryArg {
		t.Errorf("value not capped: %d", len([]rune(s.Args["provider"])))
	}
	if _, ok := d["domain"].(string); !ok {
		t.Fatal("input mutated")
	}
}

func TestSummaryNonStringValuesIgnored(t *testing.T) {
	s := SummaryOf(EventTypeCertificateExpired, "Cert expired", map[string]any{"domain": map[string]any{"x": 1}})
	if s.Variant != "title" || s.Text != "Cert expired" {
		t.Errorf("got %+v", s)
	}
}
