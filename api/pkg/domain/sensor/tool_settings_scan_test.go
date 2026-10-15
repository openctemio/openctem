package sensor

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/ctis/settings"
)

// scanTestConfig: a scan-scope common option (retries), a sensor-scope key
// (workers) and a scan-scope tool option (strategy).
const scanTestConfig = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 150, "x-octm-common": "rate", "x-octm-scope": "scan"},
    "retries": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1, "x-octm-common": "retries", "x-octm-scope": "scan"},
    "workers": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25, "x-octm-scope": "sensor"},
    "strategy": {"type": "string", "enum": ["auto", "host-spray"], "default": "auto", "x-octm-scope": "scan"}
  }
}`

func scanTestSchema(t *testing.T) *settings.Schema {
	t.Helper()
	s, err := ToolSettingsSchema(testToolDescriptor(scanTestConfig))
	if err != nil || s == nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

// The scan layer is built as the sensor builds it: the tool's keys, never
// the executor's own (job limits, run switches); other keys are ignored and
// a key that is not a setting name is not echoed.
func TestScanSettingsLayer(t *testing.T) {
	layer, ignored := ScanSettingsLayer(scanTestSchema(t), map[string]any{
		"retries": 0, "strategy": "host-spray", "rate_limit": 10, "exclude": []any{"a"},
		"template_id": "x", "Bad Key!": 1,
	})
	if len(layer) != 2 || layer["retries"] != 0 || layer["strategy"] != "host-spray" {
		t.Fatalf("layer = %v", layer)
	}
	if !slices.Equal(ignored, []string{"<invalid key>", "template_id"}) {
		t.Fatalf("ignored = %v", ignored)
	}
}

func TestValidateScanSettings(t *testing.T) {
	schema := scanTestSchema(t)
	sensorRaised := values(t, `{"retries": 3}`)
	cases := []struct {
		name   string
		sensor map[string]any
		scan   map[string]any
		path   string // "" = accepted
	}{
		{"lower than the default", nil, map[string]any{"retries": 0}, ""},
		{"a decoded JSON number", nil, map[string]any{"retries": float64(0)}, ""},
		{"raise above the default", nil, map[string]any{"retries": 2}, "/retries"},
		{"up to the sensor's raise", sensorRaised, map[string]any{"retries": 3}, ""},
		{"above the sensor's raise", sensorRaised, map[string]any{"retries": 4}, "/retries"},
		{"a sensor-only option", nil, map[string]any{"workers": 10}, "/workers"},
		{"out of the enum", nil, map[string]any{"strategy": "spray"}, "/strategy"},
		{"nothing to check", nil, map[string]any{}, ""},
	}
	for _, c := range cases {
		err := ValidateScanSettings(schema, AdminValues{Sensor: c.sensor}, c.scan)
		if c.path == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if !slices.Contains(errPaths(err), c.path) {
			t.Errorf("%s: err = %v, want a problem at %s", c.name, err, c.path)
		}
	}
}

// The preview names where each value comes from, the scan included.
func TestEffectiveToolSettingsWithScan(t *testing.T) {
	eff, err := EffectiveToolSettingsWithScan(scanTestSchema(t), AdminValues{Sensor: values(t, `{"retries": 3, "workers": 50}`)}, map[string]any{"retries": 2})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range eff {
		b, _ := json.Marshal(e.Value)
		got[e.Key] = string(e.Source) + "=" + string(b)
	}
	want := map[string]string{"rate_limit": "default=150", "retries": "scan=2", "workers": "sensor=50", "strategy": "default=\"auto\""}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
}
