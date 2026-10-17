package sensor

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/openctemio/ctis/settings"
)

// layersTestConfig: rate (scan scope, narrows), workers (sensor scope), a
// group with one scan-scope key, and an Impact (T1) option.
const layersTestConfig = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 150, "x-octm-common": "rate", "x-octm-scope": "scan"},
    "workers": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25, "x-octm-scope": "sensor"},
    "follow_redirects": {"type": "boolean", "default": false, "x-octm-tier": "T1", "x-octm-scope": "sensor"},
    "retries": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1, "x-octm-common": "retries", "x-octm-scope": "scan"},
    "dns": {"type": "object", "additionalProperties": false, "properties": {
      "wildcard": {"type": "boolean", "default": true, "x-octm-scope": "scan"},
      "resolver": {"type": "string", "maxLength": 64, "x-octm-scope": "sensor"}
    }}
  }
}`

func layersSchema(t *testing.T) *settings.Schema {
	t.Helper()
	s, err := ToolSettingsSchema(testToolDescriptor(layersTestConfig))
	if err != nil || s == nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func effective(t *testing.T, eff []EffectiveToolSetting) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, e := range eff {
		b, _ := json.Marshal(e.Value)
		got[e.Key] = string(e.Source) + "=" + string(b)
	}
	return got
}

// The organization layer is a default: the sensor overrides a key in either
// direction, and the layers delivered never share a key.
func TestInheritedValues(t *testing.T) {
	org := values(t, `{"rate_limit": 150, "workers": 40, "dns": {"wildcard": false, "resolver": "1.1.1.1"}}`)
	sensor := values(t, `{"rate_limit": 300, "dns": {"wildcard": true}}`)
	got := InheritedValues(org, sensor)
	b, _ := json.Marshal(got)
	if string(b) != `{"dns":{"resolver":"1.1.1.1"},"workers":40}` {
		t.Fatalf("inherited = %s", b)
	}
	if InheritedValues(nil, sensor) != nil || InheritedValues(values(t, `{"rate_limit": 1}`), values(t, `{"rate_limit": 2}`)) != nil {
		t.Fatal("nothing left must be nil")
	}
	// The input is not changed.
	if _, ok := org["rate_limit"]; !ok {
		t.Fatal("org values changed")
	}
}

func TestEffectiveToolSettings_Precedence(t *testing.T) {
	s := layersSchema(t)
	org := values(t, `{"rate_limit": 150, "workers": 40, "retries": 3, "dns": {"wildcard": false}}`)
	cases := []struct {
		name  string
		admin AdminValues
		scan  map[string]any
		want  map[string]string
		errAt string
	}{
		{"defaults only", AdminValues{}, nil,
			map[string]string{"rate_limit": "default=150", "workers": "default=25", "retries": "default=1", "dns.wildcard": "default=true"}, ""},
		{"organization raises above the tool default", AdminValues{Organization: values(t, `{"rate_limit": 900}`)}, nil,
			map[string]string{"rate_limit": "tenant=900"}, ""},
		{"organization lowers", AdminValues{Organization: org}, nil,
			map[string]string{"rate_limit": "tenant=150", "workers": "tenant=40", "retries": "tenant=3", "dns.wildcard": "tenant=false"}, ""},
		{"sensor raises above the organization", AdminValues{Organization: org, Sensor: values(t, `{"rate_limit": 300}`)}, nil,
			map[string]string{"rate_limit": "sensor=300", "workers": "tenant=40"}, ""},
		{"sensor lowers below the organization", AdminValues{Organization: org, Sensor: values(t, `{"retries": 0}`)}, nil,
			map[string]string{"retries": "sensor=0", "rate_limit": "tenant=150"}, ""},
		{"sensor overrides one key of a group", AdminValues{Organization: org, Sensor: values(t, `{"dns": {"wildcard": true}}`)}, nil,
			map[string]string{"dns.wildcard": "sensor=true", "workers": "tenant=40"}, ""},
		{"scan lowers the organization's value", AdminValues{Organization: org}, map[string]any{"rate_limit": 100},
			map[string]string{"rate_limit": "scan=100"}, ""},
		{"scan may not raise the organization's value", AdminValues{Organization: org}, map[string]any{"rate_limit": 151},
			nil, "/rate_limit"},
		{"scan may not raise above the sensor's raise", AdminValues{Organization: org, Sensor: values(t, `{"rate_limit": 300}`)},
			map[string]any{"rate_limit": 301}, nil, "/rate_limit"},
		{"scan up to the sensor's raise", AdminValues{Organization: org, Sensor: values(t, `{"rate_limit": 300}`)},
			map[string]any{"rate_limit": 300}, map[string]string{"rate_limit": "scan=300"}, ""},
		{"scan may not raise retries above the organization", AdminValues{Organization: org},
			map[string]any{"retries": 4}, nil, "/retries"},
		{"scan may not set a sensor-scope key", AdminValues{Organization: org}, map[string]any{"workers": 1}, nil, "/workers"},
	}
	for _, c := range cases {
		eff, err := EffectiveToolSettingsWithScan(s, c.admin, c.scan)
		if c.errAt != "" {
			if !slices.Contains(errPaths(err), c.errAt) {
				t.Errorf("%s: err = %v, want a problem at %s", c.name, err, c.errAt)
			}
			if verr := ValidateScanSettings(s, c.admin, c.scan); !slices.Contains(errPaths(verr), c.errAt) {
				t.Errorf("%s: ValidateScanSettings = %v", c.name, verr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		got := effective(t, eff)
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s = %s, want %s", c.name, k, got[k], v)
			}
		}
	}
}

// The chain lists every layer that sets a key, an overridden organization
// value included.
func TestEffectiveToolSettings_Chain(t *testing.T) {
	eff, err := EffectiveToolSettingsWithScan(layersSchema(t), AdminValues{
		Organization: values(t, `{"rate_limit": 150}`), Sensor: values(t, `{"rate_limit": 300}`),
	}, map[string]any{"rate_limit": 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range eff {
		if e.Key != "rate_limit" {
			continue
		}
		if fmt.Sprint(e.Chain) != "[{default 150} {tenant 150} {sensor 300} {scan 200}]" {
			t.Fatalf("chain = %v", e.Chain)
		}
		return
	}
	t.Fatal("rate_limit missing")
}

func TestValidateTenantToolSettings(t *testing.T) {
	s := layersSchema(t)
	if err := ValidateTenantToolSettings(s, values(t, `{"rate_limit": 4000, "workers": 200, "dns": {"resolver": "9.9.9.9"}}`)); err != nil {
		t.Fatalf("raise at the organization: %v", err)
	}
	for in, path := range map[string]string{
		`{"rate_limit": 0}`:    "/rate_limit",
		`{"bogus": 1}`:         "/bogus",
		`{"dns": {"x": true}}`: "/dns/x",
	} {
		if err := ValidateTenantToolSettings(s, values(t, in)); !slices.Contains(errPaths(err), path) {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestImpactChanges(t *testing.T) {
	s := layersSchema(t)
	if got := ImpactChanges(s, nil, values(t, `{"follow_redirects": true, "rate_limit": 900}`)); !slices.Equal(got, []string{"follow_redirects"}) {
		t.Fatalf("set = %v", got)
	}
	if got := ImpactChanges(s, values(t, `{"follow_redirects": true}`), values(t, `{"follow_redirects": true, "workers": 3}`)); len(got) != 0 {
		t.Fatalf("unchanged = %v", got)
	}
	if got := ImpactChanges(s, values(t, `{"follow_redirects": true}`), nil); len(got) != 0 {
		t.Fatalf("removed = %v", got)
	}
	if ImpactChanges(nil, nil, values(t, `{"a": 1}`)) != nil {
		t.Fatal("nil schema")
	}
}
