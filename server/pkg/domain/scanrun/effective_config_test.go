package scanrun

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseSensorSettings_UntrustedInput(t *testing.T) {
	eff := json.RawMessage(`{
		"severity": {"value": ["low","high"], "source": "step"},
		"tags": {"value": "cve\u0000,\nx", "source": "` + strings.Repeat("s", 100) + `"},
		"headers": {"value": "Authorization: Bearer x", "source": "step"},
		"api_key": {"value": "k", "source": "step"},
		"obj": {"value": {"a": 1}, "source": "step"},
		"rate": {"value": 50, "source": "policy"}}`)
	got := ParseSensorSettings(eff, json.RawMessage(`["targets","auth_token","`+strings.Repeat("k", 200)+`", 5]`))
	if _, ok := got.Effective["headers"]; ok {
		t.Fatal("headers stored")
	}
	if _, ok := got.Effective["api_key"]; ok {
		t.Fatal("api_key stored")
	}
	if _, ok := got.Effective["obj"]; ok {
		t.Fatal("object value stored")
	}
	if got.Effective["rate"].Value != float64(50) || len(got.Effective["severity"].Value.([]string)) != 2 {
		t.Fatalf("lost valid values: %+v", got.Effective)
	}
	if utf8.RuneCountInString(got.Effective["tags"].Source) > maxSensorSourceRunes || strings.ContainsAny(got.Effective["tags"].Value.(string), "\x00\n") {
		t.Fatalf("not cleaned: %+v", got.Effective["tags"])
	}
	if len(got.IgnoredConfigKeys) != 2 || got.IgnoredConfigKeys[0] != "targets" || utf8.RuneCountInString(got.IgnoredConfigKeys[1]) > maxIgnoredKeyRunes {
		t.Fatalf("ignored: %v", got.IgnoredConfigKeys)
	}
}

func TestParseSensorSettings_Bounds(t *testing.T) {
	m := map[string]map[string]any{}
	for i := range 200 {
		m["k"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+strings.Repeat("b", i/26)] = map[string]any{"value": "v"}
	}
	b, _ := json.Marshal(m)
	got := ParseSensorSettings(b, nil)
	if len(got.Effective) > MaxSensorSettings {
		t.Fatalf("%d settings", len(got.Effective))
	}
	if !ParseSensorSettings(json.RawMessage(`not json`), json.RawMessage(`{}`)).IsZero() {
		t.Fatal("malformed input produced data")
	}
	huge := json.RawMessage(`{"a":{"value":"` + strings.Repeat("x", maxSensorSettingsBytes) + `"}}`)
	if !ParseSensorSettings(huge, nil).IsZero() {
		t.Fatal("oversized document parsed")
	}
}

func TestEffectiveConfigBounded(t *testing.T) {
	c := EffectiveConfig{Params: map[string]ParamValue{
		"big": {Value: strings.Repeat("x", maxParamValueBytes+1), Source: ParamSourceTemplateStep},
		"ok":  {Value: "y", Source: ParamSourceDepthOverlay}}}
	got := c.Bounded()
	if _, ok := got.Params["big"]; ok || got.Params["ok"].Value != "y" {
		t.Fatalf("%+v", got.Params)
	}
}

// A setting the sensor reports with a credential in it is shown masked: a URL
// with user:pass@, a bearer token, a provider key.
func TestParseSensorSettings_MasksCredentialLookingValues(t *testing.T) {
	eff := json.RawMessage(`{
		"proxy": {"value": "http://user:hunter2@proxy.example:8080", "source": "step"},
		"note": {"value": "Bearer abcdefghijklmnop", "source": "step"},
		"rate": {"value": 50, "source": "policy"},
		"severity": {"value": ["low", "high"], "source": "policy"}}`)
	got := ParseSensorSettings(eff, nil)
	for _, k := range []string{"proxy", "note"} {
		if got.Effective[k].Value != MaskedSensorValue {
			t.Fatalf("%s not masked: %+v", k, got.Effective[k])
		}
	}
	if got.Effective["rate"].Value != float64(50) || len(got.Effective["severity"].Value.([]string)) != 2 {
		t.Fatalf("plain values changed: %+v", got.Effective)
	}
}
