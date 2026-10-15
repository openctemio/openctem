package sensor

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/ctis/settings"
)

// testToolSettingsConfig is a tool settings schema with a common option, a
// tool option bounded by an enum, a dangerous (T2) key, a sensitive key and
// a group.
const testToolSettingsConfig = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {"type": "integer", "maximum": 5000, "default": 150, "x-octm-common": "rate", "x-octm-flag": "-rate-limit", "x-octm-scope": "scan"},
    "scan_strategy": {"type": "string", "enum": ["auto", "host-spray"], "default": "auto", "x-octm-flag": "-ss", "x-octm-group": "Engine"},
    "headless": {"type": "boolean", "default": false, "x-octm-tier": "T2", "x-octm-flag": "-headless"},
    "api_token": {"type": "string", "x-octm-sensitive": true},
    "dns": {"type": "object", "additionalProperties": false, "properties": {
      "retries": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1}
    }}
  }
}`

func testToolDescriptor(config string) json.RawMessage {
	if config == "" {
		return json.RawMessage(`{"apiVersion":"openctem.io/tool/v1","name":"nuclei","version":"1.0.0"}`)
	}
	return json.RawMessage(`{"apiVersion":"openctem.io/tool/v1","name":"nuclei","version":"1.0.0","config":` + config + `}`)
}

func mustToolSchema(t *testing.T) *settings.Schema {
	t.Helper()
	s, err := ToolSettingsSchema(testToolDescriptor(testToolSettingsConfig))
	if err != nil || s == nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func values(t *testing.T, raw string) map[string]any {
	t.Helper()
	v, err := DecodeToolSettingsValues([]byte(raw))
	if err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

func errPaths(err error) []string {
	var errs settings.Errors
	if errors.As(err, &errs) {
		return errs.Paths()
	}
	return nil
}

func TestToolSettingsSchema(t *testing.T) {
	if s, err := ToolSettingsSchema(testToolDescriptor("")); err != nil || s != nil {
		t.Fatalf("descriptor without config: %v, %v", s, err)
	}
	if s, err := ToolSettingsSchema(nil); err != nil || s != nil {
		t.Fatalf("no descriptor: %v, %v", s, err)
	}
	// A schema outside the contract (a keyword it does not allow) is an
	// error, not "no settings".
	_, err := ToolSettingsSchema(testToolDescriptor(`{"type":"object","additionalProperties":false,"properties":{"x":{"type":"string","$ref":"#/y"}}}`))
	if !errors.Is(err, ErrToolSettingsSchema) {
		t.Fatalf("invalid schema: %v", err)
	}
	s := mustToolSchema(t)
	if !strings.HasPrefix(s.Digest(), "sha256:") {
		t.Fatalf("digest %q", s.Digest())
	}
}

func TestValidateToolSettings(t *testing.T) {
	s := mustToolSchema(t)
	cases := []struct {
		name  string
		raw   string
		paths []string
	}{
		{"empty is the defaults", `{}`, nil},
		{"in range", `{"rate_limit": 300, "scan_strategy": "host-spray", "dns": {"retries": 3}}`, nil},
		{"unknown key", `{"bogus": 1}`, []string{"/bogus"}},
		{"above the maximum", `{"rate_limit": 6000}`, []string{"/rate_limit"}},
		{"below the common minimum", `{"rate_limit": 0}`, []string{"/rate_limit"}},
		{"outside the enum", `{"scan_strategy": "fast"}`, []string{"/scan_strategy"}},
		{"group key out of range", `{"dns": {"retries": 9}}`, []string{"/dns/retries"}},
		{"wrong type", `{"rate_limit": "fast"}`, []string{"/rate_limit"}},
		{"T2 non-default refused", `{"headless": true}`, []string{"/headless"}},
		{"T2 default allowed", `{"headless": false}`, nil},
		{"sensitive key never a plain value", `{"api_token": "s3cr3t"}`, []string{"/api_token"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateToolSettings(s, values(t, c.raw))
			if got := errPaths(err); !slices.Equal(got, c.paths) {
				t.Fatalf("paths = %v (err %v), want %v", got, err, c.paths)
			}
		})
	}
	// The T2 refusal says why, so the console can show it.
	err := ValidateToolSettings(s, values(t, `{"headless": true}`))
	if !strings.Contains(err.Error(), "not available yet") {
		t.Fatalf("T2 message: %v", err)
	}
}

func TestDecodeToolSettingsValues(t *testing.T) {
	if _, err := DecodeToolSettingsValues([]byte(`[1]`)); err == nil {
		t.Fatal("array accepted")
	}
	if _, err := DecodeToolSettingsValues([]byte(`{"a":` + strings.Repeat(" ", MaxToolSettingsBytes) + `1}`)); err == nil {
		t.Fatal("oversized document accepted")
	}
	v := values(t, `{"rate_limit": 12}`)
	if _, ok := v["rate_limit"].(json.Number); !ok {
		t.Fatalf("number not kept exact: %T", v["rate_limit"])
	}
}

func TestToolSettingsDiffRedactsSensitive(t *testing.T) {
	s := mustToolSchema(t)
	before := map[string]any{"rate_limit": json.Number("100"), "api_token": "old-secret", "gone": "x"}
	after := map[string]any{"rate_limit": json.Number("200"), "api_token": "new-secret", "dns": map[string]any{"retries": json.Number("2")}}
	old, updated := ToolSettingsDiff(s, before, after)
	if old["rate_limit"] != json.Number("100") || updated["rate_limit"] != json.Number("200") {
		t.Fatalf("rate_limit diff = %v -> %v", old["rate_limit"], updated["rate_limit"])
	}
	if old["api_token"] != RedactedSettingValue || updated["api_token"] != RedactedSettingValue {
		t.Fatalf("sensitive value leaked: %v -> %v", old["api_token"], updated["api_token"])
	}
	// A key the schema no longer knows is redacted too.
	if old["gone"] != RedactedSettingValue || updated["gone"] != nil {
		t.Fatalf("unknown key diff = %v -> %v", old["gone"], updated["gone"])
	}
	if old["dns.retries"] != nil || updated["dns.retries"] != json.Number("2") {
		t.Fatalf("group key diff = %v -> %v", old["dns.retries"], updated["dns.retries"])
	}
	for _, v := range []map[string]any{old, updated} {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), "secret") {
			t.Fatalf("diff carries a secret: %s", b)
		}
	}
	if o, u := ToolSettingsDiff(s, before, before); len(o) != 0 || len(u) != 0 {
		t.Fatalf("no change gave a diff: %v %v", o, u)
	}
}

func TestEffectiveToolSettings(t *testing.T) {
	s := mustToolSchema(t)
	eff, err := EffectiveToolSettings(s, AdminValues{Sensor: values(t, `{"rate_limit": 300}`)})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]EffectiveToolSetting{}
	for _, e := range eff {
		byKey[e.Key] = e
	}
	if len(eff) != 5 {
		t.Fatalf("keys = %d, want every key of the schema", len(eff))
	}
	r := byKey["rate_limit"]
	if r.Value != json.Number("300") || r.Source != settings.SourceSensor || r.Flag != "-rate-limit" || r.Common != "rate" || r.Scope != settings.ScopeScan {
		t.Fatalf("rate_limit = %+v", r)
	}
	if d := byKey["dns.retries"]; d.Value != json.Number("1") || d.Source != settings.SourceDefault {
		t.Fatalf("dns.retries = %+v", d)
	}
	if h := byKey["headless"]; h.Tier != "T2" || h.Source != settings.SourceDefault {
		t.Fatalf("headless = %+v", h)
	}
	if a := byKey["api_token"]; a.Value != nil || a.Source != "" {
		t.Fatalf("api_token = %+v", a)
	}
	if _, err := EffectiveToolSettings(s, AdminValues{Sensor: values(t, `{"bogus": 1}`)}); err == nil {
		t.Fatal("invalid values resolved")
	}
	if eff, err := EffectiveToolSettings(nil, AdminValues{}); err != nil || len(eff) != 0 {
		t.Fatalf("nil schema = %v, %v", eff, err)
	}
}

func TestNormalizeToolName(t *testing.T) {
	if NormalizeToolName(" Nuclei ") != "nuclei" {
		t.Fatal("not normalized")
	}
	for _, bad := range []string{"", "../x", "a b", strings.Repeat("a", 200)} {
		if NormalizeToolName(bad) != "" {
			t.Fatalf("%q accepted", bad)
		}
	}
}
