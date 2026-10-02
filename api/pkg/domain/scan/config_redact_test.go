package scan

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func secretCfg() map[string]any {
	return map[string]any{
		"password": "hunter2",
		"headers": map[string]any{
			"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
			"X-Trace":       "plain",
		},
		"args":      []any{"-u", "https://user:pw@example.com/", "-rate", 50.0},
		"severity":  "high",
		"retries":   3.0,
		"enabled":   true,
		"token_env": "${SCAN_TOKEN}",
	}
}

func TestRedactConfigSecrets_MasksExactlyTheWarnedValues(t *testing.T) {
	cfg := secretCfg()
	got := RedactConfigSecrets(cfg)

	want := map[string]any{
		"password": RedactedSecretValue,
		"headers": map[string]any{
			"Authorization": RedactedSecretValue,
			"X-Trace":       "plain",
		},
		"args":      []any{"-u", RedactedSecretValue, "-rate", 50.0},
		"severity":  "high",
		"retries":   3.0,
		"enabled":   true,
		"token_env": "${SCAN_TOKEN}",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("redacted:\n got %#v\nwant %#v", got, want)
	}

	// Every warned path is masked and nothing else is: the warnings computed
	// from the original config still describe the redacted one.
	warned := DetectConfigSecrets(cfg)
	if len(warned) != 3 {
		t.Fatalf("expected 3 warnings, got %v", paths(warned))
	}
	var masked []string
	collectMasked("", got, &masked)
	var warnedPaths []string
	for _, w := range warned {
		warnedPaths = append(warnedPaths, w.Path)
	}
	slices.Sort(masked)
	if !slices.Equal(masked, warnedPaths) {
		t.Fatalf("masked paths %v != warned paths %v", masked, warnedPaths)
	}

	// The input is not modified.
	if cfg["password"] != "hunter2" || cfg["headers"].(map[string]any)["Authorization"] == RedactedSecretValue {
		t.Fatal("RedactConfigSecrets modified its input")
	}
}

func collectMasked(prefix string, v any, out *[]string) {
	switch val := v.(type) {
	case map[string]any:
		for k, item := range val {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			collectMasked(p, item, out)
		}
	case []any:
		for i, item := range val {
			collectMasked(prefix+"["+strconv.Itoa(i)+"]", item, out)
		}
	case string:
		if val == RedactedSecretValue {
			*out = append(*out, prefix)
		}
	}
}

func TestRedactConfigSecrets_NilAndEmpty(t *testing.T) {
	if RedactConfigSecrets(nil) != nil {
		t.Fatal("nil config must stay nil")
	}
	if got := RedactConfigSecrets(map[string]any{}); got == nil || len(got) != 0 {
		t.Fatalf("empty config must stay empty, got %#v", got)
	}
}

func TestRedactConfigSecrets_StringSlice(t *testing.T) {
	got := RedactConfigSecrets(map[string]any{"tokens": []string{"abc", "def"}, "names": []string{"a"}})
	if !reflect.DeepEqual(got["tokens"], []string{RedactedSecretValue, RedactedSecretValue}) {
		t.Fatalf("tokens: %#v", got["tokens"])
	}
	if !reflect.DeepEqual(got["names"], []string{"a"}) {
		t.Fatalf("names: %#v", got["names"])
	}
}

func TestRedactConfigSecrets_BeyondDetectorDepthIsMaskedWhole(t *testing.T) {
	// Build a chain deeper than the detector walks, ending in a secret the
	// detector never sees. The redaction must not hand it out.
	leaf := map[string]any{"password": "deep-secret"}
	cfg := leaf
	for range maxSecretScanDepth + 2 {
		cfg = map[string]any{"n": cfg}
	}
	b, err := json.Marshal(RedactConfigSecrets(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "deep-secret") {
		t.Fatalf("value below the detector depth leaked: %s", b)
	}
	if !strings.Contains(string(b), RedactedSecretValue) {
		t.Fatalf("expected a mask in %s", b)
	}
}

func TestRedactPayloadSecrets(t *testing.T) {
	payload := map[string]any{
		"scan_id":        "6f1c5b0e-3c0a-4b8e-9b2a-0d1e2f3a4b5c",
		"scanner":        "nuclei",
		"scanner_config": map[string]any{"api_key": "k-123", "rate": 10.0},
		"config":         map[string]any{"api_key": "k-123", "rate": 10.0},
		"context": map[string]any{
			"scanner_config": map[string]any{"headers": map[string]any{"Authorization": "Bearer abcdefghijklmnop"}},
		},
	}
	raw, _ := json.Marshal(payload)
	out := RedactPayloadSecrets(raw)
	s := string(out)
	for _, leak := range []string{"k-123", "abcdefghijklmnop"} {
		if strings.Contains(s, leak) {
			t.Fatalf("payload leaks %q: %s", leak, s)
		}
	}
	for _, keep := range []string{"6f1c5b0e-3c0a-4b8e-9b2a-0d1e2f3a4b5c", `"nuclei"`, `"rate":10`} {
		if !strings.Contains(s, keep) {
			t.Fatalf("payload lost %q: %s", keep, s)
		}
	}

	if got := RedactPayloadSecrets(nil); got != nil {
		t.Fatalf("empty payload: %s", got)
	}
	if got := string(RedactPayloadSecrets(json.RawMessage(`null`))); got != "null" {
		t.Fatalf("null payload: %s", got)
	}
	if got := string(RedactPayloadSecrets(json.RawMessage(`["secret-in-a-list"]`))); strings.Contains(got, "secret") {
		t.Fatalf("non-object payload must be masked, got %s", got)
	}
}

func TestRestoreRedactedConfigSecrets(t *testing.T) {
	stored := secretCfg()
	// A client saves what it was shown (masked), changing one non-secret
	// value and adding a key.
	incoming := RedactConfigSecrets(stored)
	incoming["severity"] = "critical"
	incoming["new_key"] = RedactedSecretValue // no stored value: kept as typed

	got := RestoreRedactedConfigSecrets(incoming, stored)

	if got["password"] != "hunter2" {
		t.Fatalf("password overwritten with %v", got["password"])
	}
	if got["headers"].(map[string]any)["Authorization"] != "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" {
		t.Fatalf("Authorization overwritten with %v", got["headers"])
	}
	if got["args"].([]any)[1] != "https://user:pw@example.com/" {
		t.Fatalf("args[1] overwritten with %v", got["args"])
	}
	if got["severity"] != "critical" {
		t.Fatalf("non-secret edit lost: %v", got["severity"])
	}
	if got["new_key"] != RedactedSecretValue {
		t.Fatalf("new key: %v", got["new_key"])
	}

	// A new secret value replaces the stored one.
	incoming = RedactConfigSecrets(stored)
	incoming["password"] = "new-pass"
	if got := RestoreRedactedConfigSecrets(incoming, stored); got["password"] != "new-pass" {
		t.Fatalf("new secret not taken: %v", got["password"])
	}

	// The mask typed over a value that was never masked stays the mask: the
	// stored value was visible, so the client really meant to change it.
	got = RestoreRedactedConfigSecrets(map[string]any{"severity": RedactedSecretValue}, stored)
	if got["severity"] != RedactedSecretValue {
		t.Fatalf("plain value restored: %v", got["severity"])
	}

	if RestoreRedactedConfigSecrets(nil, stored) != nil {
		t.Fatal("nil incoming must stay nil")
	}
}
