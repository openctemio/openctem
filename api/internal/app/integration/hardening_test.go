package integration

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Request metadata is stored in plaintext and merged over server-written keys
// (chat ids, SMTP host, sync state): only known, non-secret, bounded keys are
// accepted (23b G-M5).
func TestSanitizeCallerMetadata(t *testing.T) {
	ok, err := sanitizeCallerMetadata(map[string]any{"hec_url": "https://splunk.example:8088", "index": "sec", "sourcetype": "openctem"})
	if err != nil || len(ok) != 3 {
		t.Fatalf("allowed keys: %v, %v", ok, err)
	}
	for name, in := range map[string]map[string]any{
		"unknown key":       {"chat_id": "123"},
		"secret in meta":    {"smtp_password": "hunter2"},
		"provider override": {"tenable_sync": "{}"},
		"non-string":        {"index": map[string]any{"x": 1}},
		"too long":          {"index": strings.Repeat("a", maxCallerMetadataValueLen+1)},
	} {
		if _, err := sanitizeCallerMetadata(in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://Jira.Example.com/rest": "https://jira.example.com",
		"https://jira.example.com:8443": "https://jira.example.com:8443",
		"":                              "",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
