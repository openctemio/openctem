package handler

import "testing"

// Guards the redaction allowlist: project_key (a Jira identifier, not a secret)
// must round-trip in plaintext so the UI doesn't overwrite it with "[REDACTED]"
// on a wholesale re-save, while every real *_key / secret stays redacted.
func TestSanitizeConfigMap_ProjectKeyAllowlisted(t *testing.T) {
	in := map[string]any{
		"project_key":   "PROJ",                     // allowlisted → plaintext
		"url":           "https://jira.example.com", // not sensitive → plaintext
		"issue_type":    "Bug",                      // not sensitive → plaintext
		"access_key":    "AKIA-REAL-SECRET",         // Tenable/Nessus secret → redact
		"api_key":       "real-api-key",             // secret → redact
		"secret_key":    "real-secret-key",          // secret → redact
		"signing_key":   "real-signing-key",         // secret (only matches "key") → redact
		"token":         "real-token",               // secret → redact
		"password":      "hunter2",                  // secret → redact
		"client_secret": "cs",                       // secret → redact
	}

	out := sanitizeConfigMap(in)

	plaintext := []string{"project_key", "url", "issue_type"}
	for _, k := range plaintext {
		if out[k] != in[k] {
			t.Errorf("%q should be plaintext, got %v (want %v)", k, out[k], in[k])
		}
	}

	redacted := []string{"access_key", "api_key", "secret_key", "signing_key", "token", "password", "client_secret"}
	for _, k := range redacted {
		if out[k] != "[REDACTED]" {
			t.Errorf("%q should be [REDACTED], got %v", k, out[k])
		}
	}
}
