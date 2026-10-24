package handler

import (
	"strings"
	"testing"
)

// Rows written before failures were stored as codes hold the upstream error
// text; a read cleans it like an error response.
func TestPublicStatusText(t *testing.T) {
	old := "Connection test failed: integration 99999999-9999-4999-8999-999999999999 has no credentials"
	if got := publicStatusText(old); strings.Contains(got, "99999999") {
		t.Fatalf("id kept: %q", got)
	}
	if got := publicStatusText("Connection test failed: Get \"https://jira.internal\": dial tcp 10.1.2.3:443: i/o timeout"); strings.Contains(got, "10.1.2.3") || strings.Contains(got, "dial") {
		t.Fatalf("network text kept: %q", got)
	}
	if publicStatusText("") != "" {
		t.Fatal("empty stays empty")
	}
	if got := publicStatusText("The service refused the credentials."); got != "The service refused the credentials." {
		t.Fatalf("a safe sentence is kept, got %q", got)
	}
}
