package httpsec

import (
	"context"
	"strings"
	"testing"
)

func TestUpstreamStatusError_HoldsNoBody(t *testing.T) {
	body := []byte(`{"error":"bad token sk_live_SECRET","echo":"Authorization: Bearer xyz"}`)
	err := NewUpstreamStatusError(context.Background(), "jira", 401, body)
	msg := err.Error()
	if msg != "jira returned HTTP 401" {
		t.Fatalf("error = %q", msg)
	}
	for _, leak := range []string{"SECRET", "Bearer", "token"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q contains upstream body text %q", msg, leak)
		}
	}
}

func TestBodySnippet_BoundedAndSanitised(t *testing.T) {
	long := strings.Repeat("a", 1000)
	if got := BodySnippet([]byte(long)); len([]rune(got)) != maxUpstreamSnippet+1 {
		t.Fatalf("snippet length = %d", len([]rune(got)))
	}
	got := BodySnippet([]byte("line1\nline2\x1b[31m‮evil"))
	if strings.ContainsAny(got, "\n\x1b‮") {
		t.Fatalf("control or bidi characters kept: %q", got)
	}
}
