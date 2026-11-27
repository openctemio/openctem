package integration

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A connection a member turned off carries a stable code, so a client words
// it in the reader's language and shows the time in the reader's locale; the
// English message keeps the time in RFC 3339 (UTC) for clients without the code.
func TestSetDisabledByUser_CodeAndTime(t *testing.T) {
	i := NewIntegration(shared.NewID(), shared.NewID(), "GitLab", CategorySCM, ProviderGitLab, AuthTypeToken)
	i.SetFailure("INTEGRATION_NOT_FOUND", "The service did not find what this connection points at.")

	at := time.Date(2026, 11, 27, 15, 59, 36, 0, time.FixedZone("ICT", 7*3600))
	i.SetDisabledByUser(at)

	if i.Status() != StatusDisabled {
		t.Fatalf("status = %q, want disabled", i.Status())
	}
	if i.StatusCode() != StatusCodeDisabledByUser {
		t.Fatalf("code = %q, want %q", i.StatusCode(), StatusCodeDisabledByUser)
	}
	if got, want := i.StatusMessage(), "Disabled by user at 2026-11-27T08:59:36Z"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}

	// Turning it back on clears the code with the message.
	i.SetStatus(StatusPending)
	i.SetStatusMessage("")
	if i.StatusCode() != "" {
		t.Fatalf("code after enable = %q, want empty", i.StatusCode())
	}
}
