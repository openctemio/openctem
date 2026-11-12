package exposure

import (
	"slices"
	"testing"
)

// identityEventTypes are the identity attack-surface exposure types emitted by
// the EntraID/IdP identity-exposure discovery source (RFC-018).
var identityEventTypes = []EventType{
	EventTypeIdentityMFAGap,
	EventTypeIdentityStalePrincipal,
	EventTypeIdentityOverprivileged,
}

func TestIdentityEventTypes_AreValid(t *testing.T) {
	for _, et := range identityEventTypes {
		if !et.IsValid() {
			t.Errorf("event type %q should be valid", et)
		}
		if !slices.Contains(AllEventTypes(), et) {
			t.Errorf("event type %q missing from AllEventTypes()", et)
		}
	}
}

func TestIdentityEventTypes_StableStrings(t *testing.T) {
	// The string form is persisted (event_type column) and matched by the
	// migration CHECK constraint — it must not drift.
	want := map[EventType]string{
		EventTypeIdentityMFAGap:         "identity_mfa_gap",
		EventTypeIdentityStalePrincipal: "identity_stale_principal",
		EventTypeIdentityOverprivileged: "identity_overprivileged",
	}
	for et, s := range want {
		if et.String() != s {
			t.Errorf("event type string = %q, want %q", et.String(), s)
		}
		parsed, err := ParseEventType(s)
		if err != nil {
			t.Errorf("ParseEventType(%q) returned error: %v", s, err)
		}
		if parsed != et {
			t.Errorf("ParseEventType(%q) = %q, want %q", s, parsed, et)
		}
	}
}

func TestIdentityEventTypes_IncreaseExposure(t *testing.T) {
	// Identity posture weaknesses represent increased exposure (like a leaked
	// credential or misconfiguration), never a reduction.
	for _, et := range identityEventTypes {
		if !et.IsPositiveExposure() {
			t.Errorf("event type %q should be a positive (exposure-increasing) event", et)
		}
	}
}
