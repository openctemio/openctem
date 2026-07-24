package unit

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestAuthMethod_Semantics locks the value-object behavior the SSO-enforcement
// gate relies on: which methods are federated, and the fail-safe defaulting.
func TestAuthMethod_Semantics(t *testing.T) {
	if !session.AuthMethodSSO.IsFederated() {
		t.Error("sso must be federated")
	}
	if !session.AuthMethodSAML.IsFederated() {
		t.Error("saml must be federated")
	}
	if session.AuthMethodPassword.IsFederated() {
		t.Error("password must NOT be federated")
	}
	if session.AuthMethod("").IsFederated() {
		t.Error("empty method must NOT be federated (fail-closed)")
	}

	// FromString maps known values and defaults everything else to password.
	if got := session.AuthMethodFromString("sso"); got != session.AuthMethodSSO {
		t.Errorf("FromString(sso) = %q", got)
	}
	if got := session.AuthMethodFromString("saml"); got != session.AuthMethodSAML {
		t.Errorf("FromString(saml) = %q", got)
	}
	if got := session.AuthMethodFromString(""); got != session.AuthMethodPassword {
		t.Errorf("FromString(empty) = %q, want password", got)
	}
	if got := session.AuthMethodFromString("garbage"); got != session.AuthMethodPassword {
		t.Errorf("FromString(garbage) = %q, want password (fail-safe)", got)
	}
}

// TestSession_AuthMethod_Default confirms a freshly created session defaults to
// password (so the password login path needs no explicit stamp).
func TestSession_AuthMethod_Default(t *testing.T) {
	s, err := session.New(shared.NewID(), "token", "127.0.0.1", "ua", time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.AuthMethod() != session.AuthMethodPassword {
		t.Errorf("default auth method = %q, want password", s.AuthMethod())
	}

	// Federated flows stamp explicitly before persistence.
	s.SetAuthMethod(session.AuthMethodSSO)
	if s.AuthMethod() != session.AuthMethodSSO {
		t.Errorf("after SetAuthMethod(sso) = %q", s.AuthMethod())
	}
}

// TestSession_Reconstitute_RoundTrip proves the repository round-trip preserves
// the auth method, and that an empty persisted value defaults to password
// (backward compatibility with rows written before the column existed).
func TestSession_Reconstitute_RoundTrip(t *testing.T) {
	now := time.Now()
	for _, m := range []session.AuthMethod{
		session.AuthMethodPassword, session.AuthMethodSSO, session.AuthMethodSAML,
	} {
		s := session.Reconstitute(
			shared.NewID(), shared.NewID(), "hash", "1.2.3.4", "ua", "",
			now.Add(time.Hour), now, session.StatusActive, m, now, now,
		)
		if s.AuthMethod() != m {
			t.Errorf("round-trip %q = %q", m, s.AuthMethod())
		}
	}

	// Empty persisted method (legacy row) → password.
	legacy := session.Reconstitute(
		shared.NewID(), shared.NewID(), "hash", "1.2.3.4", "ua", "",
		now.Add(time.Hour), now, session.StatusActive, session.AuthMethod(""), now, now,
	)
	if legacy.AuthMethod() != session.AuthMethodPassword {
		t.Errorf("legacy empty method = %q, want password", legacy.AuthMethod())
	}
}
