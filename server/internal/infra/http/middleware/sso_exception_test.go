package middleware

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type stubSSOWithExceptions struct {
	stubSSOEnforced
	excepted map[string]bool // tenant|user
	err      error
}

func (s *stubSSOWithExceptions) HasSSOException(_ context.Context, tenantID, userID string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.excepted[tenantID+"|"+userID], nil
}

// A member with an SSO exception (RFC-058) passes the per-request gate of an
// SSO-enforced tenant with a password token; others, and lookup failures, do
// not.
func TestSSOEnforcement_Exception(t *testing.T) {
	p := &stubSSOWithExceptions{stubSSOEnforced: stubSSOEnforced{enforced: map[string]bool{"t": true}},
		excepted: map[string]bool{"t|u1": true}}
	if code, reached := runEnforce(t, p, passwordClaims("t", "member")); code != http.StatusOK || !reached {
		t.Fatalf("excepted member: code=%d reached=%v", code, reached)
	}
	other := passwordClaims("t", "member")
	other.UserID = "u2"
	if code, _ := runEnforce(t, p, other); code != http.StatusForbidden {
		t.Fatalf("member without an exception: code=%d, want 403", code)
	}
	p.err = errors.New("db down")
	if code, _ := runEnforce(t, p, passwordClaims("t", "member")); code != http.StatusForbidden {
		t.Fatalf("lookup failure must fail closed: code=%d", code)
	}
}
