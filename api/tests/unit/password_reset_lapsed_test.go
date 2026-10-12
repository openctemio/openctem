package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
)

type stubLapsed struct {
	lapsed map[string]bool
	err    error
}

func (s stubLapsed) IsLapsedSSODomain(_ context.Context, d string) (bool, error) {
	return s.lapsed[d], s.err
}

// A domain whose verified owner lost it (RFC-058): its mailboxes may have
// changed hands, so no reset link is mailed there. The answer matches an
// unknown address (no enumeration).
func TestForgotPassword_LapsedDomain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		checker stubLapsed
		token   bool
	}{
		{"held domain", stubLapsed{lapsed: map[string]bool{}}, true},
		{"lapsed domain", stubLapsed{lapsed: map[string]bool{"lapsed.example": true}}, false},
		{"lookup failure", stubLapsed{err: errors.New("db down")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, deps := newTestAuthService()
			svc.SetLapsedDomainChecker(tc.checker)
			seedAuthLocalUser(deps.userRepo, "user@lapsed.example", "hash")
			res, err := svc.ForgotPassword(context.Background(), auth.ForgotPasswordInput{Email: "user@lapsed.example"})
			if err != nil || res == nil {
				t.Fatalf("anti-enumeration: no error expected, got %v", err)
			}
			if (res.Token != "") != tc.token {
				t.Fatalf("token issued = %v, want %v", res.Token != "", tc.token)
			}
		})
	}
}
