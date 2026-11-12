package unit

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/password"
)

// Emailed tokens carry no "=": mail clients drop a trailing "=" from a link,
// so a padded token's hash used to miss.
func TestEmailedTokensAreUnpadded(t *testing.T) {
	for i := 0; i < 50; i++ {
		for name, gen := range map[string]func() (string, error){
			"reset": password.GenerateResetToken, "verify": password.GenerateVerificationToken,
		} {
			tok, err := gen()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(tok, "=") || len(tok) != 43 {
				t.Fatalf("%s token %q must be 43 chars without padding", name, tok)
			}
		}
	}
}

// A token issued before the switch was stored hashed in padded form; its link
// arrives with the "=" stripped and must still work for one release.
func TestResetPassword_AcceptsStrippedPaddedToken(t *testing.T) {
	svc, deps := newTestAuthService()
	padded := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ="
	seedAuthUserWithResetToken(deps.userRepo, "legacy@example.com", "$2a$04$dummy", padded)
	if padded2, ok := crypto.PaddedTokenVariant(strings.TrimSuffix(padded, "=")); !ok || padded2 != padded {
		t.Fatalf("variant mismatch: %q %v", padded2, ok)
	}
	err := svc.ResetPassword(context.Background(), auth.ResetPasswordInput{
		Token: strings.TrimSuffix(padded, "="), NewPassword: "NewStrongPassword123!",
	})
	if err != nil {
		t.Fatalf("stripped padded token must still be accepted: %v", err)
	}
}
