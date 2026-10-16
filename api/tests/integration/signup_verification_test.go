package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// noSMTPConfigured reports that no SMTP server is configured anywhere.
type noSMTPConfigured struct{}

func (noSMTPConfigured) HasSystemSMTP() bool                        { return false }
func (noSMTPConfigured) HasTenantSMTP(context.Context, string) bool { return false }

// Under SIGNUP_MODE=open every self-registered account verifies its address,
// end to end on the database: missing SMTP does not skip it, and an
// organization whose email_verification_mode is "never" does not decide it,
// not even when the person presents that organization's invitation token for
// another address. The account row stays unverified.
func TestSelfRegistrationAlwaysVerifiesUnderPublicSignup(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	tenants := postgres.NewTenantRepository(db)

	// An organization that opted out of verification for its own invitees.
	inviter, _ := orgSelfServiceUser(t, db, orgAuthService(db, config.SignupModeOpen))
	var inviterID string
	if err := db.QueryRow(`SELECT id FROM users WHERE email = $1`, inviter).Scan(&inviterID); err != nil {
		t.Fatal(err)
	}
	org, err := tenant.NewTenant("Never Verify", "never-verify-"+uuid.NewString()[:8], inviterID)
	if err != nil {
		t.Fatal(err)
	}
	settings := org.TypedSettings()
	settings.Security.EmailVerificationMode = tenant.EmailVerificationNever
	if err := org.UpdateSettings(settings); err != nil {
		t.Fatal(err)
	}
	if err := tenants.Create(ctx, org); err != nil {
		t.Fatalf("create organization: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, org.ID().String()) })
	inv, err := tenant.NewInvitation(org.ID(), "invitee-"+uuid.NewString()[:8]+"@example.com", tenant.RoleMember,
		shared.MustIDFromString(inviterID), []string{"00000000-0000-0000-0000-000000000003"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tenants.CreateInvitation(ctx, inv); err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"no invitation", ""},
		{"another address's invitation token", inv.Token()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := orgAuthService(db, config.SignupModeOpen)
			svc.SetSMTPChecker(noSMTPConfigured{})
			email := "self-" + uuid.NewString()[:8] + "@example.com"
			t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE email = $1`, email) })
			res, err := svc.Register(ctx, authapp.RegisterInput{
				Email: email, Password: "Correct-Horse-9!", Name: "Self", InvitationToken: tc.token,
			})
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			if !res.RequiresVerification {
				t.Fatal("self-registration under SIGNUP_MODE=open must require verification")
			}
			var verified bool
			if err := db.QueryRow(`SELECT email_verified FROM users WHERE email = $1`, email).Scan(&verified); err != nil {
				t.Fatal(err)
			}
			if verified {
				t.Fatal("the stored account must stay unverified until the address is proved")
			}
		})
	}
}
