package adminconsole

// A super admin who can mint an IdP token carrying another administrator's
// email must not become that administrator (and so approve their own
// four-eyes requests): the identity is bound only after the target's own
// console second factor, and a trusted ACR/AMR never stands in for it on a
// first sign-in.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/totp"
)

func TestIdPTakeoverByEmailIsRefused(t *testing.T) {
	b := newBGHarness(t)
	ctx := context.Background()
	// Victim B: a super admin who enrolled the console TOTP on /login.
	victim, victimRefresh := b.addAdmin(t, "b@acme.io", admin.AdminRoleSuperAdmin, false)
	if _, err := b.signIn(t, victimRefresh); err != nil {
		t.Fatalf("victim enrollment: %v", err)
	}
	// The IdP trusts amr=pwd: before the fix this skipped the console factor.
	b.configureIdP(t, func(i *PlatformIdPInput) { i.TrustedAMRValues = []string{"pwd"} })

	claims := verifiedClaims("sub-attacker", "b@acme.io")
	claims["amr"] = []string{"pwd"}
	res, err := b.idpSignIn(t, claims)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if res.Status == StatusSignedIn || res.SessionToken != "" {
		t.Fatalf("a first IdP sign-in must not open a verified session: %+v", res)
	}
	if res.Status != StatusMFARequired || res.Second == nil || res.Second.Secret != "" {
		t.Fatalf("the victim's own enrolled factor must be asked, never a new enrollment: %+v", res)
	}
	a, _ := b.admins.GetByID(ctx, victim.ID())
	if a.IdPBound() {
		t.Fatal("the attacker's identity must not be bound to the victim")
	}
	// A wrong code does not bind either.
	if _, _, err := b.svc.VerifyMFA(ctx, res.Second.PendingToken, "000000", client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("wrong code: %v", err)
	}
	// A second try with the same identity is still a first sign-in: amr=pwd
	// does not open a session for an unbound identity.
	res, err = b.idpSignIn(t, claims)
	if err != nil || res.Status == StatusSignedIn {
		t.Fatalf("second attempt must still need the console factor: %v %+v", err, res)
	}
	if a, _ := b.admins.GetByID(ctx, victim.ID()); a.IdPBound() {
		t.Fatal("still unbound")
	}
}

func TestIdPBindingNeedsTheAdminsOwnFactorAndIsSingle(t *testing.T) {
	b := newBGHarness(t)
	ctx := context.Background()
	secret, _ := b.enroll(t) // ops@acme.io, the harness admin
	b.configureIdP(t, nil)

	// Two first sign-ins race with different subjects for the same email.
	first, err := b.idpSignIn(t, verifiedClaims("sub-1", "ops@acme.io"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.idpSignIn(t, verifiedClaims("sub-2", "ops@acme.io"))
	if err != nil {
		t.Fatal(err)
	}
	b.clock = b.clock.Add(31 * time.Second) // the enrollment code's step is spent
	code, _ := totp.Code(secret, b.clock)
	if _, _, err := b.svc.VerifyMFA(ctx, first.Second.PendingToken, code, client); err != nil {
		t.Fatalf("first confirmation: %v", err)
	}
	b.clock = b.clock.Add(31 * time.Second)
	code, _ = totp.Code(secret, b.clock)
	if _, _, err := b.svc.VerifyMFA(ctx, second.Second.PendingToken, code, client); !errors.Is(err, admin.ErrIdPSignInFailed) {
		t.Fatalf("the second identity must not bind or sign in: %v", err)
	}
	a, _ := b.admins.GetByID(ctx, b.admin.ID())
	if st := a.SignInState(); st.IdPSubject != "sub-1" {
		t.Fatalf("expected sub-1 bound, got %+v", st)
	}
}

func TestPendingBindingDroppedWhenIssuerChanges(t *testing.T) {
	b := newBGHarness(t)
	ctx := context.Background()
	secret, _ := b.enroll(t)
	b.configureIdP(t, nil)
	res, err := b.idpSignIn(t, verifiedClaims("sub-1", "ops@acme.io"))
	if err != nil {
		t.Fatal(err)
	}
	other := newMockIdP(t)
	b.configureIdP(t, func(i *PlatformIdPInput) { i.Issuer = other.issuer })
	b.clock = b.clock.Add(31 * time.Second)
	code, _ := totp.Code(secret, b.clock)
	if _, _, err := b.svc.VerifyMFA(ctx, res.Second.PendingToken, code, client); !errors.Is(err, admin.ErrIdPSignInFailed) {
		t.Fatalf("a binding for the old issuer must not complete: %v", err)
	}
	if a, _ := b.admins.GetByID(ctx, b.admin.ID()); a.IdPBound() {
		t.Fatal("must stay unbound")
	}
}

func TestPlatformIdPChangeApproval(t *testing.T) {
	base := PlatformIdPInput{
		Enabled: true, DisplayName: "Corp", Issuer: "https://idp.example.com", ClientID: "console",
		ClientSecret: "x", RedirectURI: "https://console.example/cb",
	}
	cur := &admin.PlatformIdP{Issuer: base.Issuer, ClientID: base.ClientID, TrustedAMRValues: []string{"mfa"}}

	cases := []struct {
		name   string
		cur    *admin.PlatformIdP
		mutate func(*PlatformIdPInput)
		need   bool
	}{
		{"first config, no trust", nil, nil, false},
		{"first config with trusted amr", nil, func(i *PlatformIdPInput) { i.TrustedAMRValues = []string{"pwd"} }, true},
		{"unchanged", cur, func(i *PlatformIdPInput) { i.TrustedAMRValues = []string{"mfa"} }, false},
		{"trust removed", cur, nil, false},
		{"display name only", cur, func(i *PlatformIdPInput) { i.DisplayName = "New"; i.TrustedAMRValues = []string{"mfa"} }, false},
		{"issuer changed", cur, func(i *PlatformIdPInput) { i.Issuer = "https://evil.example.com"; i.TrustedAMRValues = []string{"mfa"} }, true},
		{"client changed", cur, func(i *PlatformIdPInput) { i.ClientID = "other"; i.TrustedAMRValues = []string{"mfa"} }, true},
		{"amr added", cur, func(i *PlatformIdPInput) { i.TrustedAMRValues = []string{"mfa", "pwd"} }, true},
		{"acr added", cur, func(i *PlatformIdPInput) { i.TrustedAMRValues = []string{"mfa"}; i.TrustedACRValues = []string{"x"} }, true},
	}
	for _, c := range cases {
		in := base
		if c.mutate != nil {
			c.mutate(&in)
		}
		target, need := PlatformIdPChangeApproval(c.cur, in)
		if need != c.need {
			t.Fatalf("%s: need=%v, want %v", c.name, need, c.need)
		}
		if need && !admin.ApprovalPlatformIdPChange.ValidTarget(target) {
			t.Fatalf("%s: target %q must be a valid approval target", c.name, target)
		}
	}
	// The target binds the exact values: another amr is another target.
	a := base
	a.TrustedAMRValues = []string{"pwd"}
	bIn := base
	bIn.TrustedAMRValues = []string{"otp"}
	ta, _ := PlatformIdPChangeApproval(nil, a)
	tb, _ := PlatformIdPChangeApproval(nil, bIn)
	if ta == tb {
		t.Fatal("different trusted values must give different targets")
	}
}
