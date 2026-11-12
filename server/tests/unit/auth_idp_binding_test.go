package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/pkg/domain/session"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/user"
)

// An organization's identity provider vouches for a person in that
// organization only. A person who belongs to organizations A and B and signs
// in through A's IdP (which skips the account's own password and second
// factor) must not open B with that session: A's IdP administrator would
// otherwise control the person's access to B.

type idpBindingFixture struct {
	svc  *auth.AuthService
	deps *authTestDeps
	a, b *tenant.Tenant
	rt   string
	sid  string
	uid  shared.ID
}

// newIdPBindingFixture: a member of A and B (neither requires SSO or 2FA)
// whose session was issued by A's identity provider.
func newIdPBindingFixture(t *testing.T, roleInB string, bEnforced bool) *idpBindingFixture {
	t.Helper()
	svc, deps := newTestAuthService()
	a := mustNewEnforcedTenant(t, deps.tenantRepo, "bind-org-a", false)
	b := mustNewEnforcedTenant(t, deps.tenantRepo, "bind-org-b", bEnforced)
	deps.tenantRepo.userMemberships = memberOf(map[*tenant.Tenant]string{a: "member", b: roleInB})
	rt, sid := loginPassword(t, svc, deps, "shared@example.com")
	sess := deps.sessionRepo.sessions[sid]
	federate(sess, session.AuthMethodSAML, a.ID())
	return &idpBindingFixture{svc: svc, deps: deps, a: a, b: b, rt: rt, sid: sid, uid: sess.UserID()}
}

// makeIdPOnly turns the account into one an identity provider created: no
// password, no second factor, not a social account.
func (f *idpBindingFixture) makeIdPOnly() {
	old := f.deps.userRepo.users[f.uid.String()]
	now := time.Now().UTC()
	f.deps.userRepo.users[f.uid.String()] = user.Reconstitute(f.uid, nil, old.Email(), old.Name(), "", "",
		user.StatusActive, user.Preferences{}, nil, now, now, user.AuthProviderOIDC, nil, true, nil, nil, nil, nil, 0, nil)
}

func (f *idpBindingFixture) mint(t *testing.T, op string, tenantID shared.ID) error {
	t.Helper()
	ctx := context.Background()
	var err error
	if op == "exchange" {
		_, err = f.svc.ExchangeToken(ctx, auth.ExchangeTokenInput{RefreshToken: f.rt, TenantID: tenantID.String()})
	} else {
		_, err = f.svc.RefreshToken(ctx, auth.RefreshTokenInput{RefreshToken: f.rt, TenantID: tenantID.String()})
	}
	return err
}

func TestIdPBinding_ForeignIdPSessionCannotOpenAnotherOrganization(t *testing.T) {
	for _, op := range []string{"exchange", "refresh"} {
		for _, role := range []string{"member", "admin", "owner"} {
			t.Run(op+"/"+role, func(t *testing.T) {
				f := newIdPBindingFixture(t, role, false)
				if err := f.mint(t, op, f.b.ID()); !errors.Is(err, auth.ErrOwnSignInRequired) {
					t.Fatalf("org A IdP session -> org B: want ErrOwnSignInRequired, got %v", err)
				}
			})
		}
		t.Run(op+"/issuing organization still admits its own IdP session", func(t *testing.T) {
			f := newIdPBindingFixture(t, "member", false)
			if err := f.mint(t, op, f.a.ID()); err != nil {
				t.Fatalf("org A IdP session -> org A: want allowed, got %v", err)
			}
		})
	}
}

// The same rule holds per request on /tenants/{tenant}/... routes, which
// accept a token minted for another organization.
func TestIdPBinding_CheckEntryRefusesForeignIdPSession(t *testing.T) {
	f := newIdPBindingFixture(t, "member", false)
	for _, tn := range []*tenant.Tenant{f.a, f.b} {
		m, merr := tenant.NewMembership(f.uid, tn.ID(), tenant.RoleMember, nil)
		if merr != nil {
			t.Fatal(merr)
		}
		f.deps.tenantRepo.memberships = append(f.deps.tenantRepo.memberships, m)
	}
	err := f.svc.CheckEntry(context.Background(), f.sid, f.uid.String(), f.b.ID().String())
	var refusal *auth.EntryRefusal
	if !errors.As(err, &refusal) || refusal.ErrorCode() != string(auth.CodeOwnSignInRequired) || refusal.HTTPStatus() != 403 {
		t.Fatalf("want a 403 %s refusal, got %v", auth.CodeOwnSignInRequired, err)
	}
	if err := f.svc.CheckEntry(context.Background(), f.sid, f.uid.String(), f.a.ID().String()); err != nil {
		t.Fatalf("issuing organization: want allowed, got %v", err)
	}
}

// A password session (the account's own sign-in) is not affected.
func TestIdPBinding_PasswordSessionUnaffected(t *testing.T) {
	f := newIdPBindingFixture(t, "member", false)
	f.deps.sessionRepo.sessions[f.sid].SetAuthMethod(session.AuthMethodPassword)
	f.deps.sessionRepo.sessions[f.sid].SetIDPTenant(shared.ID{})
	if err := f.mint(t, "exchange", f.b.ID()); err != nil {
		t.Fatalf("password session -> org B: want allowed, got %v", err)
	}
}

// An account an identity provider created has no sign-in of its own for the
// IdP to skip: B admitted that account as it is, and it keeps working.
func TestIdPBinding_IdPOnlyAccountKeepsAccess(t *testing.T) {
	f := newIdPBindingFixture(t, "member", false)
	f.makeIdPOnly()
	if err := f.mint(t, "exchange", f.b.ID()); err != nil {
		t.Fatalf("IdP-only account -> org B: want allowed, got %v", err)
	}
}

// A second factor proven by A's IdP is A's business: it never satisfies an
// owner break-glass into B, which requires SSO (B wants the owner's own
// password AND own factor).
func TestIdPBinding_ForeignIdPMFAEvidenceDoesNotOpenBreakGlass(t *testing.T) {
	f := newIdPBindingFixture(t, "owner", true)
	f.makeIdPOnly()
	f.deps.sessionRepo.sessions[f.sid].SetMFAEvidence(true)
	if err := f.mint(t, "exchange", f.b.ID()); !errors.Is(err, auth.ErrSSOBreakGlassNeedsMFA) {
		t.Fatalf("org A IdP session with A's MFA evidence -> SSO-enforced org B as owner: want ErrSSOBreakGlassNeedsMFA, got %v", err)
	}
}

// Deleting the account or signing it out everywhere reaches every
// organization: an organization IdP's session may not do it for an account
// that has its own sign-in.
func TestIdPBinding_AccountActionsNeedOwnSignIn(t *testing.T) {
	ctx := context.Background()
	t.Run("organization IdP session, account with a password: refused", func(t *testing.T) {
		f := newIdPBindingFixture(t, "member", false)
		got, err := f.svc.OwnSignInRequired(ctx, f.uid.String(), f.sid)
		if err != nil || !got {
			t.Fatalf("want required, got %v %v", got, err)
		}
	})
	t.Run("password session: allowed", func(t *testing.T) {
		f := newIdPBindingFixture(t, "member", false)
		f.deps.sessionRepo.sessions[f.sid].SetAuthMethod(session.AuthMethodPassword)
		f.deps.sessionRepo.sessions[f.sid].SetIDPTenant(shared.ID{})
		got, err := f.svc.OwnSignInRequired(ctx, f.uid.String(), f.sid)
		if err != nil || got {
			t.Fatalf("want not required, got %v %v", got, err)
		}
	})
	t.Run("account the IdP created: allowed", func(t *testing.T) {
		f := newIdPBindingFixture(t, "member", false)
		f.makeIdPOnly()
		got, err := f.svc.OwnSignInRequired(ctx, f.uid.String(), f.sid)
		if err != nil || got {
			t.Fatalf("want not required, got %v %v", got, err)
		}
	})
	t.Run("session of another user: error", func(t *testing.T) {
		f := newIdPBindingFixture(t, "member", false)
		if _, err := f.svc.OwnSignInRequired(ctx, shared.NewID().String(), f.sid); err == nil {
			t.Fatal("want an error for a session of another user")
		}
	})
}

// A token minted for A, used on B's /tenants/{B}/... routes, meets B's
// verified-email rule exactly as a token minted for B would.
func TestCheckEntry_AppliesTheOrganizationsEmailVerificationRule(t *testing.T) {
	f := newIdPBindingFixture(t, "member", false)
	sess := f.deps.sessionRepo.sessions[f.sid]
	sess.SetAuthMethod(session.AuthMethodPassword)
	sess.SetIDPTenant(shared.ID{})
	for _, tn := range []*tenant.Tenant{f.a, f.b} {
		m, err := tenant.NewMembership(f.uid, tn.ID(), tenant.RoleMember, nil)
		if err != nil {
			t.Fatal(err)
		}
		f.deps.tenantRepo.memberships = append(f.deps.tenantRepo.memberships, m)
	}
	st := f.b.TypedSettings()
	st.Security.EmailVerificationMode = tenant.EmailVerificationAlways
	if err := f.b.UpdateSettings(st); err != nil {
		t.Fatal(err)
	}
	old := f.deps.userRepo.users[f.uid.String()]
	now := time.Now().UTC()
	f.deps.userRepo.users[f.uid.String()] = user.Reconstitute(f.uid, nil, old.Email(), old.Name(), "", "",
		user.StatusActive, user.Preferences{}, nil, now, now, user.AuthProviderLocal, old.PasswordHash(), false, nil, nil, nil, nil, 0, nil)

	var refusal *auth.EntryRefusal
	err := f.svc.CheckEntry(context.Background(), f.sid, f.uid.String(), f.b.ID().String())
	if !errors.As(err, &refusal) || refusal.ErrorCode() != "EMAIL_NOT_VERIFIED" {
		t.Fatalf("unverified account on B (verification always): want EMAIL_NOT_VERIFIED, got %v", err)
	}
	if err := f.svc.CheckEntry(context.Background(), f.sid, f.uid.String(), f.a.ID().String()); err != nil {
		t.Fatalf("A does not require verification: want allowed, got %v", err)
	}
}
