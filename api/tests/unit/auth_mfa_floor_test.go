package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/platformmfa"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/password"
)

type floorStub struct {
	p   platformmfa.Policy
	err error
}

func (f *floorStub) Policy(context.Context) (platformmfa.Policy, error) { return f.p, f.err }

type privStub struct {
	perms []string
	full  bool
}

func (p privStub) GetUserPermissions(context.Context, string, string) ([]string, error) {
	return p.perms, nil
}
func (p privStub) HasFullDataAccess(context.Context, string, string) (bool, error) {
	return p.full, nil
}

// floorFixture is one organization with no 2FA rule of its own, one member
// of it (created createdAgo ago) holding role, and a plain password session.
type floorFixture struct {
	h     *mfaHarness
	tn    *tenant.Tenant
	uid   shared.ID
	email string
	res   *auth.LoginResult
	floor *floorStub
}

func newFloorFixture(t *testing.T, role string, createdAgo time.Duration, floor tenant.MFAFloor, effectiveFrom time.Time) *floorFixture {
	t.Helper()
	h := newMFAHarness(t)
	tn := newPolicyTenant(t, h.tenants, "floor-"+role, false)
	pre := tn.TypedSettings()
	pre.Security.MFARequiredForAdmins = false
	_ = tn.UpdateSettings(pre)
	h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: role}}

	hash, _ := password.New(password.WithCost(4)).Hash(mfaTestPassword)
	email := role + "@example.com"
	created := time.Now().UTC().Add(-createdAgo)
	u := user.Reconstitute(shared.NewID(), nil, email, "Test User", "", "", user.StatusActive, user.Preferences{}, nil,
		created, created, user.AuthProviderLocal, &hash, true, nil, nil, nil, nil, 0, nil)
	h.users.users[u.ID().String()] = u
	ms, _ := tenant.NewMembership(u.ID(), tn.ID(), tenant.Role(role), nil)
	h.tenants.memberships = append(h.tenants.memberships, ms)

	res := h.login(t, email) // no floor yet: a plain session
	f := &floorStub{p: platformmfa.Policy{Floor: floor, GraceExistingDays: 14, GraceNewDays: 7, EffectiveFrom: effectiveFrom}}
	h.svc.SetMFAFloor(f, privStub{})
	return &floorFixture{h: h, tn: tn, uid: u.ID(), email: email, res: res, floor: f}
}

func (f *floorFixture) exchange() error {
	_, err := f.h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: f.res.RefreshToken, TenantID: f.tn.ID().String()})
	return err
}

func (f *floorFixture) credential() error {
	return f.h.svc.CheckCredentialFactor(context.Background(), f.uid.String(), f.tn.ID().String(), f.res.SessionID)
}

// The floor gates administrators after their grace period, members only when
// it is "everyone", and nobody when it is none; the organization's own
// settings are never lowered by it.
func TestMFAFloor_GateByRoleAndFloor(t *testing.T) {
	past := time.Now().Add(-30 * 24 * time.Hour) // grace over
	cases := []struct {
		name  string
		role  string
		floor tenant.MFAFloor
		gated bool
	}{
		{"admins floor gates an admin", "admin", tenant.MFAFloorAdmins, true},
		{"admins floor gates an owner", "owner", tenant.MFAFloorAdmins, true},
		{"admins floor leaves a member alone", "member", tenant.MFAFloorAdmins, false},
		{"everyone floor gates a member", "member", tenant.MFAFloorEveryone, true},
		{"none floor gates nobody", "admin", tenant.MFAFloorNone, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFloorFixture(t, c.role, 400*24*time.Hour, c.floor, past)
			err := f.exchange()
			if c.gated && !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
				t.Fatalf("exchange: %v, want ErrMFAEnrollmentRequired", err)
			}
			if !c.gated && err != nil {
				t.Fatalf("exchange: %v, want a token", err)
			}
		})
	}
}

// A member who holds a privileged role (through any grant) counts as an
// administrator for the floor; the base role alone would have missed them.
func TestMFAFloor_PrivilegedRoleCountsAsAdministrator(t *testing.T) {
	past := time.Now().Add(-30 * 24 * time.Hour)
	plain := newFloorFixture(t, "member", 400*24*time.Hour, tenant.MFAFloorAdmins, past)
	if err := plain.exchange(); err != nil {
		t.Fatalf("plain member: %v", err)
	}
	priv := newFloorFixture(t, "member", 400*24*time.Hour, tenant.MFAFloorAdmins, past)
	priv.h.svc.SetMFAFloor(priv.floor, privStub{perms: []string{string(permission.RolesWrite)}})
	if err := priv.exchange(); !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
		t.Fatalf("member with a privileged role: %v, want ErrMFAEnrollmentRequired", err)
	}
}

// During grace the floor does not gate sign-in (existing members 14 days from
// effective_from, new accounts 7 days from creation), but creating a
// credential already needs a factor.
func TestMFAFloor_GraceAndCredentialRule(t *testing.T) {
	now := time.Now()
	t.Run("existing member inside the 14 days", func(t *testing.T) {
		f := newFloorFixture(t, "admin", 400*24*time.Hour, tenant.MFAFloorAdmins, now.Add(-3*24*time.Hour))
		if err := f.exchange(); err != nil {
			t.Fatalf("sign-in during grace: %v", err)
		}
		if err := f.credential(); !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
			t.Fatalf("credential during grace: %v, want ErrMFAEnrollmentRequired", err)
		}
		st, err := f.h.svc.GetMFAStatus(context.Background(), f.uid.String())
		if err != nil || st.RequiredByOrganization || st.GraceDueAt == nil {
			t.Fatalf("status %+v err %v: want a grace due date and no gate", st, err)
		}
		if want := now.Add(-3*24*time.Hour).AddDate(0, 0, 14); st.GraceDueAt.Sub(want) > time.Minute || want.Sub(*st.GraceDueAt) > time.Minute {
			t.Fatalf("due %v, want about %v", st.GraceDueAt, want)
		}
	})
	t.Run("new account keeps its own 7 days after the 14 are over", func(t *testing.T) {
		f := newFloorFixture(t, "admin", 2*24*time.Hour, tenant.MFAFloorAdmins, now.Add(-30*24*time.Hour))
		if err := f.exchange(); err != nil {
			t.Fatalf("new account inside 7 days: %v", err)
		}
	})
	t.Run("after the due date sign-in is gated", func(t *testing.T) {
		f := newFloorFixture(t, "admin", 400*24*time.Hour, tenant.MFAFloorAdmins, now.Add(-15*24*time.Hour))
		if err := f.exchange(); !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
			t.Fatalf("after grace: %v", err)
		}
	})
	t.Run("an organization's own requirement has no grace", func(t *testing.T) {
		f := newFloorFixture(t, "member", 400*24*time.Hour, tenant.MFAFloorNone, time.Time{})
		st := f.tn.TypedSettings()
		st.Security.MFARequired = true
		_ = f.tn.UpdateSettings(st)
		if err := f.exchange(); !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
			t.Fatalf("organization requirement: %v", err)
		}
	})
}

// An enrolled factor satisfies the gate and the credential rule; the
// requirement does not apply to someone the floor does not cover.
func TestMFAFloor_EnrolledAndUncoveredUsersPass(t *testing.T) {
	f := newFloorFixture(t, "admin", 400*24*time.Hour, tenant.MFAFloorAdmins, time.Now().Add(-30*24*time.Hour))
	f.h.mfa.factors[f.uid.String()] = &mfa.Factor{UserID: f.uid, Enabled: true}
	if err := f.credential(); err != nil {
		t.Fatalf("enrolled admin creating a credential: %v", err)
	}
	g := newFloorFixture(t, "member", 400*24*time.Hour, tenant.MFAFloorAdmins, time.Now().Add(-30*24*time.Hour))
	if err := g.credential(); err != nil {
		t.Fatalf("an uncovered member needs no factor: %v", err)
	}
}

// Sign-in method rules, shared with the organization's own policy: the
// organization's own IdP counts unless the organization requires proof,
// a social sign-in never counts.
func TestMFAFloor_SessionKinds(t *testing.T) {
	past := time.Now().Add(-30 * 24 * time.Hour)
	setup := func(t *testing.T, method session.AuthMethod, own, evidence bool) *floorFixture {
		f := newFloorFixture(t, "admin", 400*24*time.Hour, tenant.MFAFloorAdmins, past)
		sess := f.h.sessions.sessions[f.res.SessionID]
		sess.SetAuthMethod(method)
		if own {
			sess.SetIDPTenant(f.tn.ID())
		}
		sess.SetMFAEvidence(evidence)
		return f
	}
	t.Run("own IdP session passes", func(t *testing.T) {
		f := setup(t, session.AuthMethodSSO, true, false)
		if err := f.exchange(); err != nil {
			t.Fatalf("own IdP: %v", err)
		}
		if err := f.credential(); err != nil {
			t.Fatalf("own IdP credential: %v", err)
		}
	})
	t.Run("own IdP without proof is refused when the organization requires proof", func(t *testing.T) {
		f := setup(t, session.AuthMethodSSO, true, false)
		st := f.tn.TypedSettings()
		st.Security.SSORequireMFAEvidence = true
		_ = f.tn.UpdateSettings(st)
		if err := f.exchange(); !errors.Is(err, auth.ErrSSOMFAEvidenceRequired) {
			t.Fatalf("own IdP without proof: %v", err)
		}
		f.h.sessions.sessions[f.res.SessionID].SetMFAEvidence(true)
		if err := f.exchange(); err != nil {
			t.Fatalf("own IdP with proof: %v", err)
		}
	})
	t.Run("social sign-in never counts, even for an enrolled user", func(t *testing.T) {
		f := setup(t, session.AuthMethodSSO, false, true)
		f.h.mfa.factors[f.uid.String()] = &mfa.Factor{UserID: f.uid, Enabled: true}
		if err := f.exchange(); !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
			t.Fatalf("social session: %v", err)
		}
		if err := f.credential(); !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
			t.Fatalf("social session credential: %v", err)
		}
	})
}

// An unreadable platform floor never means "none": the mint gate refuses.
func TestMFAFloor_UnreadableFloorFailsClosed(t *testing.T) {
	f := newFloorFixture(t, "admin", 400*24*time.Hour, tenant.MFAFloorAdmins, time.Now())
	f.floor.err = errors.New("store down")
	if err := f.exchange(); err == nil {
		t.Fatal("a token was minted on an unreadable platform floor")
	}
}

// Login under an administrator floor offers enrollment only once the grace
// period is over; a member the floor does not cover is not asked.
func TestMFAFloor_LoginChallenge(t *testing.T) {
	f := newFloorFixture(t, "admin", 400*24*time.Hour, tenant.MFAFloorAdmins, time.Now().Add(-30*24*time.Hour))
	res := f.h.login(t, f.email)
	if res.MFAChallenge == nil || res.MFAChallenge.Purpose != mfa.PurposeEnroll {
		t.Fatalf("admin after grace must be sent to enrollment: %+v", res)
	}
	g := newFloorFixture(t, "admin", 400*24*time.Hour, tenant.MFAFloorAdmins, time.Now().Add(-1*24*time.Hour))
	if res := g.h.login(t, g.email); res.MFAChallenge != nil {
		t.Fatalf("admin inside grace must sign in without a challenge: %+v", res.MFAChallenge)
	}
}
