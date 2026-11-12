package securityoverview

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func find(t *testing.T, o *Overview, id string) Check {
	t.Helper()
	for _, c := range o.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %s missing", id)
	return Check{}
}

func has(o *Overview, id string) bool {
	for _, c := range o.Checks {
		if c.ID == id {
			return true
		}
	}
	return false
}

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func TestSettingsChecks(t *testing.T) {
	cases := []struct {
		name string
		sec  tenant.SecuritySettings
		id   string
		want Status
	}{
		{"mfa none", tenant.SecuritySettings{}, CheckMFAAdminsRequired, StatusRisk},
		{"mfa for admins", tenant.SecuritySettings{MFARequiredForAdmins: true}, CheckMFAAdminsRequired, StatusPass},
		{"mfa for all", tenant.SecuritySettings{MFARequired: true}, CheckMFAAdminsRequired, StatusPass},
		{"verification auto", tenant.SecuritySettings{EmailVerificationMode: tenant.EmailVerificationAuto}, CheckEmailVerification, StatusPass},
		{"verification empty", tenant.SecuritySettings{}, CheckEmailVerification, StatusPass},
		{"verification always", tenant.SecuritySettings{EmailVerificationMode: tenant.EmailVerificationAlways}, CheckEmailVerification, StatusPass},
		{"verification never", tenant.SecuritySettings{EmailVerificationMode: tenant.EmailVerificationNever}, CheckEmailVerification, StatusWarn},
		{"allowlist empty", tenant.SecuritySettings{}, CheckIPAllowlist, StatusInfo},
		{"allowlist set", tenant.SecuritySettings{IPWhitelist: []string{"192.0.2.0/24"}}, CheckIPAllowlist, StatusPass},
		{"opt-ins off", tenant.SecuritySettings{}, CheckSensorOptIns, StatusPass},
		{"interactsh on", tenant.SecuritySettings{AllowSensorInteractsh: true}, CheckSensorOptIns, StatusWarn},
		{"templates on", tenant.SecuritySettings{AllowSensorCustomTemplates: true}, CheckSensorOptIns, StatusWarn},
		{"private rule off", tenant.SecuritySettings{}, CheckPrivateTargetRule, StatusInfo},
		{"private rule on", tenant.SecuritySettings{RequireSensorLocalPolicyForPrivateTargets: true}, CheckPrivateTargetRule, StatusPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sec := tc.sec
			if got := find(t, Evaluate(&sec, nil, now), tc.id).Status; got != tc.want {
				t.Fatalf("%s = %s, want %s", tc.id, got, tc.want)
			}
		})
	}
}

func TestCountChecks(t *testing.T) {
	type tc struct {
		id         string
		set        func(*Counts, int)
		whenZero   Status
		whenOver   Status
		wantLink   string
		wantGroup  string
		countAware bool
	}
	cases := []tc{
		{CheckAdminsWithoutMFA, func(c *Counts, n int) { c.AdminsWithoutMFA = n }, StatusPass, StatusRisk, "/settings/members", GroupSignIn, true},
		{CheckDormantMembers, func(c *Counts, n int) { c.DormantMembers = n }, StatusPass, StatusWarn, "/settings/members", GroupPeople, true},
		{CheckJoinRequests, func(c *Counts, n int) { c.PendingJoinRequests = n }, StatusPass, StatusWarn, "/settings/members", GroupPeople, true},
		{CheckAPIKeysExpiring, func(c *Counts, n int) { c.APIKeysExpiring = n }, StatusPass, StatusWarn, "/settings/api-keys", GroupCredentials, true},
		{CheckAPIKeysUnused, func(c *Counts, n int) { c.APIKeysUnused = n }, StatusPass, StatusWarn, "/settings/api-keys", GroupCredentials, true},
		{CheckSupportAccess, func(c *Counts, n int) { c.ActiveSupportGrants = n }, StatusPass, StatusWarn, "/settings/support-access", GroupOrganization, true},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			zero := Counts{SCIMTokensActive: 1}
			ch := find(t, Evaluate(nil, &zero, now), c.id)
			if ch.Status != c.whenZero || ch.Count == nil || *ch.Count != 0 {
				t.Fatalf("zero: %+v", ch)
			}
			over := Counts{SCIMTokensActive: 1}
			c.set(&over, 3)
			ch = find(t, Evaluate(nil, &over, now), c.id)
			if ch.Status != c.whenOver || *ch.Count != 3 || ch.Link != c.wantLink || ch.Group != c.wantGroup {
				t.Fatalf("over: %+v", ch)
			}
		})
	}
}

func TestSCIMAndDomainChecks(t *testing.T) {
	// No token: informational. A token in use: pass. An unused token: warn.
	if st := find(t, Evaluate(nil, &Counts{}, now), CheckSCIMTokensUnused).Status; st != StatusInfo {
		t.Fatalf("no tokens = %s", st)
	}
	if st := find(t, Evaluate(nil, &Counts{SCIMTokensActive: 2}, now), CheckSCIMTokensUnused).Status; st != StatusPass {
		t.Fatalf("tokens in use = %s", st)
	}
	ch := find(t, Evaluate(nil, &Counts{SCIMTokensActive: 2, SCIMTokensUnused: 1}, now), CheckSCIMTokensUnused)
	if ch.Status != StatusWarn || *ch.Count != 1 || ch.Link != "/settings/scim" {
		t.Fatalf("unused token = %+v", ch)
	}
	if st := find(t, Evaluate(nil, &Counts{}, now), CheckVerifiedDomain).Status; st != StatusInfo {
		t.Fatalf("no domain = %s", st)
	}
	if st := find(t, Evaluate(nil, &Counts{VerifiedDomains: 1}, now), CheckVerifiedDomain).Status; st != StatusPass {
		t.Fatalf("domain = %s", st)
	}
}

func TestScoreMath(t *testing.T) {
	// Everything passes: 100.
	sec := tenant.SecuritySettings{MFARequiredForAdmins: true, IPWhitelist: []string{"192.0.2.1"}, RequireSensorLocalPolicyForPrivateTargets: true}
	o := Evaluate(&sec, &Counts{SCIMTokensActive: 1, VerifiedDomains: 1}, now)
	if o.Score != 100 || o.Counts.Risk != 0 || o.Counts.Warn != 0 || o.Counts.Info != 0 {
		t.Fatalf("all pass: %+v", o)
	}
	// One risk (admin without 2FA, weight 3) among 2 risk checks + 11 warning
	// checks: maxPenalty = 2*3 + 11 = 17, penalty = 3 -> round(82.35) = 82.
	o = Evaluate(&sec, &Counts{AdminsWithoutMFA: 1, SCIMTokensActive: 1, VerifiedDomains: 1}, now)
	if o.Score != 82 || o.Counts.Risk != 1 {
		t.Fatalf("one risk: score %d counts %+v", o.Score, o.Counts)
	}
	// One warning: penalty 1 of 17 -> round(94.12) = 94.
	o = Evaluate(&sec, &Counts{DormantMembers: 2, SCIMTokensActive: 1, VerifiedDomains: 1}, now)
	if o.Score != 94 || o.Counts.Warn != 1 {
		t.Fatalf("one warn: score %d", o.Score)
	}
	// Info is excluded from both sides.
	o = Evaluate(&tenant.SecuritySettings{MFARequiredForAdmins: true}, nil, now)
	if o.Counts.Info != 2 || o.Score != 100 {
		t.Fatalf("info: %+v", o)
	}
	// No scored checks at all: 100.
	if s := score(0, 0); s != 100 {
		t.Fatalf("empty score %d", s)
	}
	// Worst case.
	bad := tenant.SecuritySettings{EmailVerificationMode: tenant.EmailVerificationNever, AllowSensorInteractsh: true}
	o = Evaluate(&bad, &Counts{AdminsWithoutMFA: 1, DormantMembers: 1, PendingJoinRequests: 1, APIKeysExpiring: 1, APIKeysUnused: 1,
		SCIMTokensActive: 1, SCIMTokensUnused: 1, ActiveSupportGrants: 1}, now)
	if o.Score != 0 {
		t.Fatalf("worst case score %d, counts %+v", o.Score, o.Counts)
	}
}

func TestNilDependenciesOmitChecks(t *testing.T) {
	if o := Evaluate(nil, nil, now); len(o.Checks) != 0 || o.Score != 100 || o.Checks == nil {
		t.Fatalf("both nil: %+v", o)
	}
	o := Evaluate(&tenant.SecuritySettings{}, nil, now)
	if has(o, CheckDormantMembers) || !has(o, CheckMFAAdminsRequired) {
		t.Fatalf("settings only: %+v", o.Checks)
	}
	o = Evaluate(nil, &Counts{}, now)
	if has(o, CheckMFAAdminsRequired) || !has(o, CheckDormantMembers) {
		t.Fatalf("counts only: %+v", o.Checks)
	}
	if got := len(Evaluate(&tenant.SecuritySettings{}, &Counts{}, now).Checks); got != 13 {
		t.Fatalf("full overview has %d checks, want 13", got)
	}
}

type fakeCounter struct {
	tenant shared.ID
	err    error
}

func (f *fakeCounter) Counts(_ context.Context, id shared.ID, _ time.Time) (Counts, error) {
	f.tenant = id
	return Counts{AdminsWithoutMFA: 1}, f.err
}

func TestGetUsesTheGivenTenantAndFailsClosed(t *testing.T) {
	fc := &fakeCounter{}
	svc := NewService(nil, fc)
	id := shared.NewID()
	o, err := svc.Get(context.Background(), id)
	if err != nil || fc.tenant != id || find(t, o, CheckAdminsWithoutMFA).Status != StatusRisk {
		t.Fatalf("get: %v %+v", err, o)
	}
	if _, err := svc.Get(context.Background(), shared.ID{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero tenant: %v", err)
	}
	fc.err = errors.New("db down")
	if _, err := svc.Get(context.Background(), id); err == nil {
		t.Fatal("a count failure must be an error, not a partial overview")
	}
}
