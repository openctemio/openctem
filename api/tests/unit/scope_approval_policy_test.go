package unit

// Scope-entry approvals under scan approval governance (RFC-073 §6) and the
// platform scan approval policy (§5): each mode for each tier, fail-closed
// reads, and the change trail.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fixedMode struct{ m scangov.Mode }

func (f fixedMode) ScanGovernanceMode(context.Context, shared.ID) (scangov.Mode, string) {
	return f.m, scangov.SourceOrganization
}

func TestScopeApprovalPolicy_ModesByTier(t *testing.T) {
	zero, two := 0, 2
	cases := []struct {
		name      string
		mode      scangov.Mode
		settings  tenant.ScopeSettings
		admins    int
		t1, t2    int
		requested int // a member's entry (scope:write, no approve): 0 = in effect at once
	}{
		{"off", scangov.ModeOff, tenant.ScopeSettings{WideningApprovals: &two}, 3, 0, 0, 0},
		{"on", scangov.ModeOn, tenant.ScopeSettings{WideningApprovals: &two}, 3, 0, 0, 0},
		{"strict, one admin", scangov.ModeStrict, tenant.ScopeSettings{}, 1, 0, 1, 1},
		{"strict, two admins", scangov.ModeStrict, tenant.ScopeSettings{}, 2, 1, 1, 1},
		{"strict ignores 0 with two admins", scangov.ModeStrict, tenant.ScopeSettings{WideningApprovals: &zero}, 2, 1, 1, 1},
		{"strict, 2", scangov.ModeStrict, tenant.ScopeSettings{WideningApprovals: &two}, 3, 2, 2, 2},
		{"unknown mode fails closed", scangov.Mode("loose"), tenant.ScopeSettings{WideningApprovals: &zero}, 2, 1, 1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.settings.EffectiveApprovalsUnder(c.mode, c.admins, false); got != c.t1 {
				t.Fatalf("t1: %d, want %d", got, c.t1)
			}
			if got := c.settings.EffectiveApprovalsUnder(c.mode, c.admins, true); got != c.t2 {
				t.Fatalf("t2: %d, want %d", got, c.t2)
			}
			svc, _, _ := entryService(t, c.admins, c.settings)
			svc.SetGovernance(fixedMode{c.mode})
			tid := shared.NewID()
			e, err := create(svc, tid, approverA, "t2.policy.example", t2(days(3)))
			if err != nil {
				t.Fatal(err)
			}
			if e.ApprovalsRequired() != c.t2 || (c.t2 == 0) != e.InEffect(time.Now()) {
				t.Fatalf("t2 entry: approvals %d status %s, want %d", e.ApprovalsRequired(), e.Status(), c.t2)
			}
			req, err := create(svc, tid, member, "one.policy.example", func(in *scope.CreateTargetInput) {
				in.ExpiresInDays, in.Reason = days(3), "need it"
			})
			if err != nil {
				t.Fatal(err)
			}
			if req.ApprovalsRequired() != c.requested || req.IsPending() != (c.requested > 0) {
				t.Fatalf("member entry: approvals %d status %s, want %d", req.ApprovalsRequired(), req.Status(), c.requested)
			}
		})
	}
}

// Without a governance source the scope service is Strict (fail closed).
func TestScopeApprovalPolicy_NoSourceIsStrict(t *testing.T) {
	svc, _, _ := entryService(t, 2, tenant.ScopeSettings{})
	e, err := create(svc, shared.NewID(), approverA, "*.nosource.example", nil)
	if err != nil || e.InEffect(time.Now()) {
		t.Fatalf("no governance source: %v in effect=%v", err, e != nil && e.InEffect(time.Now()))
	}
}

// Off keeps step-up: a stale session still cannot widen.
func TestScopeApprovalPolicy_OffKeepsStepUp(t *testing.T) {
	svc, _, notes := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	svc.SetStepUpGate(staleGate{})
	if _, err := create(svc, shared.NewID(), approverA, "*.ours.example", nil); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("widening without step-up under Off: %v", err)
	}
	svc.SetStepUpGate(passGate{})
	e, err := create(svc, shared.NewID(), approverA, "*.ours.example", nil)
	if err != nil || !e.InEffect(time.Now()) {
		t.Fatalf("Off: %v", err)
	}
	if len(notes.titles) == 0 {
		t.Fatal("a widening without approval notified no administrator")
	}
}

// --- the policy service ---

type memPolicyRepo struct {
	def      *scangov.PlatformPolicy
	version  int
	override map[shared.ID]*scangov.PlatformPolicy
	fail     bool
}

func (r *memPolicyRepo) GetDefault(context.Context) (scangov.PlatformPolicy, int, error) {
	if r.fail {
		return "", 0, errors.New("db down")
	}
	if r.def == nil {
		return "", 0, scanpolicy.ErrNotFound
	}
	return *r.def, r.version, nil
}

func (r *memPolicyRepo) SetDefault(_ context.Context, p scangov.PlatformPolicy, v int, _ shared.ID, _ time.Time) (int, error) {
	if v != r.version {
		return 0, scanpolicy.ErrVersionConflict
	}
	r.def, r.version = &p, r.version+1
	return r.version, nil
}

func (r *memPolicyRepo) GetOverride(_ context.Context, id shared.ID) (*scangov.PlatformPolicy, error) {
	if r.fail {
		return nil, errors.New("db down")
	}
	return r.override[id], nil
}

func (r *memPolicyRepo) SetOverride(_ context.Context, id shared.ID, p *scangov.PlatformPolicy) error {
	r.override[id] = p
	return nil
}

func (r *memPolicyRepo) ListFollowingDefault(context.Context) ([]shared.ID, error) {
	var out []shared.ID
	for id, p := range r.override {
		if p == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

type adminAuditLog struct{ entries []*admin.AuditLog }

func (a *adminAuditLog) Create(_ context.Context, e *admin.AuditLog) error {
	a.entries = append(a.entries, e)
	return nil
}

type tenantNotes struct{ to []shared.ID }

func (n *tenantNotes) NotifyAdmins(_ context.Context, id shared.ID, _, _ string) {
	n.to = append(n.to, id)
}

type govSettings map[string]tenant.ScanGovernanceSettings

func (g govSettings) GetScanGovernanceSettings(_ context.Context, id string) (*tenant.ScanGovernanceSettings, error) {
	s := g[id]
	return &s, nil
}

func TestScanPolicyService(t *testing.T) {
	ctx := context.Background()
	repo := &memPolicyRepo{override: map[shared.ID]*scangov.PlatformPolicy{}}
	audit := &adminAuditLog{}
	notes := &tenantNotes{}
	svc := scanpolicy.NewService(repo, audit, nil, nil, notes, logger.NewNop())
	org, other := shared.NewID(), shared.NewID()
	svc.SetSettings(govSettings{org.String(): {Mode: scangov.ModeOn}})
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)

	if m, src, p, err := svc.EffectiveMode(ctx, org); err != nil || m != scangov.ModeOn || src != scangov.SourceOrganization || p != scangov.PolicyTenantControlled {
		t.Fatalf("nothing stored: the owner's choice: %s %s %s %v", m, src, p, err)
	}
	if m, _, _, _ := svc.EffectiveMode(ctx, other); m != scangov.ModeOff {
		t.Fatalf("an organization that chose nothing is Off: %s", m)
	}
	if _, err := svc.UpdateDefault(ctx, scangov.PolicyOff, 0, scanpolicy.Change{Actor: actor}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := svc.UpdateDefault(ctx, scangov.PolicyOff, 0, scanpolicy.Change{Actor: actor, Reason: "lab deployment"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateDefault(ctx, scangov.PolicyStrict, 0, scanpolicy.Change{Actor: actor, Reason: "stale"}); !errors.Is(err, scanpolicy.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if m, src, _, _ := svc.EffectiveMode(ctx, org); m != scangov.ModeOff || src != scangov.SourcePlatform {
		t.Fatalf("forced off by the default: %s %s", m, src)
	}
	strict := scangov.PolicyStrict
	if err := svc.UpdateOverride(ctx, org, &strict, scanpolicy.Change{Actor: actor, Reason: "customer asked"}); err != nil {
		t.Fatal(err)
	}
	if m, src, _, _ := svc.EffectiveMode(ctx, org); m != scangov.ModeStrict || src != scangov.SourcePlatform {
		t.Fatalf("override: %s %s", m, src)
	}
	if p, _, _ := svc.Policy(ctx, other); p != scangov.PolicyOff {
		t.Fatalf("another organization took the override: %s", p)
	}
	if len(audit.entries) != 2 || len(notes.to) != 1 || notes.to[0] != org {
		t.Fatalf("audit %d entries, tenant notices %v", len(audit.entries), notes.to)
	}
	repo.fail = true
	if _, _, _, err := svc.EffectiveMode(ctx, other); err == nil {
		t.Fatal("an unreadable policy must be an error")
	}
	if m, _ := svc.ScanGovernanceMode(ctx, other); m != scangov.ModeStrict {
		t.Fatalf("scope entries fail closed to Strict: %s", m)
	}
}

// A widening reaches the job signer's ledger labeled with the scan
// approval mode in force and the approvals that mode requires.
func TestScopeApprovalPolicy_LedgerCarriesThePolicy(t *testing.T) {
	svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	led := &fakeLedger{}
	svc.SetLedger(led)
	if _, err := create(svc, shared.NewID(), approverA, "*.policy-ledger.example", nil); err != nil {
		t.Fatal(err)
	}
	if len(led.changes) != 1 || led.changes[0].PlatformPolicy != "scan_approval:off" || led.changes[0].RequiredApprovals != 0 {
		t.Fatalf("ledger changes %+v, want one widening labeled scan_approval:off with 0 approvals", led.changes)
	}
}
