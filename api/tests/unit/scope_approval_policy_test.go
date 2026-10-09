package unit

// The platform policy for scope-widening approvals (RFC-054 §12.6): each
// mode for each tier, fail-closed reads, and the change trail.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/scopepolicy"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fixedMode struct{ m tenant.ScopeApprovalMode }

func (f fixedMode) EffectiveScopeApprovalMode(context.Context, shared.ID) (tenant.ScopeApprovalMode, string) {
	return f.m, scopepolicy.SourcePlatformDefault
}

func TestScopeApprovalPolicy_ModesByTier(t *testing.T) {
	one, zero, two := 1, 0, 2
	cases := []struct {
		name      string
		mode      tenant.ScopeApprovalMode
		settings  tenant.ScopeSettings
		admins    int
		t1, t2    int
		requested int // a member's request
	}{
		{"required, one admin", tenant.ScopeApprovalRequired, tenant.ScopeSettings{}, 1, 0, 1, 1},
		{"required, two admins", tenant.ScopeApprovalRequired, tenant.ScopeSettings{}, 2, 1, 1, 1},
		{"required ignores 0 with two admins", tenant.ScopeApprovalRequired, tenant.ScopeSettings{WideningApprovals: &zero}, 2, 1, 1, 1},
		{"tenant controlled 0", tenant.ScopeApprovalTenantControlled, tenant.ScopeSettings{WideningApprovals: &zero}, 3, 0, 0, 1},
		{"tenant controlled 2", tenant.ScopeApprovalTenantControlled, tenant.ScopeSettings{WideningApprovals: &two}, 3, 2, 2, 2},
		{"tenant controlled unset = required", tenant.ScopeApprovalTenantControlled, tenant.ScopeSettings{}, 2, 1, 1, 1},
		{"disabled", tenant.ScopeApprovalDisabled, tenant.ScopeSettings{WideningApprovals: &one}, 3, 0, 0, 1},
		{"unknown mode fails closed", tenant.ScopeApprovalMode("off"), tenant.ScopeSettings{WideningApprovals: &zero}, 2, 1, 1, 1},
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
			svc.SetApprovalPolicy(fixedMode{c.mode})
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
			if req.ApprovalsRequired() != c.requested || !req.IsPending() {
				t.Fatalf("member request: approvals %d status %s, want %d and pending", req.ApprovalsRequired(), req.Status(), c.requested)
			}
		})
	}
}

// Relaxed approvals keep step-up: a stale session still cannot widen.
func TestScopeApprovalPolicy_DisabledKeepsStepUp(t *testing.T) {
	svc, _, notes := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetApprovalPolicy(fixedMode{tenant.ScopeApprovalDisabled})
	svc.SetStepUpGate(staleGate{})
	if _, err := create(svc, shared.NewID(), approverA, "*.ours.example", nil); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("widening without step-up under disabled approvals: %v", err)
	}
	svc.SetStepUpGate(passGate{})
	e, err := create(svc, shared.NewID(), approverA, "*.ours.example", nil)
	if err != nil || !e.InEffect(time.Now()) {
		t.Fatalf("disabled approvals: %v", err)
	}
	if len(notes.titles) == 0 {
		t.Fatal("a widening without approval notified no administrator")
	}
	_ = scopedom.TierActive
}

// --- the policy service ---

type memPolicyRepo struct {
	def      *tenant.ScopeApprovalMode
	version  int
	override map[shared.ID]*tenant.ScopeApprovalMode
	fail     bool
}

func (r *memPolicyRepo) GetDefault(context.Context) (tenant.ScopeApprovalMode, int, error) {
	if r.fail {
		return "", 0, errors.New("db down")
	}
	if r.def == nil {
		return "", 0, scopepolicy.ErrNotFound
	}
	return *r.def, r.version, nil
}

func (r *memPolicyRepo) SetDefault(_ context.Context, m tenant.ScopeApprovalMode, v int, _ shared.ID, _ time.Time) (int, error) {
	if v != r.version {
		return 0, scopepolicy.ErrVersionConflict
	}
	r.def, r.version = &m, r.version+1
	return r.version, nil
}

func (r *memPolicyRepo) GetOverride(_ context.Context, id shared.ID) (*tenant.ScopeApprovalMode, error) {
	if r.fail {
		return nil, errors.New("db down")
	}
	return r.override[id], nil
}

func (r *memPolicyRepo) SetOverride(_ context.Context, id shared.ID, m *tenant.ScopeApprovalMode) error {
	r.override[id] = m
	return nil
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

func TestScopePolicyService(t *testing.T) {
	ctx := context.Background()
	repo := &memPolicyRepo{override: map[shared.ID]*tenant.ScopeApprovalMode{}}
	audit := &adminAuditLog{}
	notes := &tenantNotes{}
	svc := scopepolicy.NewService(repo, audit, nil, nil, notes, logger.NewNop())
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)
	org, other := shared.NewID(), shared.NewID()

	if m, src := svc.Effective(ctx, org); m != tenant.ScopeApprovalRequired || src != scopepolicy.SourcePlatformDefault {
		t.Fatalf("nothing stored: %s %s", m, src)
	}
	if _, err := svc.UpdateDefault(ctx, tenant.ScopeApprovalDisabled, 0, scopepolicy.Change{Actor: actor}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := svc.UpdateDefault(ctx, tenant.ScopeApprovalDisabled, 0, scopepolicy.Change{Actor: actor, Reason: "lab deployment"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateDefault(ctx, tenant.ScopeApprovalRequired, 0, scopepolicy.Change{Actor: actor, Reason: "stale"}); !errors.Is(err, scopepolicy.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	req := tenant.ScopeApprovalRequired
	if err := svc.UpdateOverride(ctx, org, &req, scopepolicy.Change{Actor: actor, Reason: "customer asked"}); err != nil {
		t.Fatal(err)
	}
	if m, src := svc.Effective(ctx, org); m != tenant.ScopeApprovalRequired || src != scopepolicy.SourceOrganization {
		t.Fatalf("override: %s %s", m, src)
	}
	if m, _ := svc.Effective(ctx, other); m != tenant.ScopeApprovalDisabled {
		t.Fatalf("another organization took the override: %s", m)
	}
	if len(audit.entries) != 2 || len(notes.to) != 1 || notes.to[0] != org {
		t.Fatalf("audit %d entries, tenant notices %v", len(audit.entries), notes.to)
	}
	repo.fail = true
	if m, _ := scopepolicy.NewService(repo, nil, nil, nil, nil, logger.NewNop()).Effective(ctx, other); m != tenant.ScopeApprovalRequired {
		t.Fatalf("an unreadable policy did not fail closed: %s", m)
	}
}
