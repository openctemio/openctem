package unit

// Scope entries and exclusions under each scan approval mode (RFC-073 §6,
// owner decision 2026-10-10: approvals are for scans, not scope entries).
// Off and On: a caller the route lets write scope (scope:write) changes
// entries and exclusions directly, with step-up on widening; there are no
// requests and no second person. Strict keeps the RFC-054 approvals.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

var noApprovalModes = []scangov.Mode{scangov.ModeOff, scangov.ModeOn}

// A member with scope:write (no scope:approve) adds a permanent wildcard
// entry directly in Off and On; in Strict it is a request with its rules.
func TestScopeModes_MemberWithScopeWriteAddsEntryDirectly(t *testing.T) {
	for _, m := range noApprovalModes {
		t.Run(string(m), func(t *testing.T) {
			svc, _, notes := entryService(t, 3, tenant.ScopeSettings{})
			svc.SetGovernance(fixedMode{m})
			e, err := create(svc, shared.NewID(), member, "*.member.example", nil)
			if err != nil {
				t.Fatal(err)
			}
			if !e.InEffect(time.Now()) || e.ApprovalsRequired() != 0 || e.Origin() == scopedom.OriginRequest {
				t.Fatalf("status %s approvals %d origin %s, want in effect, 0, not a request", e.Status(), e.ApprovalsRequired(), e.Origin())
			}
			if len(notes.titles) == 0 {
				t.Fatal("a widening without approval notified no administrator")
			}
			// Step-up is not an approval: it stays.
			svc.SetStepUpGate(staleGate{})
			if _, err := create(svc, shared.NewID(), member, "*.stale.example", nil); !errors.Is(err, errNeedsStepUp) {
				t.Fatalf("member widening without step-up: %v", err)
			}
		})
	}
	t.Run("strict", func(t *testing.T) {
		svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
		svc.SetGovernance(fixedMode{scangov.ModeStrict})
		if _, err := create(svc, shared.NewID(), member, "*.member.example", nil); !errors.Is(err, scope.ErrRequestMustBeOneOff) {
			t.Fatalf("strict member permanent entry: %v, want REQUEST_MUST_BE_ONE_OFF", err)
		}
		req, err := create(svc, shared.NewID(), member, "one.member.example", func(in *scope.CreateTargetInput) {
			in.ExpiresInDays, in.Reason = days(3), "need it"
		})
		if err != nil || !req.IsPending() || req.ApprovalsRequired() < 1 {
			t.Fatalf("strict member request: %v", err)
		}
	})
	t.Run("unknown mode fails closed", func(t *testing.T) {
		svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
		svc.SetGovernance(fixedMode{scangov.Mode("")})
		if _, err := create(svc, shared.NewID(), member, "*.member.example", nil); !errors.Is(err, scope.ErrRequestMustBeOneOff) {
			t.Fatalf("unknown mode: %v, want the Strict request rules", err)
		}
	})
}

// The preview follows the mode: no approval and step-up in Off; a pending
// request without step-up in Strict.
func TestScopeModes_PreviewFollowsMode(t *testing.T) {
	ctx := context.Background()
	in := func(tid shared.ID) scope.CreateTargetInput {
		return scope.CreateTargetInput{TenantID: tid.String(), TargetType: "domain", Pattern: "one.preview.example",
			CreatedBy: member.UserID, Actor: member, ExpiresInDays: days(3), Reason: "need it"}
	}
	svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	p, err := svc.PreviewTarget(ctx, in(shared.NewID()))
	if err != nil || p.Status != scopedom.StatusActive || p.ApprovalsRequired != 0 || !p.StepUpRequired {
		t.Fatalf("off preview %+v %v", p, err)
	}
	svc.SetGovernance(fixedMode{scangov.ModeStrict})
	p, err = svc.PreviewTarget(ctx, in(shared.NewID()))
	if err != nil || p.Status != scopedom.StatusPending || p.ApprovalsRequired < 1 || p.StepUpRequired {
		t.Fatalf("strict preview %+v %v", p, err)
	}
}

// Widening an existing entry (a removed expiry, activating, discovery on)
// is direct for scope:write in Off and On, approvers only in Strict.
func TestScopeModes_MemberWidensExistingEntry(t *testing.T) {
	ctx := context.Background()
	for _, m := range append(noApprovalModes, scangov.ModeStrict) {
		t.Run(string(m), func(t *testing.T) {
			svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
			svc.SetGovernance(fixedMode{scangov.ModeOff})
			tid := shared.NewID()
			e, err := create(svc, tid, member, "*.widen.example", func(in *scope.CreateTargetInput) { in.ExpiresInDays, in.Reason = days(3), "window" })
			if err != nil {
				t.Fatal(err)
			}
			svc.SetGovernance(fixedMode{m})
			_, upErr := svc.UpdateTarget(ctx, e.ID().String(), tid.String(), scope.UpdateTargetInput{ClearExpiry: true, Actor: member})
			if _, err := svc.DeactivateTarget(ctx, e.ID().String(), tid.String()); err != nil {
				t.Fatal(err)
			}
			_, actErr := svc.ActivateTarget(ctx, e.ID().String(), tid.String(), member)
			if m == scangov.ModeStrict {
				if !errors.Is(upErr, scope.ErrWideningNeedsApprove) || !errors.Is(actErr, scope.ErrWideningNeedsApprove) {
					t.Fatalf("strict member widening: update %v activate %v", upErr, actErr)
				}
				return
			}
			if upErr != nil || actErr != nil {
				t.Fatalf("member widening: update %v activate %v", upErr, actErr)
			}
			got, _ := svc.GetTarget(ctx, tid.String(), e.ID().String())
			if !got.InEffect(time.Now()) || got.ExpiresAt() != nil {
				t.Fatalf("status %s expiry %v, want in effect and permanent", got.Status(), got.ExpiresAt())
			}
		})
	}
}

func exclusionService(t *testing.T, m scangov.Mode) (*scope.Service, *mockExclusionRepo) {
	t.Helper()
	tr, er := newMockTargetRepo(), newMockExclusionRepo()
	svc := scope.NewService(tr, er, newMockAssetRepo(), logger.NewNop())
	svc.SetStepUpGate(passGate{})
	svc.SetGovernance(fixedMode{m})
	return svc, er
}

func createExclusion(t *testing.T, svc *scope.Service, tid shared.ID, by string, until *time.Time) *scopedom.Exclusion {
	t.Helper()
	e, err := svc.CreateExclusion(context.Background(), scope.CreateExclusionInput{TenantID: tid.String(),
		ExclusionType: "domain", Pattern: "prod.example.com", Reason: "fragile", ExpiresAt: until, CreatedBy: by})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// In Off and On a new exclusion is in effect at once, recorded as approved
// by its creator; extending it keeps it in effect; its creator (scope:write,
// no exclusion approval permission) may take it out of effect.
func TestScopeModes_ExclusionsWithoutReview(t *testing.T) {
	ctx := context.Background()
	creator := scopedom.Reviewer{UserID: "member1"}
	for _, m := range noApprovalModes {
		t.Run(string(m), func(t *testing.T) {
			svc, _ := exclusionService(t, m)
			tid := shared.NewID()
			week := time.Now().Add(7 * 24 * time.Hour)
			e := createExclusion(t, svc, tid, "member1", &week)
			if !e.InEffect() || e.ApprovedBy() != "member1" || e.ApprovedAt() == nil {
				t.Fatalf("status %s approved by %q, want in effect and approved by its creator", e.Status(), e.ApprovedBy())
			}
			set, err := svc.ExcludedTargets(ctx, tid.String(), []scope.ExclusionCandidate{{ID: shared.NewID(), Values: []string{"prod.example.com"}}})
			if err != nil || len(set) != 1 {
				t.Fatalf("the exclusion does not apply: %v %v", set, err)
			}
			year := time.Now().Add(365 * 24 * time.Hour)
			got, err := svc.UpdateExclusion(ctx, e.ID().String(), tid.String(), scope.UpdateExclusionInput{ExpiresAt: &year, Reviewer: creator})
			if err != nil || !got.InEffect() {
				t.Fatalf("extending: %v in effect %v", err, got != nil && got.InEffect())
			}
			day := time.Now().Add(24 * time.Hour)
			if _, err := svc.UpdateExclusion(ctx, e.ID().String(), tid.String(), scope.UpdateExclusionInput{ExpiresAt: &day, Reviewer: creator}); err != nil {
				t.Fatalf("creator shortening: %v", err)
			}
			if _, err := svc.DeactivateExclusion(ctx, e.ID().String(), tid.String(), creator); err != nil {
				t.Fatalf("creator deactivating: %v", err)
			}
			if _, err := svc.ActivateExclusion(ctx, e.ID().String(), tid.String()); err != nil {
				t.Fatalf("activating again: %v", err)
			}
			if err := svc.DeleteExclusion(ctx, e.ID().String(), tid.String(), creator); err != nil {
				t.Fatalf("creator deleting: %v", err)
			}
		})
	}
}

// Strict keeps the review: pending until another exclusion approver approves
// it, an extension goes back to review, and taking it out of effect needs an
// approver other than the creator.
func TestScopeModes_ExclusionsStrictKeepsReview(t *testing.T) {
	ctx := context.Background()
	for _, m := range []scangov.Mode{scangov.ModeStrict, scangov.Mode("")} {
		t.Run("mode "+string(m), func(t *testing.T) {
			svc, _ := exclusionService(t, m)
			tid := shared.NewID()
			week := time.Now().Add(7 * 24 * time.Hour)
			e := createExclusion(t, svc, tid, "member1", &week)
			if !e.IsPending() || e.IsApproved() {
				t.Fatalf("strict new exclusion: status %s approved %v, want pending", e.Status(), e.IsApproved())
			}
			if _, err := svc.ApproveExclusion(ctx, e.ID().String(), tid.String(), "member1"); !errors.Is(err, scopedom.ErrExclusionSelfApproval) {
				t.Fatalf("self approval: %v", err)
			}
			if _, err := svc.ApproveExclusion(ctx, e.ID().String(), tid.String(), "approver2"); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.DeactivateExclusion(ctx, e.ID().String(), tid.String(), scopedom.Reviewer{UserID: "member1"}); !errors.Is(err, scopedom.ErrExclusionReduceNeedsApprover) {
				t.Fatalf("member deactivating: %v", err)
			}
			year := time.Now().Add(365 * 24 * time.Hour)
			got, err := svc.UpdateExclusion(ctx, e.ID().String(), tid.String(), scope.UpdateExclusionInput{ExpiresAt: &year})
			if err != nil || !got.IsPending() {
				t.Fatalf("strict extension: %v, want back to pending", err)
			}
		})
	}
}

// A pending exclusion left from Strict stays pending after a switch to Off:
// nothing activates it silently; an approver approves it, or its creator
// deletes it and adds it again.
func TestScopeModes_PendingExclusionFromStrictStaysReviewable(t *testing.T) {
	ctx := context.Background()
	svc, _ := exclusionService(t, scangov.ModeStrict)
	tid := shared.NewID()
	e := createExclusion(t, svc, tid, "member1", nil)
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	got, err := svc.GetExclusion(ctx, tid.String(), e.ID().String())
	if err != nil || !got.IsPending() {
		t.Fatalf("after the switch: %v pending %v", err, got != nil && got.IsPending())
	}
	if _, err := svc.ApproveExclusion(ctx, e.ID().String(), tid.String(), "approver2"); err != nil {
		t.Fatalf("approving a left-over pending exclusion: %v", err)
	}
}

// Another tenant's exclusion is not found, in every mode.
func TestScopeModes_ExclusionCrossTenant(t *testing.T) {
	ctx := context.Background()
	svc, _ := exclusionService(t, scangov.ModeOff)
	e := createExclusion(t, svc, shared.NewID(), "member1", nil)
	other := shared.NewID().String()
	if _, err := svc.DeactivateExclusion(ctx, e.ID().String(), other, scopedom.Reviewer{UserID: "member1"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant deactivate: %v", err)
	}
	if err := svc.DeleteExclusion(ctx, e.ID().String(), other, scopedom.Reviewer{UserID: "member1"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
}

// Taking an exclusion out of effect reaches the signer with the mode's
// approval count: 0 in Off, 1 in Strict.
func TestScopeModes_ExclusionLedgerPolicy(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		mode scangov.Mode
		want int
	}{{scangov.ModeOff, 0}, {scangov.ModeStrict, 1}} {
		t.Run(string(c.mode), func(t *testing.T) {
			svc, er := exclusionService(t, c.mode)
			led := &fakeLedger{}
			svc.SetLedger(led)
			tid := shared.NewID()
			creator := shared.NewID().String()
			e, _ := scopedom.NewExclusion(tid, scopedom.ExclusionTypeDomain, "prod.example.com", "fragile", nil, creator)
			_ = e.Approve(shared.NewID().String())
			er.exclusions[e.ID().String()] = e
			if _, err := svc.DeactivateExclusion(ctx, e.ID().String(), tid.String(), scopedom.Reviewer{UserID: shared.NewID().String(), CanApprove: true}); err != nil {
				t.Fatal(err)
			}
			last := led.changes[len(led.changes)-1]
			if last.RequiredApprovals != c.want || last.PlatformPolicy != "scan_approval:"+string(c.mode) {
				t.Fatalf("ledger change approvals %d policy %q, want %d", last.RequiredApprovals, last.PlatformPolicy, c.want)
			}
		})
	}
}
