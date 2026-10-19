package unit

// A duplicate scope entry or exclusion names the caller's own existing row
// (id and status) so the client can act on it; leftover pending rows take
// effect where approvals are no longer required (RFC-073 §6), and stay
// pending in Strict.

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

// modeByTenant answers each tenant's scan approval mode (Strict when unset).
type modeByTenant map[shared.ID]scangov.Mode

func (m modeByTenant) ScanGovernanceMode(_ context.Context, id shared.ID) (scangov.Mode, string) {
	if mode, ok := m[id]; ok {
		return mode, scangov.SourceOrganization
	}
	return scangov.ModeStrict, scangov.SourcePlatform
}

// pendingTargetRepo adds TenantsWithPending to the target mock.
type pendingTargetRepo struct {
	*mockTargetRepo
	er *mockExclusionRepo
}

func (r pendingTargetRepo) TenantsWithPending(context.Context) ([]shared.ID, error) {
	seen := map[shared.ID]bool{}
	var out []shared.ID
	add := func(id shared.ID) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, t := range r.targets {
		if t.IsPending() {
			add(t.TenantID())
		}
	}
	for _, e := range r.er.exclusions {
		if e.IsPending() {
			add(e.TenantID())
		}
	}
	return out, nil
}

func dupService(t *testing.T, modes modeByTenant) (*scope.Service, *mockTargetRepo, *mockExclusionRepo) {
	t.Helper()
	tr, er := newMockTargetRepo(), newMockExclusionRepo()
	svc := scope.NewService(pendingTargetRepo{tr, er}, er, newMockAssetRepo(), logger.NewDevelopment())
	svc.SetStepUpGate(passGate{})
	svc.SetEntryPolicy(fixedSettings{tenant.ScopeSettings{}}, adminDir{3}, &noticeLog{})
	svc.SetGovernance(modes)
	return svc, tr, er
}

func wantDuplicate(t *testing.T, err error, base error, id shared.ID, status scopedom.Status) {
	t.Helper()
	var dup *scopedom.DuplicateError
	if !errors.As(err, &dup) || !errors.Is(err, base) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("got %v, want a DuplicateError wrapping %v", err, base)
	}
	if dup.Existing.ID != id || dup.Existing.Status != status {
		t.Fatalf("existing %s/%s, want %s/%s", dup.Existing.ID, dup.Existing.Status, id, status)
	}
}

func TestScopeDuplicate_EntryNamesExistingRowOfOwnTenantOnly(t *testing.T) {
	strict, other := shared.NewID(), shared.NewID()
	svc, _, _ := dupService(t, modeByTenant{other: scangov.ModeOff})
	// Strict, two more admins: an approver's entry waits for approval.
	pending, err := create(svc, strict, approverA, "*.customer.example", nil)
	if err != nil || !pending.IsPending() {
		t.Fatalf("strict entry: %v pending=%v", err, pending != nil && pending.IsPending())
	}
	_, err = create(svc, strict, approverB, "*.customer.example", nil)
	wantDuplicate(t, err, scopedom.ErrTargetAlreadyExists, pending.ID(), scopedom.StatusPending)

	_, err = svc.PreviewTarget(context.Background(), scope.CreateTargetInput{TenantID: strict.String(),
		TargetType: "domain", Pattern: "*.customer.example", CreatedBy: approverB.UserID, Actor: approverB})
	wantDuplicate(t, err, scopedom.ErrTargetAlreadyExists, pending.ID(), scopedom.StatusPending)

	// Another tenant never sees (or collides with) this tenant's row.
	mine, err := create(svc, other, approverA, "*.customer.example", nil)
	if err != nil || !mine.InEffect(time.Now()) {
		t.Fatalf("other tenant's create: %v", err)
	}
	_, err = create(svc, other, approverA, "*.customer.example", nil)
	wantDuplicate(t, err, scopedom.ErrTargetAlreadyExists, mine.ID(), scopedom.StatusActive)
}

func TestScopeDuplicate_ExclusionNamesExistingRow(t *testing.T) {
	tid := shared.NewID()
	svc, _, _ := dupService(t, modeByTenant{tid: scangov.ModeOff})
	ctx := context.Background()
	in := scope.CreateExclusionInput{TenantID: tid.String(), ExclusionType: "domain", Pattern: "prod.example.com", Reason: "prod", CreatedBy: "admin-a"}
	first, err := svc.CreateExclusion(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateExclusion(ctx, in)
	wantDuplicate(t, err, scopedom.ErrExclusionAlreadyExists, first.ID(), scopedom.StatusActive)

	in.TenantID = shared.NewID().String()
	if _, err := svc.CreateExclusion(ctx, in); err != nil {
		t.Fatalf("another tenant's exclusion collided: %v", err)
	}
}

// Activating a leftover pending entry puts it into effect where approvals
// are not required, and changes nothing in Strict.
func TestScopeDuplicate_ActivatePendingFollowsMode(t *testing.T) {
	tid := shared.NewID()
	modes := modeByTenant{}
	svc, _, _ := dupService(t, modes)
	ctx := context.Background()
	e, err := create(svc, tid, approverA, "*.legacy.example", nil)
	if err != nil || !e.IsPending() {
		t.Fatalf("strict entry: %v", err)
	}
	got, err := svc.ActivateTarget(ctx, e.ID().String(), tid.String(), member)
	if err != nil || !got.IsPending() {
		t.Fatalf("strict activate: %v pending=%v, want still pending", err, got != nil && got.IsPending())
	}
	modes[tid] = scangov.ModeOff
	got, err = svc.ActivateTarget(ctx, e.ID().String(), tid.String(), member)
	if err != nil || !got.InEffect(time.Now()) || got.ApprovalsRequired() != 0 {
		t.Fatalf("off activate: %v, want in effect", err)
	}

	x, err := svc.CreateExclusion(ctx, scope.CreateExclusionInput{TenantID: tid.String(), ExclusionType: "domain",
		Pattern: "old.example.com", Reason: "r", CreatedBy: "admin-a"})
	if err != nil || !x.InEffect() {
		t.Fatalf("off exclusion: %v", err)
	}
}

func TestScopeDuplicate_ActivateLeftoverPending(t *testing.T) {
	strict, off := shared.NewID(), shared.NewID()
	modes := modeByTenant{}
	svc, tr, er := dupService(t, modes)
	ctx := context.Background()
	mk := func(tid shared.ID, pattern string) (*scopedom.Target, *scopedom.Exclusion) {
		e, err := create(svc, tid, approverA, pattern, nil)
		if err != nil || !e.IsPending() {
			t.Fatalf("pending entry: %v", err)
		}
		x, err := svc.CreateExclusion(ctx, scope.CreateExclusionInput{TenantID: tid.String(), ExclusionType: "domain",
			Pattern: "x." + pattern[2:], Reason: "r", CreatedBy: "admin-a"})
		if err != nil || !x.IsPending() {
			t.Fatalf("pending exclusion: %v", err)
		}
		return e, x
	}
	se, sx := mk(strict, "*.strict.example")
	oe, ox := mk(off, "*.off.example")
	modes[off] = scangov.ModeOff // the organization left Strict

	n, err := svc.ActivateLeftoverPending(ctx)
	if err != nil || n != 2 {
		t.Fatalf("settled %d (%v), want 2", n, err)
	}
	if got := tr.targets[oe.ID().String()]; !got.InEffect(time.Now()) || got.ApprovalsRequired() != 0 || got.CreatedBy() != approverA.UserID {
		t.Fatalf("off entry status %s approvals %d created by %q", got.Status(), got.ApprovalsRequired(), got.CreatedBy())
	}
	if got := er.exclusions[ox.ID().String()]; !got.InEffect() || got.ApprovedBy() != scopedom.SystemReviewer {
		t.Fatalf("off exclusion status %s approved by %q", got.Status(), got.ApprovedBy())
	}
	if !tr.targets[se.ID().String()].IsPending() || !er.exclusions[sx.ID().String()].IsPending() {
		t.Fatal("a Strict organization's pending rows were put into effect")
	}
	if n, err := svc.ActivateLeftoverPending(ctx); err != nil || n != 0 {
		t.Fatalf("second run settled %d (%v), want 0", n, err)
	}
}
