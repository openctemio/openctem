package unit

// Re-attestation of long intrusive (t2) entries and the downgrade of the
// forgotten ones (RFC-054 §12.5).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// attestRepo adds the attestation job's conditional writes to the
// in-memory repository.
type attestRepo struct {
	*mockTargetRepo
	downgrades int
	done       map[string]bool
}

func (r *attestRepo) TenantsWithIntrusiveEntries(context.Context) ([]shared.ID, error) {
	seen := map[shared.ID]bool{}
	var out []shared.ID
	for _, t := range r.targets {
		if t.MaxTier() == scopedom.TierIntrusive && t.Status() == scopedom.StatusActive && !seen[t.TenantID()] {
			seen[t.TenantID()] = true
			out = append(out, t.TenantID())
		}
	}
	return out, nil
}

func (r *attestRepo) ListActiveIntrusive(_ context.Context, tid shared.ID) ([]*scopedom.Target, error) {
	var out []*scopedom.Target
	for _, t := range r.targets {
		if t.TenantID() == tid && t.MaxTier() == scopedom.TierIntrusive && t.Status() == scopedom.StatusActive {
			out = append(out, t)
		}
	}
	return out, nil
}

func (r *attestRepo) MarkAttestationRequested(_ context.Context, tid, id shared.ID, now time.Time) (bool, error) {
	t, ok := r.targets[id.String()]
	if !ok || t.TenantID() != tid || t.MaxTier() != scopedom.TierIntrusive || t.AttestationRequestedAt() != nil {
		return false, nil
	}
	t.RestoreAttestation(scopedom.AttestationState{AttestedAt: t.AttestedAt(), AttestedBy: t.AttestedBy(), RequestedAt: &now})
	return true, nil
}

func (r *attestRepo) DowngradeUnattested(_ context.Context, tid, id shared.ID, req, now time.Time) (bool, error) {
	// The service hands over the entry already set to t1; the store's
	// condition is the request it saw, once.
	t, ok := r.targets[id.String()]
	key := id.String() + req.String()
	if !ok || t.TenantID() != tid || r.done[key] {
		return false, nil
	}
	r.done[key] = true
	r.downgrades++
	return true, nil
}

func attestHarness(t *testing.T, st tenant.ScopeSettings) (*scope.Service, *attestRepo, *channelLog) {
	t.Helper()
	repo := &attestRepo{mockTargetRepo: newMockTargetRepo(), done: map[string]bool{}}
	svc := scope.NewService(repo, newMockExclusionRepo(), newMockAssetRepo(), logger.NewNop())
	svc.SetStepUpGate(passGate{})
	svc.SetEntryPolicy(fixedSettings{st}, adminDir{1}, &userNotes{})
	ch := &channelLog{}
	svc.SetApprovers(fixedApprovers{nil}, nil, nil, ch, "")
	return svc, repo, ch
}

// seedT2 stores an active t2 entry approved at approvedAt.
func seedT2(repo *attestRepo, tid shared.ID, pattern string, approvedAt time.Time, expires *time.Time) *scopedom.Target {
	e, err := scopedom.NewEntry(tid, scopedom.TargetTypeDomain, pattern, "", "owner", scopedom.EntryOptions{
		Reason: "contract", ExpiresAt: expires, MaxTier: scopedom.TierIntrusive, IntrusivePermanent: true, Now: approvedAt,
	})
	if err != nil {
		panic(err)
	}
	repo.targets[e.ID().String()] = e
	return e
}

func TestScopeAttestation_RequestThenDowngrade(t *testing.T) {
	ctx := context.Background()
	svc, repo, ch := attestHarness(t, tenant.ScopeSettings{})
	tid := shared.NewID()
	start := time.Now().UTC().Add(-100 * 24 * time.Hour)
	e := seedT2(repo, tid, "perm.t2.example", start, nil)
	// A short t2 entry expiring before its first attestation needs none.
	soon := start.Add(60 * 24 * time.Hour)
	short := seedT2(repo, tid, "short.t2.example", start, &soon)

	now := start.Add(91 * 24 * time.Hour)
	res, err := svc.ReconcileAttestations(ctx, now)
	if err != nil || res.Requested != 1 || res.Downgraded != 0 {
		t.Fatalf("first run: %+v %v, want one request", res, err)
	}
	if e.AttestationRequestedAt() == nil || short.AttestationRequestedAt() != nil {
		t.Fatal("the request went to the wrong entry")
	}
	if len(ch.events) == 0 || ch.events[0].EventType != string(integration.EventTypeApprovalRequested) {
		t.Fatalf("channels %+v", ch.events)
	}
	// Rerun before the grace ends: nothing more.
	if res, _ := svc.ReconcileAttestations(ctx, now.Add(13*24*time.Hour)); res.Requested+res.Downgraded != 0 {
		t.Fatalf("rerun inside the grace: %+v", res)
	}
	res, _ = svc.ReconcileAttestations(ctx, now.Add(14*24*time.Hour+time.Minute))
	if res.Downgraded != 1 || e.MaxTier() != scopedom.TierActive || e.Status() != scopedom.StatusActive {
		t.Fatalf("after the grace: %+v tier %s status %s, want downgraded to t1 and kept", res, e.MaxTier(), e.Status())
	}
	// Idempotent: a second run downgrades nothing.
	if res, _ := svc.ReconcileAttestations(ctx, now.Add(20*24*time.Hour)); res.Downgraded != 0 || repo.downgrades != 1 {
		t.Fatalf("second run after the downgrade: %+v (%d downgrades)", res, repo.downgrades)
	}
	if last := ch.events[len(ch.events)-1]; last.EventType != string(integration.EventTypeSecurityAlert) {
		t.Fatalf("downgrade not announced: %+v", last)
	}
}

func TestScopeAttestation_ConfirmingKeepsT2(t *testing.T) {
	ctx := context.Background()
	svc, repo, _ := attestHarness(t, tenant.ScopeSettings{T2AttestationDays: 30})
	tid := shared.NewID()
	start := time.Now().UTC().Add(-40 * 24 * time.Hour)
	e := seedT2(repo, tid, "perm.t2.example", start, nil)
	if res, _ := svc.ReconcileAttestations(ctx, time.Now().UTC()); res.Requested != 1 {
		t.Fatalf("a 30-day period did not ask after 40 days: %+v", res)
	}
	member := scope.Actor{UserID: "member"}
	if _, err := svc.AttestTarget(ctx, e.ID().String(), tid.String(), member); !errors.Is(err, scope.ErrWideningNeedsApprove) {
		t.Fatalf("a member attested: %v", err)
	}
	if _, err := svc.AttestTarget(ctx, e.ID().String(), shared.NewID().String(), approverA); !errors.Is(err, scopedom.ErrTargetNotFound) {
		t.Fatalf("cross-tenant attestation: %v", err)
	}
	got, err := svc.AttestTarget(ctx, e.ID().String(), tid.String(), approverA)
	if err != nil || got.AttestationRequestedAt() != nil || got.AttestedBy() != approverA.UserID {
		t.Fatalf("attest: %v, requested %v by %q", err, got.AttestationRequestedAt(), got.AttestedBy())
	}
	// Long after the old request's grace: the confirmation started a new
	// period, so nothing is downgraded.
	if res, _ := svc.ReconcileAttestations(ctx, time.Now().UTC().Add(15*24*time.Hour)); res.Downgraded != 0 || e.MaxTier() != scopedom.TierIntrusive {
		t.Fatalf("an attested entry was downgraded: %+v", res)
	}
	// A t1 entry is never attested.
	t1, _ := create(svc, tid, approverA, "t1.example", nil)
	if _, err := svc.AttestTarget(ctx, t1.ID().String(), tid.String(), approverA); !errors.Is(err, scopedom.ErrNotIntrusive) {
		t.Fatalf("attesting a t1 entry: %v", err)
	}
}

func TestScopeAttestation_DueDate(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e, _ := scopedom.NewEntry(shared.NewID(), scopedom.TargetTypeDomain, "x.example", "", "o", scopedom.EntryOptions{
		Reason: "r", MaxTier: scopedom.TierIntrusive, IntrusivePermanent: true, Now: start,
	})
	d := e.AttestationDueAt(90 * 24 * time.Hour)
	if d == nil || !d.Equal(start.Add(90*24*time.Hour)) {
		t.Fatalf("due %v", d)
	}
	_ = e.Attest("o", start.Add(50*24*time.Hour))
	if d := e.AttestationDueAt(90 * 24 * time.Hour); !d.Equal(start.Add(140 * 24 * time.Hour)) {
		t.Fatalf("due after an attestation %v", d)
	}
	if err := (tenant.ScopeSettings{T2AttestationDays: 29}).Validate(); err == nil {
		t.Fatal("29 attestation days accepted")
	}
	if (tenant.ScopeSettings{}).AttestationDays() != 90 {
		t.Fatal("default attestation period is not 90 days")
	}
}

// The downgrade is a narrowing: saved, then sent to the job signer's ledger
// with the entry at t1.
func TestScopeAttestation_DowngradeReachesTheLedger(t *testing.T) {
	ctx := context.Background()
	svc, repo, _ := attestHarness(t, tenant.ScopeSettings{})
	led := &fakeLedger{}
	svc.SetLedger(led)
	tid := shared.NewID()
	start := time.Now().UTC().Add(-120 * 24 * time.Hour)
	e := seedT2(repo, tid, "perm.t2.ledger.example", start, nil)
	now := start.Add(91 * 24 * time.Hour)
	if res, _ := svc.ReconcileAttestations(ctx, now); res.Requested != 1 {
		t.Fatalf("request: %+v", res)
	}
	if res, err := svc.ReconcileAttestations(ctx, now.Add(15*24*time.Hour)); err != nil || res.Downgraded != 1 {
		t.Fatalf("downgrade: %+v %v", res, err)
	}
	if e.MaxTier() != scopedom.TierActive {
		t.Fatal("not downgraded")
	}
	last := led.changes[len(led.changes)-1]
	if len(last.Ops) != 1 || last.Ops[0].Entry == nil || last.Ops[0].Entry.MaxTier != 1 {
		t.Fatalf("ledger change %+v, want the entry at t1", last)
	}
}
