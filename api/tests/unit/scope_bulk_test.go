package unit

// Adding many scope entries in one request (RFC-054 §14): each item is an
// ordinary CreateTarget (guardrails, duplicates, Strict rules, the signer
// ledger), step-up is checked once before anything is written, and the
// administrators get one notice for the batch.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func bulkItems(patterns ...string) []scope.BulkTargetItem {
	out := make([]scope.BulkTargetItem, 0, len(patterns))
	for _, p := range patterns {
		typ := "domain"
		if p != "" && (p[0] >= '0' && p[0] <= '9') {
			typ = "ip_address"
		}
		out = append(out, scope.BulkTargetItem{TargetType: typ, Pattern: p})
	}
	return out
}

func bulkIn(tid shared.ID, actor scope.Actor, items []scope.BulkTargetItem) scope.BulkTargetsInput {
	return scope.BulkTargetsInput{TenantID: tid.String(), Items: items, CreatedBy: actor.UserID, Actor: actor}
}

// A mixed batch: new entries are created in effect (Off), an existing one is
// answered as a duplicate naming the tenant's row, a public suffix and a
// malformed pattern are refused with their codes; one notice for the batch.
func TestScopeBulk_MixedBatchPerItemOutcome(t *testing.T) {
	ctx := context.Background()
	svc, tr, notes := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	tid := shared.NewID()
	existing, err := create(svc, tid, member, "old.bulk.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	before := len(notes.titles)

	out, err := svc.CreateTargets(ctx, bulkIn(tid, member, bulkItems(
		"a.bulk.example", "*.b.bulk.example", "203.0.113.7", "old.bulk.example", "*.com", "not a name",
	)))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 6 {
		t.Fatalf("%d outcomes, want one per item", len(out))
	}
	for i := 0; i < 3; i++ {
		if out[i].Err != nil || out[i].Target == nil || !out[i].Target.IsActive() {
			t.Fatalf("item %d (%s): %v, want created in effect", i, out[i].Item.Pattern, out[i].Err)
		}
		if out[i].Target.Origin() != scopedom.OriginImport {
			t.Fatalf("item %d origin %s, want import", i, out[i].Target.Origin())
		}
	}
	var dup *scopedom.DuplicateError
	if !errors.As(out[3].Err, &dup) || dup.Existing.ID != existing.ID() {
		t.Fatalf("existing entry: %v, want a duplicate naming %s", out[3].Err, existing.ID())
	}
	if code := domainCode(out[4].Err); code != "PUBLIC_SUFFIX" {
		t.Fatalf("public suffix: %v (code %q)", out[4].Err, code)
	}
	if out[5].Err == nil || !errors.Is(out[5].Err, shared.ErrValidation) {
		t.Fatalf("malformed pattern: %v, want a validation error", out[5].Err)
	}
	// One notice per administrator (3) for the whole batch, not one per entry.
	got := notes.titles[before:]
	if len(got) != 3 {
		t.Fatalf("notices %v, want one per administrator for the batch", got)
	}
	for _, title := range got {
		if title != "3 scope entries added" {
			t.Fatalf("notice %q, want the batch notice", title)
		}
	}
	if n := countTenantTargets(t, tr, tid); n != 4 {
		t.Fatalf("%d entries saved, want 4 (1 old + 3 new)", n)
	}
}

// Without a recent re-authentication nothing is written, whatever the batch.
func TestScopeBulk_StepUpBeforeAnyWrite(t *testing.T) {
	svc, tr, notes := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	svc.SetStepUpGate(staleGate{})
	tid := shared.NewID()
	_, err := svc.CreateTargets(context.Background(), bulkIn(tid, member, bulkItems("x.bulk.example", "y.bulk.example")))
	if !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("stale session: %v, want step-up", err)
	}
	if n := countTenantTargets(t, tr, tid); n != 0 || len(notes.titles) != 0 {
		t.Fatalf("%d entries, %d notices written without step-up", n, len(notes.titles))
	}
}

// In Strict a member's items follow the request rules: a permanent entry is
// refused per item (REQUEST_MUST_BE_ONE_OFF) and nothing takes effect; no
// step-up is asked because a request authorizes nothing.
func TestScopeBulk_StrictMemberFollowsRequestRules(t *testing.T) {
	svc, tr, _ := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeStrict})
	svc.SetStepUpGate(staleGate{})
	tid := shared.NewID()
	out, err := svc.CreateTargets(context.Background(), bulkIn(tid, member, bulkItems("p.bulk.example", "q.bulk.example")))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range out {
		if !errors.Is(o.Err, scope.ErrRequestMustBeOneOff) {
			t.Fatalf("%s: %v, want REQUEST_MUST_BE_ONE_OFF", o.Item.Pattern, o.Err)
		}
	}
	if n := countTenantTargets(t, tr, tid); n != 0 {
		t.Fatalf("%d entries saved in Strict for a member", n)
	}
}

// The signer ledger sees every item before it is saved: a refused widening
// is not saved and is reported on its item; the batch is not a way around
// the ledger.
func TestScopeBulk_LedgerRefusalPerItem(t *testing.T) {
	svc, tr, _, l := ledgerScopeService(t, 1)
	l.refuse = true
	tid := shared.NewID()
	actor := uuidActor()
	out, err := svc.CreateTargets(context.Background(), bulkIn(tid, actor, bulkItems("l1.bulk.example", "l2.bulk.example")))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range out {
		if o.Err == nil || o.Target != nil {
			t.Fatalf("%s: saved although the signer refused", o.Item.Pattern)
		}
	}
	if tr.writes != 0 || len(l.changes) != 2 {
		t.Fatalf("writes %d, ledger changes %d; want 0 writes and one ledger change per item", tr.writes, len(l.changes))
	}
}

// Another tenant's entry with the same pattern is not a duplicate: the
// lookup is the caller's tenant only, so a bulk add never names it.
func TestScopeBulk_OtherTenantNotADuplicate(t *testing.T) {
	svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	other := shared.NewID()
	if _, err := create(svc, other, member, "shared.bulk.example", nil); err != nil {
		t.Fatal(err)
	}
	out, err := svc.CreateTargets(context.Background(), bulkIn(shared.NewID(), member, bulkItems("shared.bulk.example")))
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Err != nil || out[0].Target == nil {
		t.Fatalf("same pattern in another tenant: %v, want created", out[0].Err)
	}
}

// The batch is bounded: empty and over the limit are refused before any
// lookup; origin refusal_fix is kept, anything else is import.
func TestScopeBulk_LimitsAndOrigin(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	tid := shared.NewID()
	if _, err := svc.CreateTargets(ctx, bulkIn(tid, member, nil)); !errors.Is(err, scope.ErrBulkTargetsEmpty) {
		t.Fatalf("empty: %v", err)
	}
	many := make([]string, scope.MaxBulkTargets+1)
	for i := range many {
		many[i] = fmt.Sprintf("h%d.bulk.example", i)
	}
	if _, err := svc.CreateTargets(ctx, bulkIn(tid, member, bulkItems(many...))); !errors.Is(err, scope.ErrBulkTargetsTooMany) {
		t.Fatalf("too many: %v", err)
	}
	in := bulkIn(tid, member, bulkItems("fix.bulk.example"))
	in.Origin = scopedom.OriginRefusalFix
	out, err := svc.CreateTargets(ctx, in)
	if err != nil || out[0].Err != nil || out[0].Target.Origin() != scopedom.OriginRefusalFix {
		t.Fatalf("refusal_fix origin: %v %v", err, out[0].Err)
	}
	in = bulkIn(tid, member, bulkItems("sys.bulk.example"))
	in.Origin = scopedom.OriginSystem
	out, err = svc.CreateTargets(ctx, in)
	if err != nil || out[0].Err != nil || out[0].Target.Origin() != scopedom.OriginImport {
		t.Fatalf("a client cannot pick origin system: %v %v", err, out[0].Err)
	}
}

func countTenantTargets(t *testing.T, tr *mockTargetRepo, tid shared.ID) int {
	t.Helper()
	n := 0
	for _, x := range tr.targets {
		if x.TenantID() == tid {
			n++
		}
	}
	return n
}
