package unit

// The scope join runs after every committed scope change that can confirm a
// waiting name, from the service so every path gets it (RFC-054 §4.3): an
// entry coming into effect (created, approved, activated), an entry in effect
// changing, an exclusion going away or shrinking. Nothing that cannot
// confirm anything asks for a run (a pending request, a rejection).

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type joinRecorder struct {
	scheduled []shared.ID
	confirm   []scope.JoinedAsset
}

func (j *joinRecorder) Schedule(id shared.ID) { j.scheduled = append(j.scheduled, id) }
func (j *joinRecorder) RunNow(context.Context, shared.ID) ([]scope.JoinedAsset, error) {
	return j.confirm, nil
}
func (j *joinRecorder) Preview(_ context.Context, _ shared.ID, c *scopedom.Target) ([]scope.JoinedAsset, error) {
	out := make([]scope.JoinedAsset, 0, len(j.confirm))
	for _, a := range j.confirm {
		a.CoveredBy = "scope_target:" + c.ID().String()
		out = append(out, a)
	}
	return out, nil
}

// visibleOnly counts the ids in its set; a nil data scope sees every one.
type visibleOnly map[string]bool

func (v visibleOnly) CountVisibleAssets(_ context.Context, _ shared.ID, ds *shared.DataScope, ids []string) (int, error) {
	if ds == nil {
		return len(ids), nil
	}
	n := 0
	for _, id := range ids {
		if v[id] {
			n++
		}
	}
	return n, nil
}

type fixedScope struct{ ds *shared.DataScope }

func (f fixedScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) { return f.ds, nil }

func TestScopeJoinTrigger_EntryChanges(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := entryService(t, 2, tenant.ScopeSettings{})
	j := &joinRecorder{}
	svc.SetScopeJoin(j, visibleOnly{})
	tenantID := shared.NewID()

	// A pending entry (the other admin must approve) confirms nothing yet.
	e, err := create(svc, tenantID, approverA, "*.trig.example", nil)
	if err != nil || e.IsActive() {
		t.Fatalf("pending entry: %v %v", e, err)
	}
	if len(j.scheduled) != 0 {
		t.Fatalf("a pending entry asked for a join: %v", j.scheduled)
	}
	// A member's request: pending too.
	if _, err := create(svc, tenantID, member, "req.trig.example", func(in *scope.CreateTargetInput) {
		in.ExpiresInDays, in.Reason = days(3), "test"
	}); err != nil {
		t.Fatal(err)
	}
	if len(j.scheduled) != 0 {
		t.Fatal("a member's request asked for a join")
	}
	// Approval puts it into effect: one run for this tenant.
	if _, effective, err := svc.ApproveTarget(ctx, e.ID().String(), tenantID.String(), approverB); err != nil || !effective {
		t.Fatalf("approve: %v %v", effective, err)
	}
	if len(j.scheduled) != 1 || j.scheduled[0] != tenantID {
		t.Fatalf("approval scheduled %v, want one run of the tenant", j.scheduled)
	}
	// An entry in effect that changes asks again.
	desc := "changed"
	if _, err := svc.UpdateTarget(ctx, e.ID().String(), tenantID.String(), scope.UpdateTargetInput{Description: &desc, Actor: approverA}); err != nil {
		t.Fatal(err)
	}
	if len(j.scheduled) != 2 {
		t.Fatalf("update of an entry in effect: %d runs, want 2", len(j.scheduled))
	}
	// Deactivate, then activate: activation asks again (2 admins: it may go
	// back to pending, which asks nothing).
	if _, err := svc.DeactivateTarget(ctx, e.ID().String(), tenantID.String()); err != nil {
		t.Fatal(err)
	}
	n := len(j.scheduled)
	act, err := svc.ActivateTarget(ctx, e.ID().String(), tenantID.String(), approverA)
	if err != nil {
		t.Fatal(err)
	}
	if want := n + map[bool]int{true: 1, false: 0}[act.IsActive()]; len(j.scheduled) != want {
		t.Fatalf("activate (active %v): %d runs, want %d", act.IsActive(), len(j.scheduled), want)
	}
}

func TestScopeJoinTrigger_CreatedInEffect(t *testing.T) {
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{})
	j := &joinRecorder{}
	svc.SetScopeJoin(j, visibleOnly{})
	tenantID := shared.NewID()
	if _, err := create(svc, tenantID, approverA, "*.now.example", nil); err != nil {
		t.Fatal(err)
	}
	if len(j.scheduled) != 1 {
		t.Fatalf("an entry created in effect: %d runs, want 1", len(j.scheduled))
	}
}

func TestScopeJoinTrigger_ExclusionGoesAway(t *testing.T) {
	ctx := context.Background()
	week := time.Now().Add(7 * 24 * time.Hour)
	for name, op := range map[string]func(svc *scope.Service, id, tid string) error{
		"delete": func(svc *scope.Service, id, tid string) error {
			return svc.DeleteExclusion(ctx, id, tid, exclusionApprover)
		},
		"deactivate": func(svc *scope.Service, id, tid string) error {
			_, err := svc.DeactivateExclusion(ctx, id, tid, exclusionApprover)
			return err
		},
		"shorten": func(svc *scope.Service, id, tid string) error {
			day := time.Now().Add(24 * time.Hour)
			_, err := svc.UpdateExclusion(ctx, id, tid, scope.UpdateExclusionInput{ExpiresAt: &day, Reviewer: exclusionApprover})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc, _, er, _ := newTestScopeService()
			j := &joinRecorder{}
			svc.SetScopeJoin(j, visibleOnly{})
			tenantID := shared.NewID()
			exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "keep.trig.example", "prod", &week, "member1")
			if err := exc.Approve("admin1"); err != nil {
				t.Fatal(err)
			}
			er.exclusions[exc.ID().String()] = exc
			if err := op(svc, exc.ID().String(), tenantID.String()); err != nil {
				t.Fatal(err)
			}
			if len(j.scheduled) != 1 || j.scheduled[0] != tenantID {
				t.Fatalf("%s: scheduled %v, want one run of the tenant", name, j.scheduled)
			}
		})
	}
}

// The apply count is the names this entry confirmed that the caller may
// see; the filter names the entry. A restricted caller sees only their own.
func TestScopeJoinNow_CountsOverTheDataScope(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{})
	j := &joinRecorder{}
	tenantID := shared.NewID()
	e, err := create(svc, tenantID, approverA, "*.count.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	src := "scope_target:" + e.ID().String()
	seen, hidden, other := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	j.confirm = []scope.JoinedAsset{{AssetID: seen, CoveredBy: src}, {AssetID: hidden, CoveredBy: src},
		{AssetID: other, CoveredBy: "scope_target:" + shared.NewID().String()}}

	// Unrestricted: both names of this entry (not the other entry's).
	svc.SetScopeJoin(j, visibleOnly{seen: true})
	svc.SetCoverage(nil, fixedScope{nil})
	fb, err := svc.JoinNow(ctx, tenantID.String(), e)
	if err != nil || fb == nil || fb.ConfirmedCount != 2 || fb.CoveredBy != e.ID().String() {
		t.Fatalf("unrestricted: %+v %v", fb, err)
	}
	// Restricted: only the one they may see.
	svc.SetCoverage(nil, fixedScope{&shared.DataScope{TenantID: tenantID, UserID: shared.NewID()}})
	if fb, err = svc.JoinNow(ctx, tenantID.String(), e); err != nil || fb.ConfirmedCount != 1 {
		t.Fatalf("restricted: %+v %v", fb, err)
	}
	// No data scope wired: refused, never a tenant-wide count.
	svc.SetCoverage(nil, nil)
	if _, err := svc.JoinNow(ctx, tenantID.String(), e); err == nil {
		t.Fatal("a count without the data scope")
	}
	// A one-off entry confirms nothing: no run, no count.
	one, err := create(svc, tenantID, approverA, "promo.count.example", func(in *scope.CreateTargetInput) {
		in.ExpiresInDays, in.Reason = days(3), "campaign"
	})
	if err != nil {
		t.Fatal(err)
	}
	if fb, err := svc.JoinNow(ctx, tenantID.String(), one); err != nil || fb != nil {
		t.Fatalf("one-off: %+v %v", fb, err)
	}

	// The preview counts the same way and names no entry.
	svc.SetCoverage(nil, fixedScope{nil})
	j.confirm = []scope.JoinedAsset{{AssetID: seen}, {AssetID: hidden}}
	pv, err := svc.PreviewJoin(ctx, tenantID.String(), "domain", "*.new.example")
	if err != nil || pv.ConfirmedCount != 2 || pv.CoveredBy != "" {
		t.Fatalf("preview: %+v %v", pv, err)
	}
	if _, err := svc.PreviewJoin(ctx, tenantID.String(), "nonsense", "x"); err == nil {
		t.Fatal("preview of an invalid type")
	}
}
