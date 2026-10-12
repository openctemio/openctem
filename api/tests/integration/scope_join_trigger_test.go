package integration

// Approving a pending scope entry confirms, at once, the discovered names it
// covers that wait for review (RFC-054 §4.3), on a real database: the preview
// counts them before, the apply reports them after, the asset list filters
// them by the entry, and one system audit event lists the run. An address is
// never confirmed by a domain entry, an exclusion still wins, and a person's
// decision is untouched.

import (
	"context"
	"testing"
	"time"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	scopesvc "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type unrestrictedScope struct{}

func (unrestrictedScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) {
	return nil, nil
}

func TestScopeJoin_AfterApproval(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)

	var entryID string
	if err := db.QueryRowContext(ctx, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, approvals_required, created_by)
		VALUES ($1, 'domain', '*.trig-a.example', 'pending', 1, 'requester') RETURNING id`, tenantA.String()).Scan(&entryID); err != nil {
		t.Fatal(err)
	}
	seedApprovedExclusion(t, db, tenantA, "domain", "excl.trig-a.example")

	pending := func(tenant shared.ID, name, typ string) shared.ID {
		id := seedOwnedAsset(t, db, tenant, name, typ)
		automatic(t, db, tenant, id, attribution.StateNeedsReview)
		return id
	}
	sub := pending(tenantA, "api.trig-a.example", "subdomain")
	svc := pending(tenantA, "trig-a.example:443:tcp", "service")
	ip := pending(tenantA, "198.51.100.77", "ip_address")
	excluded := pending(tenantA, "excl.trig-a.example", "subdomain")
	rejected := seedOwnedAsset(t, db, tenantA, "gone.trig-a.example", "subdomain")
	decide(t, db, tenantA, rejected, attribution.StateRejected)
	foreign := pending(tenantB, "b.trig-a.example", "subdomain")

	scope := scopeService(db)
	coverage := postgres.NewScopeCoverageRepository(pg)
	scope.SetCoverage(coverage, unrestrictedScope{})
	sched := easmapp.NewJoinScheduler(scopeJoin(db), 10*time.Millisecond, nil)
	scope.SetScopeJoin(sched, coverage)

	// The preview counts what the entry would confirm; nothing changes.
	pv, err := scope.PreviewJoin(ctx, tenantA.String(), "domain", "*.trig-a.example")
	if err != nil || pv.ConfirmedCount != 2 {
		t.Fatalf("preview = %+v, %v; want 2 (the name and its service)", pv, err)
	}
	if st := attributionState(t, db, tenantA, sub); st != attribution.StateNeedsReview {
		t.Fatalf("the preview wrote: %s", st)
	}

	target, effective, err := scope.ApproveTarget(ctx, entryID, tenantA.String(),
		scopesvc.Actor{UserID: shared.NewID().String(), CanApprove: true})
	if err != nil || !effective {
		t.Fatalf("approve: %v %v", effective, err)
	}
	fb, err := scope.JoinNow(ctx, tenantA.String(), target)
	if err != nil || fb == nil || fb.ConfirmedCount != 2 || fb.CoveredBy != entryID {
		t.Fatalf("apply = %+v, %v; want 2 confirmed by %s", fb, err, entryID)
	}
	sched.Wait()

	for _, id := range []shared.ID{sub, svc} {
		if st := attributionState(t, db, tenantA, id); st != attribution.StateConfirmed {
			t.Errorf("%s = %s, want confirmed", id, st)
		}
	}
	for name, c := range map[string]struct {
		tenant shared.ID
		id     shared.ID
		want   attribution.State
	}{
		"an address under no IP entry":   {tenantA, ip, attribution.StateNeedsReview},
		"excluded":                       {tenantA, excluded, attribution.StateNeedsReview},
		"a person's rejected decision":   {tenantA, rejected, attribution.StateRejected},
		"another tenant's name under it": {tenantB, foreign, attribution.StateNeedsReview},
	} {
		if st := attributionState(t, db, c.tenant, c.id); st != c.want {
			t.Errorf("%s: %s, want %s", name, st, c.want)
		}
	}

	// The asset list filter behind "N assets confirmed".
	entry, _ := shared.IDFromString(entryID)
	f := asset.NewFilter().WithTenantID(tenantA.String())
	f.CoveredByScopeTarget = &entry
	res, err := postgres.NewAssetRepository(pg).List(ctx, f, asset.ListOptions{}, pagination.New(1, 20))
	if err != nil || res.Total != 2 {
		t.Fatalf("covered_by list = %d, %v; want 2", res.Total, err)
	}
	fb2 := asset.NewFilter().WithTenantID(tenantB.String())
	fb2.CoveredByScopeTarget = &entry
	if res, err := postgres.NewAssetRepository(pg).List(ctx, fb2, asset.ListOptions{}, pagination.New(1, 20)); err != nil || res.Total != 0 {
		t.Fatalf("tenant B through tenant A's entry: %d %v", res.Total, err)
	}

	// One system audit event for the run, in tenant A only.
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'asset.attribution_auto_confirmed' AND actor_id IS NULL`,
		tenantA.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit events = %d (%v), want 1", n, err)
	}

	// Idempotent: running again confirms and audits nothing.
	if fb, err := scope.JoinNow(ctx, tenantA.String(), target); err != nil || fb.ConfirmedCount != 0 {
		t.Fatalf("second run: %+v %v", fb, err)
	}
}
