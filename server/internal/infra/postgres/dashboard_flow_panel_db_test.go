package postgres

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func flowTestDashboard(t *testing.T, tenant, user shared.ID, org bool) *dashboard.Dashboard {
	t.Helper()
	w := []dashboard.Widget{{WidgetType: "kpi", W: 3, H: 2, Config: map[string]any{"id": "a"}}}
	var d *dashboard.Dashboard
	var err error
	if org {
		d, err = dashboard.NewOrgDashboard(tenant, "Org "+shared.NewID().String(), "", 2, w)
	} else {
		d, err = dashboard.NewDashboard(tenant, user, "Mine "+shared.NewID().String(), "", 2, w)
	}
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// AddFlowPanel is one UPDATE guarded by flow_panel_at IS NULL in the caller's
// tenant and owner: a second or concurrent call, another tenant, another
// owner and the other kind change nothing.
func TestUserDashboardFlowPanel_ConditionalUpdate_DB(t *testing.T) {
	ctx := context.Background()
	sqldb := openGroupsDB(t)
	db := &DB{DB: sqldb}
	repo := NewUserDashboardRepository(db)
	tenant, other := seedTestTenant(ctx, t, sqldb), seedTestTenant(ctx, t, sqldb)
	user := shared.NewID()
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'flow')`, user.String(), user.String()+"@flow.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String())
	})

	d := flowTestDashboard(t, tenant, user, false)
	if err := repo.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	// A new row defaults to "already offered": never auto-offered.
	got, err := repo.GetByID(ctx, tenant, user, d.ID())
	if err != nil || got.FlowPanelAt() == nil {
		t.Fatalf("new dashboard flow_panel_at = %v, %v; want the creation time", got, err)
	}
	// An existing row (NULL) is eligible.
	if _, err := sqldb.ExecContext(ctx, `UPDATE user_dashboards SET flow_panel_at = NULL WHERE id = $1`, d.ID().String()); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := d.PrependFlowPanel(); err != nil {
		t.Fatal(err)
	}

	// Another tenant with the same dashboard id: 0 rows.
	foreignSame := dashboard.Reconstruct(dashboard.Stored{ID: d.ID(), TenantID: other, UserID: user, Kind: dashboard.KindPersonal,
		Name: "x", Columns: 2, Widgets: d.Widgets()})
	if won, err := repo.AddFlowPanel(ctx, foreignSame, now); err != nil || won {
		t.Fatalf("another tenant won = %v, %v", won, err)
	}
	// Another owner in the right tenant: 0 rows.
	notOwner := dashboard.Reconstruct(dashboard.Stored{ID: d.ID(), TenantID: tenant, UserID: shared.NewID(), Kind: dashboard.KindPersonal,
		Name: "x", Columns: 2, Widgets: d.Widgets()})
	if won, err := repo.AddFlowPanel(ctx, notOwner, now); err != nil || won {
		t.Fatalf("another owner won = %v, %v", won, err)
	}
	// The organization path does not reach a personal row.
	asOrg := dashboard.Reconstruct(dashboard.Stored{ID: d.ID(), TenantID: tenant, Kind: dashboard.KindOrganization,
		Name: "x", Columns: 2, Widgets: d.Widgets()})
	if won, err := repo.AddFlowPanel(ctx, asOrg, now); err != nil || won {
		t.Fatalf("org path won on a personal row = %v, %v", won, err)
	}
	if cur, _ := repo.GetByID(ctx, tenant, user, d.ID()); cur.FlowPanelAt() != nil || len(cur.Widgets()) != 1 {
		t.Fatalf("refused writes changed the row: %v widgets=%d", cur.FlowPanelAt(), len(cur.Widgets()))
	}

	// Concurrent opens: exactly one wins.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if won, err := repo.AddFlowPanel(ctx, d, now); err == nil && won {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("concurrent winners = %d, want 1", wins.Load())
	}
	cur, err := repo.GetByID(ctx, tenant, user, d.ID())
	if err != nil || cur.FlowPanelAt() == nil || !cur.HasFlowWidget() || len(cur.Widgets()) != 2 || cur.Widgets()[1].Y != 4 {
		t.Fatalf("stored = %+v %v", cur, err)
	}

	// add -> undo -> add: the second add changes nothing.
	if err := cur.RemoveFlowWidget("w_flow"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	again := dashboard.Reconstruct(dashboard.Stored{ID: d.ID(), TenantID: tenant, UserID: user, Kind: dashboard.KindPersonal,
		Name: d.Name(), Columns: 2, Widgets: d.Widgets()})
	if won, err := repo.AddFlowPanel(ctx, again, now); err != nil || won {
		t.Fatalf("add after undo won = %v, %v", won, err)
	}
	if after, _ := repo.GetByID(ctx, tenant, user, d.ID()); after.HasFlowWidget() || after.FlowPanelAt() == nil {
		t.Fatalf("after undo and re-add: flow=%v at=%v", after.HasFlowWidget(), after.FlowPanelAt())
	}

	// MarkFlowPanel: sets NULL once, leaves the layout alone.
	m := flowTestDashboard(t, tenant, user, false)
	if err := repo.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.ExecContext(ctx, `UPDATE user_dashboards SET flow_panel_at = NULL WHERE id = $1`, m.ID().String()); err != nil {
		t.Fatal(err)
	}
	if won, err := repo.MarkFlowPanel(ctx, m, now); err != nil || !won {
		t.Fatalf("mark = %v, %v", won, err)
	}
	if won, err := repo.MarkFlowPanel(ctx, m, now); err != nil || won {
		t.Fatalf("second mark = %v, %v", won, err)
	}

	// Organization dashboard: same guard through the org path, tenant-bound.
	o := flowTestDashboard(t, tenant, shared.ID{}, true)
	if err := repo.Create(ctx, o); err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.ExecContext(ctx, `UPDATE user_dashboards SET flow_panel_at = NULL WHERE id = $1`, o.ID().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PrependFlowPanel(); err != nil {
		t.Fatal(err)
	}
	foreignOrg := dashboard.Reconstruct(dashboard.Stored{ID: o.ID(), TenantID: other, Kind: dashboard.KindOrganization, Name: "x", Columns: 2, Widgets: o.Widgets()})
	if won, err := repo.AddFlowPanel(ctx, foreignOrg, now); err != nil || won {
		t.Fatalf("another tenant won the org row = %v, %v", won, err)
	}
	if won, err := repo.AddFlowPanel(ctx, o, now); err != nil || !won {
		t.Fatalf("org add = %v, %v", won, err)
	}
	if won, err := repo.AddFlowPanel(ctx, o, now); err != nil || won {
		t.Fatalf("second org add = %v, %v", won, err)
	}
}
