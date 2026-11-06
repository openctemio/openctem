package dashboard

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	domain "github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// flowRepo is an in-memory dashboard store with the repository's scoping and
// the flow_panel_at IS NULL guard.
type flowRepo struct {
	domain.Repository
	rows map[shared.ID]*domain.Dashboard
}

func (r *flowRepo) GetByID(_ context.Context, tenantID, userID, id shared.ID) (*domain.Dashboard, error) {
	d := r.rows[id]
	if d == nil || d.TenantID() != tenantID || d.UserID() != userID || d.Kind() != domain.KindPersonal {
		return nil, shared.ErrNotFound
	}
	return clone(d), nil
}

func (r *flowRepo) GetOrg(_ context.Context, tenantID, id shared.ID) (*domain.Dashboard, error) {
	d := r.rows[id]
	if d == nil || d.TenantID() != tenantID || d.Kind() != domain.KindOrganization {
		return nil, shared.ErrNotFound
	}
	return clone(d), nil
}

func (r *flowRepo) Update(_ context.Context, d *domain.Dashboard) error {
	if r.rows[d.ID()] == nil {
		return shared.ErrNotFound
	}
	r.rows[d.ID()] = clone(d)
	return nil
}

func (r *flowRepo) AddFlowPanel(_ context.Context, d *domain.Dashboard, now time.Time) (bool, error) {
	cur := r.rows[d.ID()]
	if cur == nil || cur.FlowPanelAt() != nil || cur.TenantID() != d.TenantID() {
		return false, nil
	}
	n := clone(d)
	n.MarkFlowPanelOffered(now)
	r.rows[d.ID()] = n
	return true, nil
}

func (r *flowRepo) MarkFlowPanel(_ context.Context, d *domain.Dashboard, now time.Time) (bool, error) {
	cur := r.rows[d.ID()]
	if cur == nil || cur.FlowPanelAt() != nil || cur.TenantID() != d.TenantID() {
		return false, nil
	}
	cur.MarkFlowPanelOffered(now)
	return true, nil
}

func clone(d *domain.Dashboard) *domain.Dashboard {
	w := make([]domain.Widget, len(d.Widgets()))
	copy(w, d.Widgets())
	return domain.Reconstruct(domain.Stored{
		ID: d.ID(), TenantID: d.TenantID(), UserID: d.UserID(), Kind: d.Kind(), Name: d.Name(),
		Description: d.Description(), Columns: d.Columns(), Widgets: w, FlowPanelAt: d.FlowPanelAt(),
		CreatedAt: d.CreatedAt(), UpdatedAt: d.UpdatedAt(),
	})
}

type auditSink struct{ actions []auditdom.Action }

func (a *auditSink) LogEvent(_ context.Context, _ auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.actions = append(a.actions, ev.Action)
	return nil
}

func kpi(y int, id string) domain.Widget {
	return domain.Widget{WidgetType: "kpi", X: 0, Y: y, W: 3, H: 2, Config: map[string]any{"id": id}}
}

type flowEnv struct {
	s     *Service
	repo  *flowRepo
	audit *auditSink
	c     Caller
}

func newFlowEnv(t *testing.T) *flowEnv {
	t.Helper()
	repo := &flowRepo{rows: map[shared.ID]*domain.Dashboard{}}
	s := NewService(repo, nil)
	a := &auditSink{}
	s.SetAuditService(a)
	return &flowEnv{s: s, repo: repo, audit: a, c: caller()}
}

func (e *flowEnv) personal(t *testing.T, widgets ...domain.Widget) *domain.Dashboard {
	t.Helper()
	d, err := domain.NewDashboard(e.c.TenantID, e.c.UserID, "Mine", "", 2, widgets)
	if err != nil {
		t.Fatal(err)
	}
	d = eligible(d)
	e.repo.rows[d.ID()] = d
	return d
}

// eligible is d as an existing dashboard that was never offered the panel.
func eligible(d *domain.Dashboard) *domain.Dashboard {
	return domain.Reconstruct(domain.Stored{
		ID: d.ID(), TenantID: d.TenantID(), UserID: d.UserID(), Kind: d.Kind(), Name: d.Name(),
		Columns: d.Columns(), Widgets: d.Widgets(), CreatedAt: d.CreatedAt(), UpdatedAt: d.UpdatedAt(),
	})
}

func (e *flowEnv) org(t *testing.T, widgets ...domain.Widget) *domain.Dashboard {
	t.Helper()
	d, err := domain.NewOrgDashboard(e.c.TenantID, "Org", "", 2, widgets)
	if err != nil {
		t.Fatal(err)
	}
	d = eligible(d)
	e.repo.rows[d.ID()] = d
	return d
}

func TestAddFlowPanel_OnceThenUndoNeverReadds(t *testing.T) {
	ctx := context.Background()
	e := newFlowEnv(t)
	d := e.personal(t, kpi(0, "a"), kpi(2, "b"))

	res, err := e.s.AddFlowPanel(ctx, e.c, d.ID().String())
	if err != nil || !res.Added || res.WidgetID != "w_flow" {
		t.Fatalf("first add = %+v %v", res, err)
	}
	w := res.Dashboard.Widgets()
	if len(w) != 3 || !domain.IsFlowWidget(w[0]) || w[0].Y != 0 || w[0].W != 12 || w[0].H != 4 || w[1].Y != 4 || w[2].Y != 6 {
		t.Fatalf("layout after add = %+v", w)
	}
	if res.Dashboard.FlowPanelAt() == nil || e.repo.rows[d.ID()].FlowPanelAt() == nil {
		t.Fatal("flow_panel_at not set")
	}

	res, err = e.s.AddFlowPanel(ctx, e.c, d.ID().String())
	if err != nil || res.Added || len(e.repo.rows[d.ID()].Widgets()) != 3 {
		t.Fatalf("second add = %+v %v", res, err)
	}

	got, err := e.s.UndoFlowPanel(ctx, e.c, d.ID().String(), "w_flow")
	if err != nil || len(got.Widgets()) != 2 || got.HasFlowWidget() {
		t.Fatalf("undo = %+v %v", got, err)
	}
	if got.FlowPanelAt() == nil {
		t.Fatal("undo cleared flow_panel_at")
	}
	res, err = e.s.AddFlowPanel(ctx, e.c, d.ID().String())
	if err != nil || res.Added || len(e.repo.rows[d.ID()].Widgets()) != 2 {
		t.Fatalf("add after undo = %+v %v", res, err)
	}
	want := []auditdom.Action{auditdom.ActionDashboardFlowPanelAdded, auditdom.ActionDashboardFlowPanelUndone}
	if len(e.audit.actions) != 2 || e.audit.actions[0] != want[0] || e.audit.actions[1] != want[1] {
		t.Fatalf("audit = %v, want %v", e.audit.actions, want)
	}
}

func TestAddFlowPanel_UndoRefusesOtherWidgets(t *testing.T) {
	ctx := context.Background()
	e := newFlowEnv(t)
	d := e.personal(t, kpi(0, "a"))
	if _, err := e.s.AddFlowPanel(ctx, e.c, d.ID().String()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "missing", ""} {
		if _, err := e.s.UndoFlowPanel(ctx, e.c, d.ID().String(), id); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("undo %q = %v, want validation error", id, err)
		}
	}
	if n := len(e.repo.rows[d.ID()].Widgets()); n != 2 {
		t.Fatalf("widgets = %d, undo of a non-flow id must delete nothing", n)
	}
	if len(e.audit.actions) != 1 {
		t.Fatalf("a refused undo must not be audited: %v", e.audit.actions)
	}
}

func TestAddFlowPanel_EmptyAndAlreadyHasFlow(t *testing.T) {
	ctx := context.Background()
	e := newFlowEnv(t)
	empty := e.personal(t)
	res, err := e.s.AddFlowPanel(ctx, e.c, empty.ID().String())
	if err != nil || res.Added || len(e.repo.rows[empty.ID()].Widgets()) != 0 || e.repo.rows[empty.ID()].FlowPanelAt() == nil {
		t.Fatalf("empty layout = %+v %v", res, err)
	}

	seed := e.personal(t, kpi(0, "a"))
	if _, err := seed.PrependFlowPanel(); err != nil { // a layout that already holds the flow
		t.Fatal(err)
	}
	res, err = e.s.AddFlowPanel(ctx, e.c, seed.ID().String())
	if err != nil || res.Added || len(e.repo.rows[seed.ID()].Widgets()) != 2 || e.repo.rows[seed.ID()].FlowPanelAt() == nil {
		t.Fatalf("layout with flow = %+v %v", res, err)
	}
	if len(e.audit.actions) != 0 {
		t.Fatalf("marking only is not an add: %v", e.audit.actions)
	}
}

func TestAddFlowPanel_IDCollisionGetsSuffix(t *testing.T) {
	e := newFlowEnv(t)
	d := e.personal(t, kpi(0, "w_flow"))
	res, err := e.s.AddFlowPanel(context.Background(), e.c, d.ID().String())
	if err != nil || !res.Added || res.WidgetID != "w_flow2" {
		t.Fatalf("add = %+v %v", res, err)
	}
}

func TestAddFlowPanel_LosingTheRaceChangesNothing(t *testing.T) {
	ctx := context.Background()
	e := newFlowEnv(t)
	d := e.personal(t, kpi(0, "a"))
	stale, err := e.repo.GetByID(ctx, e.c.TenantID, e.c.UserID, d.ID()) // read before the winner writes
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.AddFlowPanel(ctx, e.c, d.ID().String()); err != nil {
		t.Fatal(err)
	}
	res, err := e.s.addFlowPanel(ctx, e.c, stale)
	if err != nil || res.Added || len(res.Dashboard.Widgets()) != 2 || len(e.audit.actions) != 1 {
		t.Fatalf("loser = %+v %v audit=%v", res, err, e.audit.actions)
	}
}

func TestAddFlowPanel_Authorization(t *testing.T) {
	ctx := context.Background()
	e := newFlowEnv(t)
	mine := e.personal(t, kpi(0, "a"))
	id := mine.ID().String()

	other := caller() // another user, and another tenant
	sameTenant := e.c
	sameTenant.UserID = shared.NewID()
	for name, c := range map[string]Caller{"another user": sameTenant, "another tenant": other} {
		if _, err := e.s.AddFlowPanel(ctx, c, id); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s add = %v, want not found", name, err)
		}
		if _, err := e.s.UndoFlowPanel(ctx, c, id, "w_flow"); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s undo = %v, want not found", name, err)
		}
	}
	if len(e.repo.rows[mine.ID()].Widgets()) != 1 || e.repo.rows[mine.ID()].FlowPanelAt() != nil {
		t.Fatal("a refused caller changed the dashboard")
	}
	if _, err := e.s.AddFlowPanel(ctx, e.c, "not-a-uuid"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad id = %v", err)
	}

	// The personal route never reaches an organization dashboard.
	org := e.org(t, kpi(0, "a"))
	if _, err := e.s.AddFlowPanel(ctx, e.c, org.ID().String()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("personal add on org dashboard = %v", err)
	}

	// Organization: needs dashboards:org:manage.
	e.c.Has = func(p string) bool { return p == "dashboards:org:view" }
	if _, err := e.s.AddOrgFlowPanel(ctx, e.c, org.ID().String()); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("viewer org add = %v, want forbidden", err)
	}
	if _, err := e.s.UndoOrgFlowPanel(ctx, e.c, org.ID().String(), "w_flow"); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("viewer org undo = %v, want forbidden", err)
	}
	e.c.Has = func(p string) bool { return p == "dashboards:org:manage" }
	if _, err := e.s.AddOrgFlowPanel(ctx, other, org.ID().String()); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("no-permission caller of another tenant = %v", err)
	}
	other.Has = e.c.Has
	if _, err := e.s.AddOrgFlowPanel(ctx, other, org.ID().String()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("manager of another tenant = %v, want not found", err)
	}
	res, err := e.s.AddOrgFlowPanel(ctx, e.c, org.ID().String())
	if err != nil || !res.Added {
		t.Fatalf("manager org add = %+v %v", res, err)
	}
	if got, err := e.s.UndoOrgFlowPanel(ctx, e.c, org.ID().String(), res.WidgetID); err != nil || got.HasFlowWidget() {
		t.Fatalf("manager org undo = %+v %v", got, err)
	}
	if len(e.audit.actions) != 2 || e.audit.actions[0] != auditdom.ActionDashboardFlowPanelAdded || e.audit.actions[1] != auditdom.ActionDashboardFlowPanelUndone {
		t.Fatalf("org audit = %v", e.audit.actions)
	}
}
