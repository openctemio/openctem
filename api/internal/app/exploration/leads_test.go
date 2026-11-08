package exploration

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/exploration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// scopeOf is the caller's data scope: restricted (a member) or not.
type scopeOf struct{ restricted bool }

func (s scopeOf) ResolveStrict(_ context.Context, t shared.ID) (*shared.DataScope, error) {
	if !s.restricted {
		return nil, nil
	}
	return &shared.DataScope{TenantID: t, UserID: shared.NewID()}, nil
}

func (s scopeOf) ViewerScope(ctx context.Context, t shared.ID) (*shared.DataScope, bool, error) {
	sc, err := s.ResolveStrict(ctx, t)
	return sc, false, err
}

// assetsOf serves assets of one tenant that are in the caller's scope.
type assetsOf struct {
	tenant shared.ID
	assets map[string]*assetdom.Asset
}

func (a assetsOf) GetAssetInCallerScope(_ context.Context, tenantID, id string) (*assetdom.Asset, error) {
	x, ok := a.assets[id]
	if !ok || tenantID != a.tenant.String() {
		return nil, shared.ErrNotFound
	}
	return x, nil
}

type leadFixture struct {
	tenant shared.ID
	repo   *memRepo
	audit  *memAudit
	assets assetsOf
	person Person
}

func newLeadFixture(t *testing.T) *leadFixture {
	t.Helper()
	f := &leadFixture{tenant: shared.NewID(), repo: newMemRepo(), audit: &memAudit{}}
	f.assets = assetsOf{tenant: f.tenant, assets: map[string]*assetdom.Asset{}}
	f.person = Person{UserID: shared.NewID(), Actx: auditapp.AuditContext{ActorID: "u", ActorEmail: "u@example.com"}}
	return f
}

func (f *leadFixture) asset(t *testing.T, typ assetdom.AssetType) *assetdom.Asset {
	t.Helper()
	a, err := assetdom.NewAssetWithTenant(f.tenant, "x.example.com", typ, assetdom.CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}
	f.assets.assets[a.ID().String()] = a
	return a
}

func (f *leadFixture) svc(auto, restricted bool) *LeadService {
	return NewLeadService(f.repo, scopeOf{restricted: restricted}, f.assets, fixedSwitch{on: auto}, f.audit, logger.NewNop())
}

func TestLeadService_OpenByAPerson(t *testing.T) {
	f := newLeadFixture(t)
	a := f.asset(t, assetdom.AssetTypeSubdomain)
	s := f.svc(false, false)
	l, err := s.Open(context.Background(), f.tenant, f.person, OpenInput{LeadType: "dns.takeover_check", AssetID: a.ID().String(), Rationale: "<script>x</script> stays text"})
	if err != nil {
		t.Fatal(err)
	}
	// Active step, automatic coverage off: waits for a person.
	if l.State != exploration.StateAwaitingApproval || l.Origin != exploration.OriginUser || *l.CreatedBy != f.person.UserID {
		t.Fatalf("lead %+v", l)
	}
	if len(f.audit.events) != 1 || f.audit.events[0].Action != audit.ActionExplorationLeadOpened || f.audit.ctxs[0].ActorID != "u" {
		t.Fatal("opening by a person is audited with the person")
	}
	if _, err := s.Open(context.Background(), f.tenant, f.person, OpenInput{LeadType: "dns.takeover_check", AssetID: a.ID().String()}); !errors.Is(err, ErrAlreadyAsked) {
		t.Fatalf("same question twice: %v", err)
	}
}

func TestLeadService_OpenRefusals(t *testing.T) {
	f := newLeadFixture(t)
	repoAsset := f.asset(t, assetdom.AssetTypeRepository)
	s := f.svc(true, false)
	other := shared.NewID()
	cases := map[string]struct {
		tenant shared.ID
		in     OpenInput
		want   error
	}{
		"asset outside the caller's scope or tenant": {f.tenant, OpenInput{LeadType: "dns.takeover_check", AssetID: shared.NewID().String()}, shared.ErrNotFound},
		"another tenant":               {other, OpenInput{LeadType: "dns.takeover_check", AssetID: repoAsset.ID().String()}, shared.ErrNotFound},
		"unknown type":                 {f.tenant, OpenInput{LeadType: "shell.run", AssetID: repoAsset.ID().String()}, shared.ErrValidation},
		"no action for the asset type": {f.tenant, OpenInput{LeadType: "dns.takeover_check", AssetID: repoAsset.ID().String()}, shared.ErrValidation},
	}
	for name, c := range cases {
		if _, err := s.Open(context.Background(), c.tenant, f.person, c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

func TestLeadService_ApproveAndDismiss(t *testing.T) {
	f := newLeadFixture(t)
	s := f.svc(false, false)
	a := f.asset(t, assetdom.AssetTypeSubdomain)
	waiting, _ := s.Open(context.Background(), f.tenant, f.person, OpenInput{LeadType: "dns.takeover_check", AssetID: a.ID().String()})
	b := f.asset(t, assetdom.AssetTypeDomain)
	passive, _ := s.Open(context.Background(), f.tenant, f.person, OpenInput{LeadType: "asset.gone_with_findings", AssetID: b.ID().String()})
	if passive.State != exploration.StateOpen {
		t.Fatalf("a passive step opens at once: %s", passive.State)
	}
	approver := Person{UserID: shared.NewID()}
	res, err := s.Approve(context.Background(), f.tenant, approver, []string{waiting.ID.String(), passive.ID.String(), shared.NewID().String(), "nope"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"", BulkState, BulkNotFound, BulkNotFound}
	for i, r := range res {
		if r.Error != want[i] || r.OK != (want[i] == "") {
			t.Errorf("result %d = %+v, want %q", i, r, want[i])
		}
	}
	got, _ := f.repo.GetLead(context.Background(), f.tenant, waiting.ID, nil)
	if got.State != exploration.StateOpen || got.ApprovedBy == nil || *got.ApprovedBy != approver.UserID {
		t.Fatalf("approved lead %+v", got)
	}
	// Another tenant cannot approve or dismiss this tenant's leads.
	if res, _ := s.Dismiss(context.Background(), shared.NewID(), approver, []string{passive.ID.String()}, ""); res[0].Error != BulkNotFound {
		t.Fatalf("cross-tenant dismiss: %+v", res)
	}
	if res, _ := s.Dismiss(context.Background(), f.tenant, approver, []string{passive.ID.String()}, "covered elsewhere"); !res[0].OK {
		t.Fatalf("dismiss: %+v", res)
	}
	last := f.audit.events[len(f.audit.events)-1]
	if last.Action != audit.ActionExplorationLeadDismissed || last.Metadata["reason"] != "covered elsewhere" {
		t.Fatalf("dismiss audit %+v", last)
	}
	if _, err := s.Approve(context.Background(), f.tenant, approver, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("an empty bulk call is refused")
	}
}

// A restricted caller cannot read, approve or dismiss a lead whose subject
// is outside their data scope.
func TestLeadService_OutOfDataScope(t *testing.T) {
	f := newLeadFixture(t)
	open := f.svc(false, false)
	a := f.asset(t, assetdom.AssetTypeSubdomain)
	l, _ := open.Open(context.Background(), f.tenant, f.person, OpenInput{LeadType: "dns.takeover_check", AssetID: a.ID().String()})
	member := f.svc(false, true)
	if _, err := member.Get(context.Background(), f.tenant, l.ID.String(), Person{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("out-of-scope read: %v", err)
	}
	if res, _ := member.Approve(context.Background(), f.tenant, Person{UserID: shared.NewID()}, []string{l.ID.String()}); res[0].Error != BulkNotFound {
		t.Fatalf("out-of-scope approve: %+v", res)
	}
	f.repo.inScope[a.ID()] = true
	if _, err := member.Get(context.Background(), f.tenant, l.ID.String(), Person{}); err != nil {
		t.Fatalf("in-scope read: %v", err)
	}
}

// A run the lead was dispatched as is shown only with scans:read.
func TestLeadService_RunHiddenWithoutScansRead(t *testing.T) {
	f := newLeadFixture(t)
	s := f.svc(true, false)
	a := f.asset(t, assetdom.AssetTypeDomain)
	l, _ := s.Open(context.Background(), f.tenant, f.person, OpenInput{LeadType: "asset.gone_with_findings", AssetID: a.ID().String()})
	run := shared.NewID()
	_, _ = f.repo.AddLinks(context.Background(), []exploration.Link{{TenantID: f.tenant, LeadID: l.ID, Rel: exploration.RelDispatchedAs, EndKind: exploration.EndScanRun, EndID: &run}})
	d, err := s.Get(context.Background(), f.tenant, l.ID.String(), Person{Scans: false})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range d.Links {
		if k.EndKind == exploration.EndScanRun && k.EndID != nil {
			t.Fatal("run id shown without scans:read")
		}
	}
}

// rollupRepo is memRepo with marker figures: org-wide 7 open, scoped 1.
type rollupRepo struct {
	*memRepo
	refreshed int
}

func (r *rollupRepo) RefreshRollup(context.Context, shared.ID, shared.ID) error {
	r.refreshed++
	return nil
}

func (r *rollupRepo) Rollup(context.Context, shared.ID, shared.ID) (*exploration.Summary, error) {
	return &exploration.Summary{Open: 7, ComputedAt: time.Now().Add(-2 * time.Minute)}, nil
}

func (r *rollupRepo) ScopedSummary(context.Context, shared.ID, shared.ID, *shared.DataScope) (*exploration.Summary, error) {
	return &exploration.Summary{Open: 1, Scoped: true}, nil
}

type viewer struct {
	restricted, orgWide bool
}

func (v viewer) ResolveStrict(_ context.Context, t shared.ID) (*shared.DataScope, error) {
	sc, _, err := v.ViewerScope(context.Background(), t)
	return sc, err
}

func (v viewer) ViewerScope(_ context.Context, t shared.ID) (*shared.DataScope, bool, error) {
	if !v.restricted {
		return nil, false, nil
	}
	return &shared.DataScope{TenantID: t, UserID: shared.NewID()}, v.orgWide, nil
}

// Organization-wide figures only for those who may see them; a restricted
// member gets their own scope's counts.
func TestLeadService_SummaryFollowsTheViewer(t *testing.T) {
	tenant := shared.NewID()
	for name, c := range map[string]struct {
		v        viewer
		wantOpen int
	}{
		"unrestricted":            {viewer{}, 7},
		"organization dashboards": {viewer{restricted: true, orgWide: true}, 7},
		"restricted member":       {viewer{restricted: true}, 1},
	} {
		repo := &rollupRepo{memRepo: newMemRepo()}
		s := NewLeadService(repo, c.v, nil, nil, nil, logger.NewNop())
		got, err := s.Summary(context.Background(), tenant, false)
		if err != nil || got.Open != c.wantOpen {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
	repo := &rollupRepo{memRepo: newMemRepo()}
	s := NewLeadService(repo, viewer{}, nil, nil, nil, logger.NewNop())
	if _, err := s.Summary(context.Background(), tenant, true); err != nil || repo.refreshed != 1 {
		t.Fatalf("Refresh now on stale figures: refreshed %d (%v)", repo.refreshed, err)
	}
}
