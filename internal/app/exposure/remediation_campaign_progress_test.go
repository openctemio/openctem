package exposure

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// fakeCampaignRepo is an in-memory CampaignRepository for tests.
type fakeCampaignRepo struct {
	store     map[string]*remediation.Campaign
	updateErr error
	updates   int
}

func newFakeCampaignRepo() *fakeCampaignRepo {
	return &fakeCampaignRepo{store: map[string]*remediation.Campaign{}}
}

func (r *fakeCampaignRepo) Create(_ context.Context, c *remediation.Campaign) error {
	r.store[c.ID().String()] = c
	return nil
}

func (r *fakeCampaignRepo) GetByID(_ context.Context, _ shared.ID, id shared.ID) (*remediation.Campaign, error) {
	c, ok := r.store[id.String()]
	if !ok {
		return nil, remediation.ErrCampaignNotFound
	}
	return c, nil
}

func (r *fakeCampaignRepo) Update(_ context.Context, c *remediation.Campaign) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.updates++
	r.store[c.ID().String()] = c
	return nil
}

func (r *fakeCampaignRepo) Delete(_ context.Context, _ shared.ID, id shared.ID) error {
	delete(r.store, id.String())
	return nil
}

func (r *fakeCampaignRepo) List(_ context.Context, _ remediation.CampaignFilter, page pagination.Pagination) (pagination.Result[*remediation.Campaign], error) {
	items := make([]*remediation.Campaign, 0, len(r.store))
	for _, c := range r.store {
		items = append(items, c)
	}
	return pagination.NewResult(items, int64(len(items)), page), nil
}

func (r *fakeCampaignRepo) ListNonTerminal(_ context.Context, _ int) ([]*remediation.Campaign, error) {
	items := make([]*remediation.Campaign, 0, len(r.store))
	for _, c := range r.store {
		if c.Status() != remediation.CampaignStatusCompleted && c.Status() != remediation.CampaignStatusCanceled {
			items = append(items, c)
		}
	}
	return items, nil
}

// fakeCounter returns a scripted total/resolved count regardless of filter,
// keyed by whether the filter restricts to closed statuses.
type fakeCounter struct {
	total    int64
	resolved int64
	calls    int
	err      error
}

func (c *fakeCounter) Count(_ context.Context, filter vulnerability.FindingFilter) (int64, error) {
	c.calls++
	if c.err != nil {
		return 0, c.err
	}
	if len(filter.Statuses) > 0 {
		return c.resolved, nil
	}
	return c.total, nil
}

func newService(repo remediation.CampaignRepository, counter FindingCounter) *RemediationCampaignService {
	s := NewRemediationCampaignService(repo, logger.NewNop())
	if counter != nil {
		s.SetFindingCounter(counter)
	}
	return s
}

func TestCreateCampaign_SeedsProgress(t *testing.T) {
	repo := newFakeCampaignRepo()
	counter := &fakeCounter{total: 10, resolved: 4}
	svc := newService(repo, counter)

	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      shared.NewID().String(),
		Name:          "Fix Log4j",
		FindingFilter: map[string]any{"cve_ids": []any{"CVE-2021-44228"}},
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if c.FindingCount() != 10 || c.ResolvedCount() != 4 {
		t.Fatalf("expected 10/4, got %d/%d", c.FindingCount(), c.ResolvedCount())
	}
	if c.Progress() != 40 {
		t.Fatalf("expected progress 40, got %v", c.Progress())
	}
}

// An unscoped campaign ({} filter) must NOT inherit the tenant-wide count — the
// "every campaign shows N findings linked" bug. Even with a counter that would
// return 89, the empty-scope guard pins it to 0.
func TestCreateCampaign_EmptyFilter_TracksNothing(t *testing.T) {
	repo := newFakeCampaignRepo()
	counter := &fakeCounter{total: 89, resolved: 7}
	svc := newService(repo, counter)

	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID: shared.NewID().String(),
		Name:     "Unscoped",
		// no FindingFilter → empty scope
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if c.FindingCount() != 0 || c.ResolvedCount() != 0 {
		t.Fatalf("unscoped campaign must track nothing, got %d/%d", c.FindingCount(), c.ResolvedCount())
	}
}

func TestFindingFilterHasScope(t *testing.T) {
	tid := shared.NewID()
	empty := campaignFilterToFindingFilter(tid, map[string]any{})
	if findingFilterHasScope(empty) {
		t.Error("empty campaign filter must have no scope")
	}
	scoped := campaignFilterToFindingFilter(tid, map[string]any{"severities": []any{"critical"}})
	if !findingFilterHasScope(scoped) {
		t.Error("severity-scoped campaign filter must have scope")
	}
}

func TestCreateCampaign_NoCounter_StaysZero(t *testing.T) {
	repo := newFakeCampaignRepo()
	svc := newService(repo, nil) // no counter wired

	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID: shared.NewID().String(),
		Name:     "Plain CRUD",
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if c.FindingCount() != 0 || c.Progress() != 0 {
		t.Fatalf("expected zero progress without counter, got %d/%v", c.FindingCount(), c.Progress())
	}
}

func TestGetCampaign_RefreshesLive(t *testing.T) {
	repo := newFakeCampaignRepo()
	counter := &fakeCounter{total: 5, resolved: 0}
	svc := newService(repo, counter)

	tid := shared.NewID().String()
	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      tid,
		Name:          "C",
		FindingFilter: map[string]any{"severities": []any{"critical"}},
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}

	// Simulate findings being resolved between create and read.
	counter.resolved = 5
	got, err := svc.GetCampaign(context.Background(), tid, c.ID().String())
	if err != nil {
		t.Fatalf("GetCampaign: %v", err)
	}
	if got.ResolvedCount() != 5 || got.Progress() != 100 {
		t.Fatalf("expected live refresh 5/100, got %d/%v", got.ResolvedCount(), got.Progress())
	}
}

func TestReconcileProgress_AutoCompletes(t *testing.T) {
	repo := newFakeCampaignRepo()
	counter := &fakeCounter{total: 3, resolved: 0}
	svc := newService(repo, counter)

	tid := shared.NewID().String()
	// Scoped campaign — an unscoped ({}) campaign now correctly tracks nothing,
	// so give it a real filter to exercise the auto-complete path.
	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      tid,
		Name:          "Activate me",
		FindingFilter: map[string]any{"severities": []any{"critical"}},
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if _, err := svc.UpdateCampaignStatus(context.Background(), tid, c.ID().String(), string(remediation.CampaignStatusActive)); err != nil {
		t.Fatalf("activate: %v", err)
	}

	// All findings resolved → reconcile should auto-complete.
	counter.resolved = 3
	updated, err := svc.ReconcileProgress(context.Background())
	if err != nil {
		t.Fatalf("ReconcileProgress: %v", err)
	}
	if updated != 1 {
		t.Fatalf("expected 1 updated, got %d", updated)
	}

	got := repo.store[c.ID().String()]
	if got.Status() != remediation.CampaignStatusCompleted {
		t.Fatalf("expected auto-completed, got status %s", got.Status())
	}
	if got.RiskReduction() == nil || *got.RiskReduction() != 3 {
		t.Fatalf("expected risk reduction 3, got %v", got.RiskReduction())
	}
}

func TestReconcileProgress_NoCounter_NoOp(t *testing.T) {
	repo := newFakeCampaignRepo()
	svc := newService(repo, nil)
	updated, err := svc.ReconcileProgress(context.Background())
	if err != nil {
		t.Fatalf("ReconcileProgress: %v", err)
	}
	if updated != 0 {
		t.Fatalf("expected 0 updated without counter, got %d", updated)
	}
}

func TestCampaignFilterToFindingFilter_MapsKeys(t *testing.T) {
	tid := shared.NewID()
	raw := map[string]any{
		"severities":  []any{"critical", "high"},
		"cve_id":      "CVE-2021-44228",
		"source":      "trivy",
		"search":      "log4j",
		"finding_ids": []any{"01930000-0000-7000-8000-000000000001"},
	}
	f := campaignFilterToFindingFilter(tid, raw)

	if len(f.FindingIDs) != 1 || f.FindingIDs[0] != "01930000-0000-7000-8000-000000000001" {
		t.Fatalf("finding_ids not mapped: %v", f.FindingIDs)
	}

	if f.TenantID == nil || *f.TenantID != tid {
		t.Fatalf("tenant not pinned")
	}
	if len(f.Severities) != 2 {
		t.Fatalf("expected 2 severities, got %d", len(f.Severities))
	}
	if len(f.CVEIDs) != 1 || f.CVEIDs[0] != "CVE-2021-44228" {
		t.Fatalf("cve not mapped: %v", f.CVEIDs)
	}
	if f.Search == nil || *f.Search != "log4j" {
		t.Fatalf("search not mapped")
	}
}
