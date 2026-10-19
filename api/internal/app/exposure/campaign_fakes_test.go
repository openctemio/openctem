package exposure

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// fakeCampaignRepo holds campaigns in memory. Visibility, scope and the
// summaries are set by the test (the SQL behind them is covered by the DB
// tests in internal/infra/http/routes).
type fakeCampaignRepo struct {
	campaigns map[shared.ID]*remediation.Campaign
	whole     remediation.CampaignSummary // the summary every campaign gets
	outside   bool                        // a task has a finding outside the scope
	hidden    bool                        // Visible answers false
	refs      map[shared.ID]*shared.ID    // task -> campaign
	moved     map[shared.ID]*shared.ID
	updates   int
}

func newFakeCampaignRepo(cs ...*remediation.Campaign) *fakeCampaignRepo {
	r := &fakeCampaignRepo{campaigns: map[shared.ID]*remediation.Campaign{}, refs: map[shared.ID]*shared.ID{}, moved: map[shared.ID]*shared.ID{}}
	for _, c := range cs {
		r.campaigns[c.ID()] = c
	}
	return r
}

func (r *fakeCampaignRepo) Create(_ context.Context, c *remediation.Campaign) error {
	r.campaigns[c.ID()] = c
	return nil
}

func (r *fakeCampaignRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*remediation.Campaign, error) {
	c, ok := r.campaigns[id]
	if !ok || c.TenantID() != tenantID {
		return nil, remediation.ErrCampaignNotFound
	}
	return c, nil
}

func (r *fakeCampaignRepo) Update(_ context.Context, c *remediation.Campaign) error {
	r.updates++
	c.SetVersion(c.Version() + 1)
	return nil
}

func (r *fakeCampaignRepo) Delete(_ context.Context, _, id shared.ID) error {
	delete(r.campaigns, id)
	return nil
}

func (r *fakeCampaignRepo) List(_ context.Context, _ remediation.CampaignFilter, page pagination.Pagination) (pagination.Result[*remediation.Campaign], error) {
	out := make([]*remediation.Campaign, 0, len(r.campaigns))
	for _, c := range r.campaigns {
		out = append(out, c)
	}
	return pagination.NewResult(out, int64(len(out)), page), nil
}

func (r *fakeCampaignRepo) CountByStatus(context.Context, shared.ID, remediation.CampaignViewer) (map[remediation.CampaignStatus]int, error) {
	out := map[remediation.CampaignStatus]int{}
	for _, c := range r.campaigns {
		out[c.Status()]++
	}
	return out, nil
}

func (r *fakeCampaignRepo) Visible(context.Context, shared.ID, shared.ID, remediation.CampaignViewer) (bool, error) {
	return !r.hidden, nil
}

func (r *fakeCampaignRepo) HasTaskOutsideScope(_ context.Context, _, _ shared.ID, scope *shared.DataScope) (bool, error) {
	return scope != nil && r.outside, nil
}

func (r *fakeCampaignRepo) Summaries(_ context.Context, _ shared.ID, ids []shared.ID, _ *shared.DataScope) (map[shared.ID]remediation.CampaignSummary, error) {
	out := map[shared.ID]remediation.CampaignSummary{}
	for _, id := range ids {
		out[id] = r.whole
	}
	return out, nil
}

func (r *fakeCampaignRepo) TaskRefs(_ context.Context, _ shared.ID, ids []shared.ID) ([]remediation.CampaignTaskRef, error) {
	var out []remediation.CampaignTaskRef
	for _, id := range ids {
		camp, ok := r.refs[id]
		if !ok {
			continue
		}
		ref := remediation.CampaignTaskRef{TaskID: id, CampaignID: camp}
		if camp != nil {
			if c := r.campaigns[*camp]; c != nil {
				ref.CampaignName = c.Name()
			}
		}
		out = append(out, ref)
	}
	return out, nil
}

func (r *fakeCampaignRepo) SetTasksCampaign(_ context.Context, _ shared.ID, ids []shared.ID, campaignID *shared.ID, _ *shared.ID) ([]shared.ID, error) {
	for _, id := range ids {
		r.refs[id] = campaignID
		r.moved[id] = campaignID
	}
	return ids, nil
}

func (r *fakeCampaignRepo) ListForReconcile(context.Context, int) ([]*remediation.Campaign, error) {
	out := make([]*remediation.Campaign, 0, len(r.campaigns))
	for _, c := range r.campaigns {
		out = append(out, c)
	}
	return out, nil
}

// fakeTasks stands in for the remediation task service.
type fakeTasks struct {
	notWritable map[shared.ID]bool
	live        []shared.ID
	recomputed  []shared.ID
	claimed     []shared.ID
	lastNote    string
	refusals    map[shared.ID][]string
	claimErr    error
}

func (f *fakeTasks) CheckTaskWritable(_ context.Context, _, id shared.ID) error {
	if f.notWritable[id] {
		return shared.ErrNotFound
	}
	return nil
}

func (f *fakeTasks) RecomputeTasks(_ context.Context, _ shared.ID, ids []shared.ID) error {
	f.recomputed = append(f.recomputed, ids...)
	return nil
}

func (f *fakeTasks) CampaignTaskIDs(context.Context, shared.ID, shared.ID) ([]shared.ID, error) {
	return f.live, nil
}

func (f *fakeTasks) ClaimTaskFixed(_ context.Context, _, id shared.ID, note string) ([]string, error) {
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	f.claimed = append(f.claimed, id)
	f.lastNote = note
	return f.refusals[id], nil
}

func newCampaign(t *testing.T) *remediation.Campaign {
	t.Helper()
	c, err := remediation.NewCampaign(shared.NewID(), "Fix Log4j", remediation.CampaignPriorityHigh)
	if err != nil {
		t.Fatalf("NewCampaign: %v", err)
	}
	return c
}

func newTicketSvc(c *remediation.Campaign, tr remediation.CampaignTicketRepository, epic CampaignEpicCreator) *RemediationCampaignService {
	s := NewRemediationCampaignService(newFakeCampaignRepo(c), logger.NewNop())
	s.SetTasks(&fakeTasks{notWritable: map[shared.ID]bool{}})
	if tr != nil || epic != nil {
		s.SetTicketing(tr, epic)
	}
	return s
}
