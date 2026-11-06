package aianalysis

import (
	"context"
	"testing"
	"time"

	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// sweepRepo serves a fixed list of active AI agents with no active owner and
// records which ones the sweep paused.
type sweepRepo struct {
	aidom.AIAgentRepository
	list   []*aidom.AIAgent
	paused []shared.ID
}

func (r *sweepRepo) ListActive(context.Context, int) ([]*aidom.AIAgent, error) { return r.list, nil }
func (r *sweepRepo) PeopleOf(context.Context, shared.ID, []aidom.OwnerRef, time.Time) ([]shared.ID, error) {
	return nil, nil
}
func (r *sweepRepo) SetStatus(_ context.Context, tenantID, id shared.ID, _ []aidom.Status, _ aidom.Status, _ aidom.PauseReason) (bool, error) {
	r.paused = append(r.paused, tenantID)
	return true, nil
}

type offModules map[string]bool

func (o offModules) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	if o[tenantID] {
		return map[string]bool{moduledom.ModuleAITriage: true}
	}
	return nil
}

func TestSweep_SkipsTenantWithAITriageOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	repo := &sweepRepo{list: []*aidom.AIAgent{
		{ID: shared.NewID(), TenantID: off},
		{ID: shared.NewID(), TenantID: on},
	}}
	s := New(repo, nil, nil, nil, nil, nil, logger.NewNop())
	s.SetModuleGuard(offModules{off.String(): true})
	n, err := s.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(repo.paused) != 1 || repo.paused[0] != on {
		t.Fatalf("expected only the tenant with ai_triage on to be swept, paused=%v n=%d", repo.paused, n)
	}
}
