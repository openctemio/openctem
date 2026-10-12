package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type tscLister struct {
	rows    []*integration.Integration
	filters []integration.Filter
}

func (l *tscLister) List(_ context.Context, f integration.Filter) (integration.ListResult, error) {
	l.filters = append(l.filters, f)
	start := (f.Page - 1) * f.PerPage
	end := min(start+f.PerPage, len(l.rows))
	if start > len(l.rows) {
		start = len(l.rows)
	}
	return integration.ListResult{Data: l.rows[start:end], Total: int64(len(l.rows))}, nil
}

type tscSyncer struct {
	seen []shared.ID
	fail map[shared.ID]bool
}

func (s *tscSyncer) ScheduledSync(_ context.Context, i *integration.Integration) (bool, error) {
	s.seen = append(s.seen, i.ID())
	if s.fail[i.ID()] {
		return false, errors.New("boom")
	}
	return true, nil
}

func TestTenableSCSyncController_WalksEveryPageAndContinuesOnError(t *testing.T) {
	var rows []*integration.Integration
	for range 5 {
		rows = append(rows, integration.NewIntegration(shared.NewID(), shared.NewID(), "sc",
			integration.CategorySecurity, integration.ProviderTenable, integration.AuthTypeAPIKey))
	}
	lister := &tscLister{rows: rows}
	syncer := &tscSyncer{fail: map[shared.ID]bool{rows[1].ID(): true}}
	c := NewTenableSCSyncController(lister, syncer, logger.NewNop())
	c.pageSize = 2

	queued, err := c.Reconcile(context.Background())
	if err == nil {
		t.Fatal("the first error must be returned")
	}
	if queued != 4 || len(syncer.seen) != 5 {
		t.Fatalf("queued %d, saw %d; want 4 and 5", queued, len(syncer.seen))
	}
	for _, f := range lister.filters {
		if f.Provider == nil || *f.Provider != integration.ProviderTenable {
			t.Fatal("only Tenable integrations are listed")
		}
	}
	if c.Name() != "tenable-sc-sync" || c.Interval() <= 0 {
		t.Fatal("controller identity")
	}
}
