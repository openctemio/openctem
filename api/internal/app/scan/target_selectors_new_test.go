package scan

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type recordingSelector struct{ queries []scan.SelectorQuery }

func (r *recordingSelector) ListSelectorAssets(_ context.Context, q scan.SelectorQuery) ([]*assetgroup.ScanMember, error) {
	r.queries = append(r.queries, q)
	return []*assetgroup.ScanMember{{ID: shared.NewID(), Name: "new.example.com", Type: "subdomain"}}, nil
}

type scanRuns struct {
	scanrun.RunRepository
	runs []*scanrun.Run
	err  error
}

func (s scanRuns) ListByScanID(context.Context, shared.ID, int, int) ([]*scanrun.Run, int64, error) {
	return s.runs, int64(len(s.runs)), s.err
}

// Continuous discovery: a scan with new_since_last_run asks the inventory
// for assets newly in scope since its previous successful run (a failed or
// another tenant's run does not count), and does not add the apex itself.
func TestExpandSelectors_NewSinceLastRun(t *testing.T) {
	tenant := shared.NewID()
	ok := time.Now().UTC().Add(-24 * time.Hour)
	failed := time.Now().UTC().Add(-time.Hour)
	foreign := time.Now().UTC().Add(-time.Minute)
	runs := scanRuns{runs: []*scanrun.Run{
		{TenantID: tenant, Status: scanrun.RunStatusCompleted, StartedAt: &ok},
		{TenantID: tenant, Status: scanrun.RunStatusFailed, StartedAt: &failed},
		{TenantID: shared.NewID(), Status: scanrun.RunStatusCompleted, StartedAt: &foreign},
	}}
	sel := &recordingSelector{}
	s := &Service{selectorAssets: sel, runRepo: runs}
	sc, err := scan.NewScanWithTargets(tenant, "probe new", []string{"*.example.com"}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.SetTargetOptions(scan.TargetOptions{NewSinceLastRun: true}); err != nil {
		t.Fatal(err)
	}
	exp, err := s.expandSelectors(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.queries) != 1 || !sel.queries[0].NewOnly || sel.queries[0].NewSince == nil || !sel.queries[0].NewSince.Equal(ok) {
		t.Fatalf("query = %+v, want NewOnly since the last completed run", sel.queries)
	}
	if slices.Contains(exp.Literal, "example.com") {
		t.Fatalf("literal targets %v: the apex is added only when it is new", exp.Literal)
	}
	if !slices.Equal(exp.Roots, []string{"example.com"}) {
		t.Fatalf("roots = %v, discovery still seeds from the apex", exp.Roots)
	}

	// A failed read of the runs refuses the run.
	s.runRepo = scanRuns{err: errors.New("db down")}
	if _, err := s.expandSelectors(context.Background(), sc); err == nil {
		t.Fatal("an unreadable run history must refuse the run")
	}
	// No previous successful run: everything newly in scope (no since).
	sel.queries = nil
	s.runRepo = scanRuns{}
	if _, err := s.expandSelectors(context.Background(), sc); err != nil || sel.queries[0].NewSince != nil {
		t.Fatalf("first run: %v %+v", err, sel.queries)
	}
}
