package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestRolloverFirst(t *testing.T) {
	cases := []struct {
		name       string
		targets    []string
		unfinished []string
		want       []string
		moved      int
	}{
		{"nothing unfinished", []string{"a", "b"}, nil, []string{"a", "b"}, 0},
		{"moves leftovers to the front in their order",
			[]string{"a", "b", "c", "d"}, []string{"d", "b"}, []string{"d", "b", "a", "c"}, 2},
		{"never adds a target the gate no longer resolves",
			[]string{"a", "b"}, []string{"gone.example", "b"}, []string{"b", "a"}, 1},
		{"no leftover still resolved keeps the order",
			[]string{"a", "b"}, []string{"gone.example"}, []string{"a", "b"}, 0},
		{"matches ignoring case and space, keeps this run's spelling",
			[]string{"Host.Example", "a"}, []string{" host.example "}, []string{"Host.Example", "a"}, 1},
		{"duplicate leftovers move once",
			[]string{"a", "b"}, []string{"b", "B", "b"}, []string{"b", "a"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, n := rolloverFirst(tc.targets, tc.unfinished)
			if !reflect.DeepEqual(got, tc.want) || n != tc.moved {
				t.Fatalf("rolloverFirst = %v, %d; want %v, %d", got, n, tc.want, tc.moved)
			}
		})
	}
}

// rolloverRunRepo is a RunRepository that also serves rollovers, and records
// the tenant and scan it was asked about.
type rolloverRunRepo struct {
	pipeline.RunRepository
	ro                 *pipeline.Rollover
	err                error
	gotTenant, gotScan shared.ID
	calls              int
}

func (r *rolloverRunRepo) LatestRollover(_ context.Context, tenantID, scanID shared.ID) (*pipeline.Rollover, error) {
	r.calls++
	r.gotTenant, r.gotScan = tenantID, scanID
	return r.ro, r.err
}

func (r *rolloverRunRepo) GetUnfinishedTargets(context.Context, shared.ID, shared.ID) ([]string, error) {
	return nil, nil
}

func TestPlanRolloverFirst(t *testing.T) {
	from := shared.NewID()
	sc := &scan.Scan{ID: shared.NewID(), TenantID: shared.NewID()}

	t.Run("scheduled run plans the leftovers first, asking for its own tenant and scan", func(t *testing.T) {
		repo := &rolloverRunRepo{ro: &pipeline.Rollover{FromRunID: from, Targets: []string{"c"}}}
		svc := &Service{runRepo: repo, logger: logger.NewNop()}
		resolved := &resolvedTargets{Targets: []string{"a", "b", "c"}}
		rc := map[string]any{}
		svc.planRolloverFirst(context.Background(), sc, pipeline.TriggerTypeSchedule, resolved, rc)
		if !reflect.DeepEqual(resolved.Targets, []string{"c", "a", "b"}) {
			t.Fatalf("targets = %v, want c first", resolved.Targets)
		}
		if rc["rollover_from_run_id"] != from.String() || rc["rollover_target_count"] != 1 {
			t.Fatalf("run context = %v", rc)
		}
		if repo.gotTenant != sc.TenantID || repo.gotScan != sc.ID {
			t.Fatalf("asked tenant=%s scan=%s, want the scan's own", repo.gotTenant, repo.gotScan)
		}
	})

	for _, trig := range []pipeline.TriggerType{pipeline.TriggerTypeManual, pipeline.TriggerTypeAPI} {
		t.Run("no rollover for "+string(trig), func(t *testing.T) {
			repo := &rolloverRunRepo{ro: &pipeline.Rollover{FromRunID: from, Targets: []string{"c"}}}
			svc := &Service{runRepo: repo, logger: logger.NewNop()}
			resolved := &resolvedTargets{Targets: []string{"a", "c"}}
			rc := map[string]any{}
			svc.planRolloverFirst(context.Background(), sc, trig, resolved, rc)
			if repo.calls != 0 || !reflect.DeepEqual(resolved.Targets, []string{"a", "c"}) || len(rc) != 0 {
				t.Fatalf("calls=%d targets=%v rc=%v, want untouched", repo.calls, resolved.Targets, rc)
			}
		})
	}

	t.Run("a read error keeps the usual order", func(t *testing.T) {
		repo := &rolloverRunRepo{err: errors.New("db down")}
		svc := &Service{runRepo: repo, logger: logger.NewNop()}
		resolved := &resolvedTargets{Targets: []string{"a", "c"}}
		svc.planRolloverFirst(context.Background(), sc, pipeline.TriggerTypeSchedule, resolved, map[string]any{})
		if !reflect.DeepEqual(resolved.Targets, []string{"a", "c"}) {
			t.Fatalf("targets = %v", resolved.Targets)
		}
	})
}
