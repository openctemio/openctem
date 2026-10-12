package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// 22c B7: a run whose steps all finished but whose zone routing left
// targets out did not scan everything it was asked to: it ends partial, not
// completed.
func TestRunWithUncoveredTargets_EndsPartial(t *testing.T) {
	s, run, _, runs, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning},
		nil)
	run.Context = map[string]any{
		"zone_routing":      map[string]any{"uncovered_targets": float64(2)},
		"uncovered_targets": []any{map[string]any{"target": "api.example.com", "reason": "hostname did not resolve from the platform"}},
	}
	if err := s.OnStepCompleted(context.Background(), run.ID.String(), "a", 0, nil); err != nil {
		t.Fatal(err)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

func TestUncoveredTargetCount(t *testing.T) {
	cases := []struct {
		name string
		ctx  map[string]any
		want int
	}{
		{"nothing recorded", map[string]any{}, 0},
		{"zone summary (after a database round trip)", map[string]any{"zone_routing": map[string]any{"uncovered_targets": float64(3)}}, 3},
		{"zone summary with zero", map[string]any{"zone_routing": map[string]any{"uncovered_targets": 0}}, 0},
		{"list only", map[string]any{"uncovered_targets": []any{map[string]any{}, map[string]any{}}}, 2},
		{"typed list (in memory)", map[string]any{"uncovered_targets": []struct{ Target string }{{"a"}}}, 1},
	}
	for _, c := range cases {
		if got := uncoveredTargetCount(c.ctx); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}
