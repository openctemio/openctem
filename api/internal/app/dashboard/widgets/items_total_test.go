package widgets

import (
	"context"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// itemsFacts ranks two findings and counts the open list per filter, so the
// test can compare the widget's total with the list its drill-down opens.
type itemsFacts struct {
	*ctemFacts
	counted []dashboard.WidgetFilter
	scopes  []dashboard.ReadScope
}

func (f *itemsFacts) Rank(context.Context, dashboard.ReadScope, dashboard.RankKind, dashboard.WidgetFilter, int) ([]dashboard.RankItem, error) {
	return []dashboard.RankItem{
		{FindingID: shared.NewID(), Title: "a", Severity: "high", PriorityClass: "P0"},
		{FindingID: shared.NewID(), Title: "b", Severity: "low", PriorityClass: "P1"},
	}, nil
}

func (f *itemsFacts) CountOpen(_ context.Context, s dashboard.ReadScope, w dashboard.WidgetFilter, _ []dashboard.Dimension) ([]dashboard.CountRow, error) {
	f.counted = append(f.counted, w)
	f.scopes = append(f.scopes, s)
	// Split across two rows: the widget sums them.
	return []dashboard.CountRow{{Count: 700}, {Count: 91}}, nil
}

func TestFixNext_TotalIsTheDrillListCountInTheReadScope(t *testing.T) {
	facts := &itemsFacts{ctemFacts: &ctemFacts{}}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, ctemWidget("fix.next", "table", 10), true, scope)
	if v.State != StateReady || v.Items == nil || len(v.Items.Rows) != 2 {
		t.Fatalf("state %s items %+v", v.State, v.Items)
	}
	if v.Items.Total == nil || *v.Items.Total != 791 {
		t.Fatalf("total = %v, want 791", v.Items.Total)
	}
	if len(facts.counted) != 1 {
		t.Fatalf("CountOpen called %d times", len(facts.counted))
	}
	// The count uses the filter the drill-down opens, and the caller's scope.
	if got, want := v.Drill, drillHref(facts.counted[0]); got != want {
		t.Errorf("drill %q, count filter opens %q", got, want)
	}
	if !reflect.DeepEqual(facts.counted[0].PriorityClass, []string{"P0", "P1", "P2"}) {
		t.Errorf("count filter priorities = %v", facts.counted[0].PriorityClass)
	}
	got := facts.scopes[0]
	if got.TenantID != scope.TenantID || got.Assets != scope.Assets || got.CampaignViewer != scope.CampaignViewer {
		t.Errorf("total read another scope: %+v", got)
	}
}

func TestSLAAtRisk_HasNoTotal(t *testing.T) {
	facts := &itemsFacts{ctemFacts: &ctemFacts{}}
	s := NewService(nil, nil, facts, nil)
	v := s.widget(context.Background(), 0, ctemWidget("sla.at_risk", "list", 10), true, restrictedScope())
	if v.Items == nil || v.Items.Total != nil || len(facts.counted) != 0 {
		t.Fatalf("sla list total %v counted %d", v.Items, len(facts.counted))
	}
}
