package widgets

import (
	"context"
	"testing"
	"time"

	postureapp "github.com/openctemio/openctem/api/internal/app/posture"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/posture"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakePosture struct {
	view   *postureapp.View
	tenant shared.ID
	assets *shared.DataScope
}

func (f *fakePosture) ReadForScope(_ context.Context, tenantID shared.ID, assets *shared.DataScope) (*postureapp.View, error) {
	f.tenant, f.assets = tenantID, assets
	return f.view, nil
}

func TestPostureWidget(t *testing.T) {
	tenant := shared.NewID()
	scope := dashboard.ReadScope{TenantID: tenant, Assets: &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}}

	var v WidgetValue
	if err := (&Service{}).postureMetric(context.Background(), &v, scope); err != nil || v.State != StateNotMeasured {
		t.Fatalf("unwired: %v %+v", err, v)
	}

	f := &fakePosture{view: &postureapp.View{State: &posture.State{}}}
	s := &Service{posture: f}
	v = WidgetValue{}
	if err := s.postureMetric(context.Background(), &v, scope); err != nil || v.State != StateBuilding || v.Reason != ReasonPostureBuilding {
		t.Fatalf("building: %+v", v)
	}
	if f.tenant != tenant || f.assets != scope.Assets {
		t.Fatal("the widget must read with the server-built scope")
	}

	now := time.Now()
	f.view = &postureapp.View{State: &posture.State{ComputedAt: &now}, Score: posture.Compute(posture.Sums{})}
	v = WidgetValue{}
	if _ = s.postureMetric(context.Background(), &v, scope); v.State != StateNotMeasured || v.Reason != ReasonNoSurface || v.Posture != nil {
		t.Fatalf("no surface: %+v", v)
	}

	sums := posture.Sums{Assets: 10, Points: [6]float64{10}, Issues: [6]int64{1}}
	f.view = &postureapp.View{State: &posture.State{ComputedAt: &now}, Score: posture.Compute(sums),
		Plan: posture.FixPlan(sums, []posture.Item{{AssetID: "a", Category: posture.CatVulnerabilities, Points: 10, Issues: 1}})}
	v = WidgetValue{}
	if err := s.postureMetric(context.Background(), &v, scope); err != nil || v.Posture == nil {
		t.Fatalf("ready: %v %+v", err, v)
	}
	p := v.Posture
	if p.Score != 88 || p.Grade != "B" || p.NextGrade != "A" || p.FixSteps != 1 || len(p.Categories) != posture.NumCategories || v.Drill != drillPosture {
		t.Fatalf("posture value = %+v", p)
	}
}

func TestPostureMetricNeedsAssetsRead(t *testing.T) {
	m, ok := dashboard.LookupMetric("surface.posture")
	if !ok || metricPermission(m).String() != "assets:read" || m.ShapeFor(nil) != dashboard.ShapePosture || !m.Current() {
		t.Fatalf("surface.posture catalog entry: %+v", m)
	}
}
