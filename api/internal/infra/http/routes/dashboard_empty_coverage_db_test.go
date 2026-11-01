package routes

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	causeMarkerProgram = "cause-program-only-asset"
	causeMarkerOther   = "cause-other-tenant-asset"
)

var emptyCoverageLayout = []any{
	metricWidget("w_cov", "coverage.discovery", nil),
	metricWidget("w_p01", "exposure.priority_open", nil),
	metricWidget("w_kev", "intel.kev_open", nil),
}

// newCoverageCauseEnv extends the widget fixture with coverage ledger rows:
// A1 (in memberA's scope) was never taken by a sensor (no_sensor), B1 timed
// out (target_unreachable), a third asset was never run, a fourth is
// covered. A program-only asset and another tenant's asset fail too and
// must never count.
func newCoverageCauseEnv(t *testing.T) *widgetEnv {
	t.Helper()
	e := newWidgetEnv(t)
	h := e.h
	ten := h.tenant.String()
	pair := func(tenant, asset, state, outcome, attempt, success string) {
		h.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, last_outcome, last_attempt_at, last_success_at)
			VALUES ($1, $2, 'vuln.nuclei', '', $3, $4, `+attempt+`, `+success+`)`, tenant, asset, state, outcome)
	}
	newAsset := func(tenant, name string, programOnly bool) string {
		id := shared.NewID().String()
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, program_only) VALUES ($1, $2, $3, 'domain', $4)`, id, tenant, name, programOnly)
		return id
	}
	pair(ten, h.assetA.String(), "failed", "not_dispatched", "now()", "NULL")
	pair(ten, h.assetB.String(), "failed", "timeout", "now()", "NULL")
	pair(ten, newAsset(ten, "cause-never-run", false), "due", "", "NULL", "NULL")
	pair(ten, newAsset(ten, "cause-covered", false), "covered", "success", "now()", "now()")
	pair(ten, newAsset(ten, causeMarkerProgram, true), "failed", "not_dispatched", "now()", "NULL")
	pair(e.otherTenant.String(), newAsset(e.otherTenant.String(), causeMarkerOther, false), "failed", "not_dispatched", "now()", "NULL")
	return e
}

// Discovery coverage says why: the uncovered assets by cause count only the
// viewer's scope, and each cause row equals the asset list it opens. A
// scope with no finding shows the findings figures as not measured (never
// a 0 or a met target), and the KEV count carries its population.
func TestDashboardCoverageCausesAndNoFindings_DB(t *testing.T) {
	e := newCoverageCauseEnv(t)
	h := e.h
	for _, tc := range []struct {
		name        string
		user        shared.ID
		admin       bool
		tracked     int64
		causes      map[string]float64
		hasFindings bool
	}{
		{"scoped member", h.memberA, false, 1, map[string]float64{"no_sensor": 1}, true},
		{"member without scope rows", h.memberFree, false, 0, nil, false},
		{"administrator", h.owner, true, 4, map[string]float64{"no_sensor": 1, "target_unreachable": 1, "never_run": 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := e.createPersonal(t, tc.user, tc.admin, emptyCoverageLayout)
			code, raw := e.call(tc.user, tc.admin, nil, http.MethodGet, "/api/v1/me/dashboards/"+id+"/data", nil)
			if code != http.StatusOK {
				t.Fatalf("data = %d %s", code, raw)
			}
			out := e.data(t, tc.user, tc.admin, nil, "/api/v1/me/dashboards/"+id+"/data")

			cov := byID(t, out, "w_cov")
			if tc.tracked == 0 {
				if cov.State != widgets.StateNotMeasured || cov.Reason != widgets.ReasonNoTrackedAssets {
					t.Fatalf("nothing tracked = %+v", cov)
				}
			} else {
				if cov.State != widgets.StateReady || cov.Ratio == nil || cov.Ratio.Den != tc.tracked {
					t.Fatalf("coverage = %+v", cov)
				}
				got := map[string]float64{}
				for _, r := range cov.Ratio.Causes {
					got[r.Key] = r.Value
					n := e.assetTotal(t, tc.user, tc.admin, strings.TrimPrefix(r.Drill, "/assets?"))
					if float64(n) != r.Value {
						t.Errorf("parity %s: widget %v, asset list %d (%s)", r.Key, r.Value, n, r.Drill)
					}
				}
				if len(got) != len(tc.causes) {
					t.Errorf("causes %v want %v", got, tc.causes)
				}
				for k, v := range tc.causes {
					if got[k] != v {
						t.Errorf("cause %s = %v want %v", k, got[k], v)
					}
				}
				// The uncovered share equals the sum of its causes.
				var sum float64
				for _, v := range got {
					sum += v
				}
				if int64(sum) != cov.Ratio.Den-cov.Ratio.Num {
					t.Errorf("causes sum %v, uncovered %d", sum, cov.Ratio.Den-cov.Ratio.Num)
				}
			}

			p01, kev := byID(t, out, "w_p01"), byID(t, out, "w_kev")
			if !tc.hasFindings {
				for _, w := range []widgets.WidgetValue{p01, kev} {
					if w.State != widgets.StateNotMeasured || w.Reason != widgets.ReasonNoFindings || w.Scalar != nil || w.TargetMet != nil {
						t.Errorf("no findings %s = %+v", w.ID, w)
					}
				}
				return
			}
			if kev.State != widgets.StateReady || kev.Scalar == nil || kev.Scalar.Of == nil {
				t.Fatalf("kev = %+v", kev)
			}
			// "N of M open": M equals the open findings list it opens.
			n := e.listTotal(t, tc.user, tc.admin, strings.TrimPrefix(kev.Scalar.OfDrill, "/findings?"))
			if int64(n) != *kev.Scalar.Of {
				t.Errorf("kev population %d, findings list %d (%s)", *kev.Scalar.Of, n, kev.Scalar.OfDrill)
			}
		})
	}
	// A cause filter on the asset list never shows another tenant's or a
	// program-only asset.
	code, raw := e.call(h.owner, true, nil, http.MethodGet, "/api/v1/assets?coverage_cause=no_sensor&program_assets=exclude", nil)
	if code != http.StatusOK {
		t.Fatalf("assets = %d %s", code, raw)
	}
	for _, m := range []string{causeMarkerProgram, causeMarkerOther} {
		if strings.Contains(raw, m) {
			t.Errorf("cause list shows %q", m)
		}
	}
}
