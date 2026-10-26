package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/attack"
	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	ctemMarkerProgram = "ctem-program-only-crown-jewel"
	ctemMarkerOther   = "ctem-other-tenant-crown-jewel"
)

var ctemLayout = []any{
	metricWidget("w_loop", "ctem.loop", nil),
	metricWidget("w_cj", "crown_jewels.exposed", nil),
	metricWidget("w_paths", "attack_paths.to_crown_jewels", map[string]any{"limit": 5}),
	metricWidget("w_cov", "coverage.discovery", nil),
}

// newCTEMEnv extends the pentest fixture: A1 and B1 are crown jewels (A1 in
// memberA's scope), a program-only crown jewel with a P0 finding, a crown
// jewel of another tenant, the coverage ledger (A1 covered, B1 tracked
// without a successful run), validation evidence on A1's ordinary finding.
func newCTEMEnv(t *testing.T) *widgetEnv {
	t.Helper()
	e := newWidgetEnv(t)
	h := e.h
	ten := h.tenant.String()
	h.exec(`UPDATE assets SET is_crown_jewel = TRUE WHERE tenant_id = $1 AND id IN ($2, $3)`, ten, h.assetA.String(), h.assetB.String())
	h.exec(`UPDATE findings SET priority_class = 'P1' WHERE tenant_id = $1 AND id = $2`, ten, h.findingB.String())

	prog := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, is_crown_jewel, program_only)
		VALUES ($1, $2, $3, 'domain', 'public', 'high', TRUE, TRUE)`, prog.String(), ten, ctemMarkerProgram)
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, priority_class)
		VALUES ($1::uuid, $2, $3, 'sast', 'x', 'prog', 'critical', $1::text, 'confirmed', 'P0')`, shared.NewID().String(), ten, prog.String())
	h.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, last_success_at)
		VALUES ($1, $2, 'web.http_probe', '', 'covered', now() - interval '1 day')`, ten, prog.String())

	other := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, is_crown_jewel)
		VALUES ($1, $2, $3, 'domain', 'public', 'high', TRUE)`, other.String(), e.otherTenant.String(), ctemMarkerOther)
	h.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, last_success_at)
		VALUES ($1, $2, 'web.http_probe', '', 'covered', now())`, e.otherTenant.String(), other.String())

	h.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, last_success_at)
		VALUES ($1, $2, 'web.http_probe', '', 'covered', now() - interval '2 days'),
		       ($1, $3, 'web.http_probe', '', 'failed', NULL),
		       ($1, $3, 'network_va.connector', '', 'covered', now() - interval '90 days')`, ten, h.assetA.String(), h.assetB.String())
	h.exec(`INSERT INTO validation_evidence (tenant_id, finding_id, executor_kind, outcome)
		SELECT tenant_id, id, 'manual', 'detected' FROM findings WHERE tenant_id = $1 AND rule_id = $2`, ten, ptSca)

	db := &postgres.DB{DB: h.db}
	surface := attack.NewSurfaceService(postgres.NewAssetRepository(db), postgres.NewAssetRelationshipRepository(db), logger.NewNop())
	surface.SetFindingRiskCounter(postgres.NewFindingRepository(db))
	e.svc.SetAttackPaths(surface)

	facts := postgres.NewDashboardFactsRepository(db)
	for _, tid := range []shared.ID{h.tenant, e.otherTenant} {
		if _, err := facts.RebuildTenant(context.Background(), tid, 100); err != nil {
			t.Fatalf("build facts: %v", err)
		}
	}
	return e
}

// assetTotal is the asset list total for the viewer and query.
func (e *widgetEnv) assetTotal(t *testing.T, user shared.ID, admin bool, query string) int {
	t.Helper()
	code, body := e.call(user, admin, nil, http.MethodGet, "/api/v1/assets?per_page=1&"+query, nil)
	if code != http.StatusOK {
		t.Fatalf("assets %s = %d %s", query, code, body)
	}
	var out struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	return out.Total
}

// findingAssets is the number of distinct assets in the findings list.
func (e *widgetEnv) findingAssets(t *testing.T, user shared.ID, admin bool, query string) int {
	t.Helper()
	code, body := e.call(user, admin, nil, http.MethodGet, "/api/v1/findings?per_page=100&"+query, nil)
	if code != http.StatusOK {
		t.Fatalf("findings %s = %d %s", query, code, body)
	}
	var out struct {
		Data []struct {
			AssetID string `json:"asset_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	seen := map[string]bool{}
	for _, f := range out.Data {
		seen[f.AssetID] = true
	}
	return len(seen)
}

func stage(t *testing.T, w widgets.WidgetValue, key string) widgets.StageValue {
	t.Helper()
	if w.Stages == nil {
		t.Fatalf("no stages in %+v", w)
	}
	for _, s := range w.Stages.Stages {
		if s.Key == key {
			return s
		}
	}
	t.Fatalf("no stage %s", key)
	return widgets.StageValue{}
}

// The CTEM metrics count each viewer's own scope: crown jewels, the
// coverage ledger, validation and attack paths of assets outside it never
// count or show, program-only assets and other tenants never do, pentest
// findings count only for campaign members, and each figure equals the
// list it opens for the same viewer.
func TestDashboardCTEMWidgets_ScopeAndParity_DB(t *testing.T) {
	e := newCTEMEnv(t)
	h := e.h
	for _, tc := range []struct {
		name                  string
		user                  shared.ID
		admin                 bool
		designated, exposed   int64
		tracked, uncovered    int64
		open, validated       int64
		p0                    int64
		reachable             int64
		seesB                 bool
		validatedPctAtLeast50 bool
	}{
		// A1 only: the harness finding and the ordinary P0 finding are open.
		{"scoped non-member", h.memberA, false, 1, 1, 1, 0, 2, 1, 1, 1, false, true},
		// + the published pentest finding on A1.
		{"campaign tester", e.tester, false, 1, 1, 1, 0, 3, 1, 2, 1, false, false},
		{"member without scope rows", h.memberFree, false, 0, 0, 0, 0, 0, 0, 0, 0, false, false},
		// A1 and B1 (B1's finding is P1); never the program-only crown jewel.
		{"administrator", h.owner, true, 2, 2, 2, 1, 4, 1, 2, 2, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := e.call(tc.user, tc.admin, nil, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "CTEM", "layout": ctemLayout})
			if code != http.StatusCreated {
				t.Fatalf("create = %d %s", code, body)
			}
			var d struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal([]byte(body), &d)
			code, raw := e.call(tc.user, tc.admin, nil, http.MethodGet, "/api/v1/me/dashboards/"+d.ID+"/data", nil)
			if code != http.StatusOK {
				t.Fatalf("data = %d %s", code, raw)
			}
			for _, m := range []string{ctemMarkerProgram, ctemMarkerOther, ptDraft, ptReview, ptOther} {
				if strings.Contains(raw, m) {
					t.Errorf("CTEM widgets show %q", m)
				}
			}
			if strings.Contains(raw, dsMarkerAssetA) != (tc.designated > 0) {
				t.Errorf("A1 shown = %v, want %v", strings.Contains(raw, dsMarkerAssetA), tc.designated > 0)
			}
			var out dataResp
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatal(err)
			}
			loop := byID(t, out, "w_loop")
			if loop.State != widgets.StateReady {
				t.Fatalf("loop = %+v", loop)
			}

			scoping := stage(t, loop, widgets.StageScoping)
			if *scoping.Value != float64(tc.designated) || scoping.Detail.Value != tc.exposed {
				t.Errorf("scoping %v / %d, want %d / %d", *scoping.Value, scoping.Detail.Value, tc.designated, tc.exposed)
			}
			if got := e.assetTotal(t, tc.user, tc.admin, "is_crown_jewel=true&program_assets=exclude"); int64(got) != tc.designated {
				t.Errorf("parity designated: widget %d, asset list %d", tc.designated, got)
			}
			cj := byID(t, out, "w_cj")
			paths := byID(t, out, "w_paths")
			if tc.designated == 0 {
				// No crown jewel in scope: never a green 0.
				for _, w := range []widgets.WidgetValue{cj, paths} {
					if w.State != widgets.StateNotMeasured || w.Reason != widgets.ReasonNoCrownJewels || w.Scalar != nil || w.Paths != nil {
						t.Errorf("%s without crown jewels = %+v, want not measured", w.ID, w)
					}
				}
			} else if cj.Scalar == nil || cj.Scalar.Value != tc.exposed {
				t.Fatalf("crown jewels exposed = %+v, want %d", cj.Scalar, tc.exposed)
			}
			// Dashboards leave program-only assets out; the findings list
			// shows them to an administrator, so parity is checked where no
			// program-only finding is visible.
			wantList := tc.exposed
			if tc.admin {
				wantList++
			}
			// group is the findings page's grouping view, not a list
			// filter: the list refuses unknown parameters, so leave it out.
			q := withoutParam(strings.TrimPrefix(cj.Drill, "/findings?"), "group")
			if got := e.findingAssets(t, tc.user, tc.admin, q); int64(got) != wantList {
				t.Errorf("parity exposed: widget %d, distinct assets in %s = %d", tc.exposed, cj.Drill, got)
			}

			disc := stage(t, loop, widgets.StageDiscovery)
			if tc.tracked == 0 {
				if disc.State != widgets.StageNotMeasured || disc.Value != nil {
					t.Errorf("discovery without tracked assets = %+v", disc)
				}
			} else {
				if disc.Detail == nil || disc.Detail.Value != tc.uncovered {
					t.Errorf("discovery uncovered = %+v, want %d", disc.Detail, tc.uncovered)
				}
				want := float64(tc.tracked-tc.uncovered) * 100 / float64(tc.tracked)
				if *disc.Value != want {
					t.Errorf("discovery %v, want %v", *disc.Value, want)
				}
			}
			if got := e.assetTotal(t, tc.user, tc.admin, "coverage=uncovered&program_assets=exclude"); int64(got) != tc.uncovered {
				t.Errorf("parity uncovered: widget %d, asset list %d", tc.uncovered, got)
			}

			// The catalog coverage figure is the same read as the loop's
			// Discovery stage, in the same scope; nothing tracked is not
			// measured, never 0 %.
			cov := byID(t, out, "w_cov")
			if tc.tracked == 0 {
				if cov.State != widgets.StateNotMeasured || cov.Reason != widgets.ReasonNoTrackedAssets || (cov.Ratio != nil && cov.Ratio.ValuePct != nil) {
					t.Errorf("coverage without tracked assets = %+v", cov)
				}
			} else {
				if cov.State != widgets.StateReady || cov.Ratio == nil || cov.Ratio.Den != tc.tracked || cov.Ratio.Num != tc.tracked-tc.uncovered {
					t.Errorf("coverage = %+v, want %d of %d", cov.Ratio, tc.tracked-tc.uncovered, tc.tracked)
				}
				if cov.Drill != "/assets?coverage=uncovered&program_assets=exclude" {
					t.Errorf("coverage drill %s", cov.Drill)
				}
			}

			val := stage(t, loop, widgets.StageValidate)
			if tc.open == 0 {
				if val.State != widgets.StageNotMeasured {
					t.Errorf("validate with nothing open = %+v", val)
				}
			} else {
				want := float64(int(float64(tc.validated)*1000/float64(tc.open)+0.5)) / 10
				if val.Value == nil || *val.Value != want {
					t.Errorf("validate %v, want %v (%d of %d)", val.Value, want, tc.validated, tc.open)
				}
			}

			pr := stage(t, loop, widgets.StagePrioritize)
			if *pr.Value != float64(tc.p0) {
				t.Errorf("P0 %v, want %d", *pr.Value, tc.p0)
			}
			if got := e.listTotal(t, tc.user, tc.admin, strings.TrimPrefix(pr.Drill, "/findings?")); int64(got) != tc.p0 && !tc.admin {
				t.Errorf("parity P0: widget %d, list %d", tc.p0, got)
			}

			if tc.designated == 0 {
				return
			}
			if paths.Paths == nil || paths.Paths.Reachable != tc.reachable || paths.Paths.Designated != tc.designated {
				t.Fatalf("paths = %+v, want reachable %d", paths.Paths, tc.reachable)
			}
			sawB := false
			for _, r := range paths.Paths.Rows {
				if r.AssetID == h.assetB.String() {
					sawB = true
				}
			}
			if sawB != tc.seesB {
				t.Errorf("attack paths show B1 = %v, want %v", sawB, tc.seesB)
			}
		})
	}
}

// The asset list's coverage filter is tenant-scoped and refuses values
// outside covered / uncovered.
func TestAssetListCoverageFilter_DB(t *testing.T) {
	e := newCTEMEnv(t)
	h := e.h
	if got := e.assetTotal(t, h.owner, true, "coverage=covered&program_assets=exclude"); got != 1 {
		t.Errorf("covered = %d, want 1 (A1; the other tenant's covered asset never counts)", got)
	}
	if code, _ := e.call(h.owner, true, nil, http.MethodGet, "/api/v1/assets?coverage=everything", nil); code != http.StatusBadRequest && code != http.StatusUnprocessableEntity {
		t.Errorf("unknown coverage value = %d, want a validation error", code)
	}
}

// withoutParam drops one parameter from a query string.
func withoutParam(query, name string) string {
	v, err := url.ParseQuery(query)
	if err != nil {
		return query
	}
	v.Del(name)
	return v.Encode()
}

// An asset is covered only when every capability that applies to it
// succeeded in the window: a working HTTP probe never hides a failed or
// paused vulnerability check. Scope-blocked rows and the platform's DNS
// checks are not part of the requirement.
func TestAssetListCoverage_EveryApplicableCapability_DB(t *testing.T) {
	e := newCTEMEnv(t)
	h := e.h
	ten := h.tenant.String()
	before := e.assetTotal(t, h.owner, true, "coverage=uncovered&program_assets=exclude")

	mixed, full, paused := shared.NewID(), shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{mixed, full, paused} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality)
			VALUES ($1, $2, $3, 'domain', 'public', 'high')`, id.String(), ten, "cov-"+id.String()+".example.com")
	}
	h.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, last_success_at) VALUES
		($1, $2, 'web.http_probe', '', 'covered', now()),
		($1, $2, 'vuln.templates', '', 'failed', NULL),
		($1, $3, 'web.http_probe', '', 'covered', now()),
		($1, $3, 'vuln.templates', '', 'covered', now()),
		($1, $3, 'port.scan', '', 'blocked', NULL),
		($1, $3, 'dns.email', '', 'failed', NULL),
		($1, $4, 'web.http_probe', '', 'covered', now()),
		($1, $4, 'vuln.templates', '', 'paused', now() - interval '400 days')`,
		ten, mixed.String(), full.String(), paused.String())

	if got := e.assetTotal(t, h.owner, true, "coverage=covered&program_assets=exclude"); got != 2 {
		t.Errorf("covered = %d, want 2 (A1 and the asset whose every applicable check succeeded)", got)
	}
	if got := e.assetTotal(t, h.owner, true, "coverage=uncovered&program_assets=exclude"); got != before+2 {
		t.Errorf("uncovered = %d, want %d (the failed and the paused vulnerability check are gaps)", got, before+2)
	}
}
