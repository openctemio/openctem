package routes

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	surfaceMarkerProgram = "surface-program-only-cert"
	surfaceMarkerOther   = "surface-other-tenant-cert"
)

var surfaceLayout = []any{
	metricWidget("w_new", "surface.new_assets", map[string]any{"time": map[string]any{"range": "7d", "compare": "previous_period"}}),
	metricWidget("w_cert", "certificates.expiry", nil),
	metricWidget("w_acc", "exceptions.expiring", nil),
}

// newSurfaceEnv extends the widget fixture: A1 (in memberA's scope) is a
// certificate expiring in 10 days, B1 a certificate that expired; a
// program-only certificate and another tenant's certificate expire in 3 days.
// A1's finding is accepted until 3 days from now, B1's is accepted with no
// end given (the database caps every acceptance, so it lands in "later");
// another tenant has an accepted finding too.
func newSurfaceEnv(t *testing.T) *widgetEnv {
	t.Helper()
	e := newWidgetEnv(t)
	h := e.h
	ten := h.tenant.String()
	h.exec(`UPDATE assets SET asset_type = 'certificate', properties = jsonb_build_object('not_after', to_char((now() + interval '10 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
		WHERE tenant_id = $1 AND id = $2`, ten, h.assetA.String())
	h.exec(`UPDATE assets SET asset_type = 'certificate', properties = jsonb_build_object('not_after', to_char((now() - interval '2 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
		WHERE tenant_id = $1 AND id = $2`, ten, h.assetB.String())
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, program_only, properties)
		VALUES ($1, $2, $3, 'certificate', 'public', 'high', TRUE, jsonb_build_object('not_after', to_char((now() + interval '3 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')))`,
		shared.NewID().String(), ten, surfaceMarkerProgram)
	other := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, properties)
		VALUES ($1, $2, $3, 'certificate', 'public', 'high', jsonb_build_object('not_after', to_char((now() + interval '3 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')))`,
		other.String(), e.otherTenant.String(), surfaceMarkerOther)

	h.exec(`UPDATE findings SET status = 'accepted', acceptance_expires_at = now() + interval '3 days' WHERE tenant_id = $1 AND id = $2`, ten, h.findingA.String())
	h.exec(`UPDATE findings SET status = 'accepted', acceptance_expires_at = NULL WHERE tenant_id = $1 AND id = $2`, ten, h.findingB.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, acceptance_expires_at)
		VALUES ($1::uuid, $2, $3, 'sast', 'x', 'other accepted', 'high', $1::text, 'accepted', now() + interval '2 days')`,
		shared.NewID().String(), e.otherTenant.String(), other.String())
	return e
}

func category(t *testing.T, w widgets.WidgetValue) map[string]widgets.CategoryRow {
	t.Helper()
	if w.State != widgets.StateReady || w.Category == nil {
		t.Fatalf("%s = %s %s", w.ID, w.State, w.Reason)
	}
	out := map[string]widgets.CategoryRow{}
	for _, r := range w.Category.Rows {
		out[r.Key] = r
	}
	return out
}

// The attack surface and accepted-risk breakdowns count each viewer's own
// scope: assets and findings outside it, program-only assets and other
// tenants never count or show, and each band equals the list it opens for
// the same viewer.
func TestDashboardSurfaceWidgets_ScopeAndParity_DB(t *testing.T) {
	e := newSurfaceEnv(t)
	h := e.h
	for _, tc := range []struct {
		name              string
		user              shared.ID
		admin             bool
		certs             bool
		expired, within30 float64
		acc7, accLater    float64
	}{
		{"scoped member", h.memberA, false, true, 0, 1, 1, 0},
		{"member without scope rows", h.memberFree, false, false, 0, 0, 0, 0},
		{"administrator", h.owner, true, true, 1, 1, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := e.createPersonal(t, tc.user, tc.admin, surfaceLayout)
			code, raw := e.call(tc.user, tc.admin, nil, http.MethodGet, "/api/v1/me/dashboards/"+id+"/data", nil)
			if code != http.StatusOK {
				t.Fatalf("data = %d %s", code, raw)
			}
			for _, m := range []string{surfaceMarkerProgram, surfaceMarkerOther} {
				if strings.Contains(raw, m) {
					t.Errorf("surface widgets show %q", m)
				}
			}
			out := e.data(t, tc.user, tc.admin, nil, "/api/v1/me/dashboards/"+id+"/data")

			// Certificates: not measured with none in scope, else bands
			// that equal the asset list each opens.
			cert := byID(t, out, "w_cert")
			if !tc.certs {
				if cert.State != widgets.StateNotMeasured || cert.Reason != widgets.ReasonNoCertificates || cert.Category != nil {
					t.Fatalf("no certificates = %+v", cert)
				}
			} else {
				rows := category(t, cert)
				if rows[widgets.BandExpired].Value != tc.expired || rows[widgets.BandWithin30d].Value != tc.within30 || rows[widgets.BandWithin7d].Value != 0 {
					t.Errorf("certificate bands %+v", rows)
				}
				for k, r := range rows {
					if r.Value == 0 {
						continue
					}
					if got := e.assetTotal(t, tc.user, tc.admin, strings.TrimPrefix(r.Drill, "/assets?")); float64(got) != r.Value {
						t.Errorf("parity %s: widget %v, asset list %d (%s)", k, r.Value, got, r.Drill)
					}
				}
			}

			// New assets: every type row equals the asset list it opens.
			for k, r := range category(t, byID(t, out, "w_new")) {
				if r.Drill == "" {
					continue
				}
				if got := e.assetTotal(t, tc.user, tc.admin, strings.TrimPrefix(r.Drill, "/assets?")); float64(got) != r.Value {
					t.Errorf("parity new %s: widget %v, asset list %d (%s)", k, r.Value, got, r.Drill)
				}
			}

			// Accepted risks.
			acc := category(t, byID(t, out, "w_acc"))
			if acc[widgets.BandWithin7d].Value != tc.acc7 || acc[widgets.BandLater].Value != tc.accLater || acc[widgets.BandWithin30d].Value != 0 {
				t.Errorf("acceptance bands %+v", acc)
			}
			for k, r := range acc {
				if r.Value == 0 {
					continue
				}
				if got := e.listTotal(t, tc.user, tc.admin, strings.TrimPrefix(r.Drill, "/findings?")); float64(got) != r.Value {
					t.Errorf("parity accepted %s: widget %v, findings list %d (%s)", k, r.Value, got, r.Drill)
				}
			}
		})
	}
}
