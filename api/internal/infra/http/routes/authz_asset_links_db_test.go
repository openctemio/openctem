package routes

// Objects that feed the risk of the assets they link (compensating controls,
// business services) are changed only by a caller who can act on every
// linked asset or finding.

import (
	"net/http"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAssetLinks_ControlUpdateDeleteTestNeedAllLinksInScope(t *testing.T) {
	h := newDSHarness(t)
	authz170Mount(t, h)
	perms := []string{permission.CompensatingControlsWrite.String(), permission.CompensatingControlsRead.String()}
	mk := func(asset, finding shared.ID) string {
		c := shared.NewID()
		h.exec(`INSERT INTO compensating_controls (id, tenant_id, name, control_type, status, reduction_factor)
			VALUES ($1, $2, $3, 'segmentation', 'active', 0.5)`, c.String(), h.tenant.String(), "c-"+c.String()[:8])
		h.exec(`INSERT INTO compensating_control_assets (control_id, asset_id) VALUES ($1, $2)`, c.String(), asset.String())
		if !finding.IsZero() {
			h.exec(`INSERT INTO compensating_control_findings (control_id, finding_id) VALUES ($1, $2)`, c.String(), finding.String())
		}
		return "/api/v1/compensating-controls/" + c.String()
	}
	upd := map[string]any{"name": "renamed", "control_type": "segmentation", "reduction_factor": 0.9,
		"expires_at": time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)}

	foreign := mk(h.assetB, shared.ID{})
	foreignFinding := mk(h.assetA, h.findingB)
	for name, base := range map[string]string{"asset": foreign, "finding": foreignFinding} {
		if st, _ := authz170Do(t, h, h.memberA, false, perms, http.MethodPut, base, upd); st != http.StatusForbidden {
			t.Errorf("%s link out of scope: PUT = %d, want 403", name, st)
		}
		if st, _ := authz170Do(t, h, h.memberA, false, perms, http.MethodPost, base+"/test", map[string]any{"test_result": "fail"}); st != http.StatusForbidden {
			t.Errorf("%s link out of scope: test = %d, want 403", name, st)
		}
		if st, _ := authz170Do(t, h, h.memberA, false, perms, http.MethodDelete, base, nil); st != http.StatusForbidden {
			t.Errorf("%s link out of scope: DELETE = %d, want 403", name, st)
		}
		if st, _ := authz170Do(t, h, h.owner, true, perms, http.MethodPut, base, upd); st != http.StatusOK {
			t.Errorf("%s link: admin PUT = %d, want 200", name, st)
		}
	}
	own := mk(h.assetA, shared.ID{})
	if st, _ := authz170Do(t, h, h.memberA, false, perms, http.MethodPut, own, upd); st != http.StatusOK {
		t.Errorf("in-scope control: PUT = %d, want 200", st)
	}
	if st, _ := authz170Do(t, h, h.memberA, false, perms, http.MethodPost, own+"/assets", map[string]any{"asset_ids": []string{"not-a-uuid"}}); st != http.StatusBadRequest {
		t.Errorf("bad asset id = %d, want 400", st)
	}
	if st, _ := authz170Do(t, h, h.memberA, false, perms, http.MethodPost, own+"/assets", map[string]any{"asset_ids": []string{h.assetA.String()}}); st != http.StatusNoContent {
		t.Errorf("in-scope link = %d, want 204", st)
	}
	if st, _ := authz170Do(t, h, h.memberA, false, perms, http.MethodDelete, own, nil); st != http.StatusNoContent {
		t.Errorf("in-scope control: DELETE = %d, want 204", st)
	}
}

func TestAssetLinks_BusinessServiceDeleteNeedsAllLinksInScope(t *testing.T) {
	h := newDSHarness(t)
	authz170Mount(t, h)
	perms := []string{permission.BusinessServicesRead.String(), permission.BusinessServicesWrite.String()}
	svc := shared.NewID()
	h.exec(`INSERT INTO business_services (id, tenant_id, name, criticality) VALUES ($1, $2, 'svc', 'low')`, svc.String(), h.tenant.String())
	h.exec(`INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1, $2, $3)`, h.tenant.String(), svc.String(), h.assetB.String())
	p := "/api/v1/business-services/" + svc.String()
	if st, _ := authz170Do(t, h, h.memberA, false, perms, http.MethodDelete, p, nil); st != http.StatusForbidden {
		t.Errorf("DELETE service linking out-of-scope asset = %d, want 403", st)
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM business_services WHERE id=$1`, svc.String()).Scan(&n)
	if n != 1 {
		t.Errorf("service was deleted by a caller who cannot act on its asset")
	}
	if st, _ := authz170Do(t, h, h.owner, true, perms, http.MethodGet, p, nil); st != http.StatusOK {
		t.Errorf("admin GET = %d", st)
	}
	if st, _ := authz170Do(t, h, h.owner, true, perms, http.MethodDelete, p, nil); st != http.StatusNoContent {
		t.Errorf("admin DELETE = %d, want 204", st)
	}
}
