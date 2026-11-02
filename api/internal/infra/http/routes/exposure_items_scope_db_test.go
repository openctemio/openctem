package routes

// GET /attack-surface/exposures (and /stats, /assets): an exposure is visible
// exactly when its asset is. Another tenant's exposures, exposures of assets
// outside the caller's data scope and exposures without an asset (in no one's
// scope) never reach a restricted member, in the list, the counts, the
// by-asset form or a search; a member with no scope row sees nothing. The
// monitoring state and the primary marker come from the tenant's own scope
// entries.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	expItemOrphan = "exp-item-orphan-SECRET leak"
	expItemOther  = "exp-item-other-tenant SECRET"
)

func (h *dsHarness) seedExposureItems() {
	h.t.Helper()
	t := h.tenant.String()
	// An exposure without an asset (a leaked credential), in progress.
	orphan := shared.NewID()
	h.exec(`INSERT INTO exposure_events (id, tenant_id, event_type, title, fingerprint, source, severity, state)
		VALUES ($1::uuid, $2, 'credential_leaked', $3, $1::text, 'ds', 'critical', 'in_progress')`, orphan.String(), t, expItemOrphan)
	// A1 is a root domain of the organization: a permanent domain scope
	// entry on it makes it primary and monitored.
	h.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', $2, 'active')`,
		t, "*."+dsMarkerAssetA)

	// Another tenant with the same kind of data.
	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "exp-items-other-"+other.String())
	h.t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
		otherAsset.String(), other.String(), dsMarkerAssetA)
	h.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', $2, 'active')`,
		other.String(), "*."+dsMarkerAssetA)
	h.exec(`INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, title, fingerprint, source, severity, state)
		VALUES ($1::uuid, $2, $3, 'port_open', $4, $1::text, 'ds', 'high', 'active')`,
		shared.NewID().String(), other.String(), otherAsset.String(), expItemOther)
}

type expItemsList struct {
	Total int `json:"total"`
	Data  []struct {
		Title                string `json:"title"`
		AssetName            string `json:"asset_name"`
		AssetPrimary         bool   `json:"asset_primary"`
		AssetMonitoringState string `json:"asset_monitoring_state"`
		DisplayCategory      string `json:"display_category"`
		Severity             string `json:"severity"`
	} `json:"data"`
}

func decodeExpItems(t *testing.T, body string) expItemsList {
	t.Helper()
	var r expItemsList
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return r
}

func TestExposureItems_DataScopeAndTenant_DB(t *testing.T) {
	h := newDSHarness(t)
	h.seedExposureItems()
	const list = "/api/v1/attack-surface/exposures"

	// The scoped member sees only the exposure on A1.
	st, body := h.do(h.memberA, false, http.MethodGet, list, nil)
	if r := decodeExpItems(t, body); st != http.StatusOK || r.Total != 1 || len(r.Data) != 1 ||
		r.Data[0].AssetName != dsMarkerAssetA || strings.Contains(body, "SECRET") {
		t.Fatalf("memberA list = %d %s", st, body)
	}
	st, body = h.do(h.memberA, false, http.MethodGet, list+"/stats", nil)
	if st != http.StatusOK || !strings.Contains(body, `"total":1`) || !strings.Contains(body, `"exposed_ports":1`) ||
		strings.Contains(body, "credentials_data") {
		t.Fatalf("memberA stats = %d %s", st, body)
	}
	st, body = h.do(h.memberA, false, http.MethodGet, list+"/assets", nil)
	if st != http.StatusOK || !strings.Contains(body, `"total":1`) || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("memberA by asset = %d %s", st, body)
	}
	// Searches and filters on B's values find nothing for the member.
	for _, q := range []string{"?q=SECRET", "?asset_name_contains=dsb", "?asset_id=" + h.assetB.String(),
		"?category=credentials_data", "?state=in_progress"} {
		if st, body := h.do(h.memberA, false, http.MethodGet, list+q, nil); st != http.StatusOK ||
			decodeExpItems(t, body).Total != 0 || strings.Contains(body, "SECRET") {
			t.Errorf("memberA %s = %d %s, want empty", q, st, body)
		}
	}
	// A member with no scope row sees nothing.
	for _, p := range []string{list, list + "/assets"} {
		if st, body := h.do(h.memberStrict, false, http.MethodGet, p, nil); st != http.StatusOK || decodeExpItems(t, body).Total != 0 {
			t.Errorf("member without scope %s = %d %s", p, st, body)
		}
	}
	if st, body := h.do(h.memberStrict, false, http.MethodGet, list+"/stats", nil); st != http.StatusOK || !strings.Contains(body, `"total":0`) {
		t.Errorf("member without scope stats = %d %s", st, body)
	}

	// The owner sees the tenant's three exposures (most severe first), never
	// another tenant's.
	st, body = h.do(h.owner, true, http.MethodGet, list, nil)
	r := decodeExpItems(t, body)
	if st != http.StatusOK || r.Total != 3 || strings.Contains(body, expItemOther) || r.Data[0].Severity != "critical" {
		t.Fatalf("owner list = %d %s", st, body)
	}
	st, body = h.do(h.owner, true, http.MethodGet, list+"/stats", nil)
	if st != http.StatusOK || !strings.Contains(body, `"total":3`) || !strings.Contains(body, `"exposed_ports":2`) ||
		!strings.Contains(body, `"credentials_data":1`) || !strings.Contains(body, `"in_progress":1`) {
		t.Fatalf("owner stats = %d %s", st, body)
	}

	// Monitoring state and primary marker: A1 is a root domain in scope, B1
	// is covered by no scope entry (and unclassified assets are not scanned).
	st, body = h.do(h.owner, true, http.MethodGet, list+"?asset_monitoring_state=monitored&state=active,in_progress", nil)
	r = decodeExpItems(t, body)
	if st != http.StatusOK || r.Total != 1 || r.Data[0].AssetName != dsMarkerAssetA || !r.Data[0].AssetPrimary ||
		r.Data[0].AssetMonitoringState != "monitored" {
		t.Fatalf("owner monitored = %d %s", st, body)
	}
	st, body = h.do(h.owner, true, http.MethodGet, list+"?asset_monitoring_state=not_monitored", nil)
	r = decodeExpItems(t, body)
	if st != http.StatusOK || r.Total != 1 || r.Data[0].AssetName != dsMarkerAssetB || r.Data[0].AssetPrimary {
		t.Fatalf("owner not monitored = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, list+"?primary=true", nil); st != http.StatusOK || decodeExpItems(t, body).Total != 1 {
		t.Errorf("owner primary = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, list+"?category=exposed_ports&sort=asset_name", nil); st != http.StatusOK ||
		decodeExpItems(t, body).Total != 2 {
		t.Errorf("owner category = %d %s", st, body)
	}

	// Grouped by asset: the two assets with exposures, never the orphan.
	st, body = h.do(h.owner, true, http.MethodGet, list+"/assets", nil)
	if st != http.StatusOK || !strings.Contains(body, `"total":2`) || !strings.Contains(body, `"top_severity":"high"`) ||
		strings.Contains(body, expItemOrphan) || !strings.Contains(body, `"asset_primary":true`) {
		t.Fatalf("owner by asset = %d %s", st, body)
	}
	if st, _ := h.do(h.owner, true, http.MethodGet, list+"?nonsense=1", nil); st != http.StatusBadRequest {
		t.Errorf("unknown param = %d, want 400", st)
	}
	if st, _ := h.do(h.owner, true, http.MethodGet, list+"?asset_monitoring_state=bogus", nil); st != http.StatusBadRequest {
		t.Errorf("bad enum = %d, want 400", st)
	}
}
