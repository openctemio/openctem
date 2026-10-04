package routes

// Safe asset delete (owner decision O3) over the real asset routes: a delete
// never destroys findings, and a deleted asset disappears from reads.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAssetDelete_RefusedWithFindingsThenSoftDeleted(t *testing.T) {
	h := newDSHarness(t)

	// A1 has a finding: refused with the archive hint, nothing changes.
	status, body := h.do(h.owner, true, http.MethodDelete, "/api/v1/assets/"+h.assetA.String(), nil)
	if status != http.StatusConflict {
		t.Fatalf("delete asset with findings = %d %s, want 409", status, body)
	}
	var refused struct {
		Code    string `json:"code"`
		Details struct {
			Reason       string `json:"reason"`
			FindingCount int    `json:"finding_count"`
			ArchivePath  string `json:"archive_path"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(body), &refused); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if refused.Details.Reason != "asset_has_findings" || refused.Details.FindingCount != 1 ||
		refused.Details.ArchivePath != "/api/v1/assets/"+h.assetA.String()+"/archive" {
		t.Fatalf("refusal details = %+v", refused.Details)
	}
	if st, _, _ := h.findingState(h.findingA); st == "" {
		t.Fatal("finding gone after a refused delete")
	}

	// A scoped member cannot delete an asset outside their scope.
	if status, _ := h.do(h.memberA, false, http.MethodDelete, "/api/v1/assets/"+h.assetB.String(), nil); status != http.StatusNotFound {
		t.Fatalf("scoped member deleting an out-of-scope asset = %d, want 404", status)
	}

	// An asset without findings is soft-deleted and gone from reads.
	empty := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'ds-empty.example.com', 'domain')`,
		empty.String(), h.tenant.String())
	if status, body := h.do(h.owner, true, http.MethodDelete, "/api/v1/assets/"+empty.String(), nil); status != http.StatusNoContent {
		t.Fatalf("delete asset without findings = %d %s, want 204", status, body)
	}
	if status, _ := h.do(h.owner, true, http.MethodGet, "/api/v1/assets/"+empty.String(), nil); status != http.StatusNotFound {
		t.Fatalf("GET deleted asset = %d, want 404", status)
	}
	if status, body := h.do(h.owner, true, http.MethodGet, "/api/v1/assets?per_page=100", nil); status != http.StatusOK || strings.Contains(body, empty.String()) {
		t.Fatalf("asset list after delete = %d, contains deleted asset: %v", status, strings.Contains(body, empty.String()))
	}
	if status, _ := h.do(h.owner, true, http.MethodDelete, "/api/v1/assets/"+empty.String(), nil); status != http.StatusNotFound {
		t.Fatalf("second delete = %d, want 404", status)
	}
	var deletedAt *string
	if err := h.db.QueryRow(`SELECT deleted_at::text FROM assets WHERE id = $1`, empty.String()).Scan(&deletedAt); err != nil || deletedAt == nil {
		t.Fatalf("row not soft-deleted: %v", err)
	}
}
