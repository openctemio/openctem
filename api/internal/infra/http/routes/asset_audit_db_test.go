package routes

// Every human change to an asset leaves an audit entry: who, what, which
// asset and the names of the changed fields, never their values.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type assetAuditRow struct {
	Actor, ResourceID, ResourceName, Metadata, Changes string
}

func (h *dsHarness) auditRows(action string) []assetAuditRow {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT COALESCE(actor_id::text, ''), COALESCE(resource_id, ''), COALESCE(resource_name, ''),
		COALESCE(metadata::text, ''), COALESCE(changes::text, '')
		FROM audit_logs WHERE tenant_id = $1 AND action = $2 ORDER BY logged_at`, h.tenant.String(), action)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []assetAuditRow
	for rows.Next() {
		var r assetAuditRow
		if err := rows.Scan(&r.Actor, &r.ResourceID, &r.ResourceName, &r.Metadata, &r.Changes); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *dsHarness) wantAudit(action, resourceID string, mustContain ...string) assetAuditRow {
	h.t.Helper()
	for _, r := range h.auditRows(action) {
		if r.ResourceID != resourceID {
			continue
		}
		if r.Actor != h.owner.String() {
			h.t.Errorf("%s on %s: actor %q, want %s", action, resourceID, r.Actor, h.owner)
		}
		all := r.Metadata + r.Changes
		for _, m := range mustContain {
			if !strings.Contains(all, m) {
				h.t.Errorf("%s on %s: audit entry lacks %q (metadata %s changes %s)", action, resourceID, m, r.Metadata, r.Changes)
			}
		}
		return r
	}
	h.t.Errorf("no %s audit entry for %s", action, resourceID)
	return assetAuditRow{}
}

const auditSecret = "s3cr3t-token-value"

func TestAssetAudit_CreateUpdateStatusDelete(t *testing.T) {
	h := newDSHarness(t)

	// Create.
	status, body := h.do(h.owner, true, http.MethodPost, "/api/v1/assets/", map[string]any{
		"name": "audit-new.example.com", "type": "domain", "criticality": "medium",
	})
	if status != http.StatusCreated {
		t.Fatalf("create = %d (body %.200s)", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &created)
	h.wantAudit("asset.created", created.ID)

	// Update: field names recorded, values never (a property may carry a secret).
	status, body = h.do(h.owner, true, http.MethodPut, "/api/v1/assets/"+created.ID, map[string]any{
		"criticality": "critical", "description": "new-desc-value", "properties": map[string]any{"api_token": auditSecret},
	})
	if status != http.StatusOK {
		t.Fatalf("update = %d (body %.200s)", status, body)
	}
	r := h.wantAudit("asset.updated", created.ID, "criticality", "description", "properties.api_token")
	if strings.Contains(r.Metadata+r.Changes, auditSecret) || strings.Contains(r.Metadata+r.Changes, "new-desc-value") {
		t.Errorf("asset.updated recorded values: %s %s", r.Metadata, r.Changes)
	}

	// Crown-jewel flag.
	if status, body := h.do(h.owner, true, http.MethodPatch, "/api/v1/assets/"+created.ID+"/crown-jewel", map[string]any{
		"is_crown_jewel": true, "business_impact_score": 90,
	}); status != http.StatusOK {
		t.Fatalf("crown-jewel = %d (body %.200s)", status, body)
	}
	h.wantAudit("asset.crown_jewel_changed", created.ID, "is_crown_jewel")

	// Status transitions.
	for _, op := range []string{"deactivate", "activate", "archive"} {
		if status, body := h.do(h.owner, true, http.MethodPost, "/api/v1/assets/"+created.ID+"/"+op, nil); status != http.StatusOK {
			t.Fatalf("%s = %d (body %.200s)", op, status, body)
		}
	}
	statusChanges := 0
	for _, r := range h.auditRows("asset.status_changed") {
		if r.ResourceID == created.ID {
			statusChanges++
		}
	}
	if statusChanges != 3 {
		t.Errorf("status changes audited %d times, want 3", statusChanges)
	}

	// Bulk status.
	if status, body := h.do(h.owner, true, http.MethodPost, "/api/v1/assets/bulk/status", map[string]any{
		"asset_ids": []string{h.assetA.String(), h.assetB.String()}, "status": "inactive",
	}); status != http.StatusOK {
		t.Fatalf("bulk status = %d (body %.200s)", status, body)
	}
	bulk := h.auditRows("asset.bulk_status_changed")
	if len(bulk) != 1 || !strings.Contains(bulk[0].Metadata, h.assetA.String()) || !strings.Contains(bulk[0].Metadata, `"updated": 2`) &&
		!strings.Contains(bulk[0].Metadata, `"updated":2`) {
		t.Errorf("bulk status audit = %+v, want one entry naming the assets and the count", bulk)
	}

	// Delete.
	if status, body := h.do(h.owner, true, http.MethodDelete, "/api/v1/assets/"+created.ID, nil); status != http.StatusNoContent {
		t.Fatalf("delete = %d (body %.200s)", status, body)
	}
	if r := h.wantAudit("asset.deleted", created.ID); r.ResourceName != "audit-new.example.com" {
		t.Errorf("asset.deleted resource name = %q, want the deleted asset's name", r.ResourceName)
	}

	// A refused change writes nothing.
	before := len(h.auditRows("asset.updated"))
	_, _ = h.do(h.memberA, false, http.MethodPut, "/api/v1/assets/"+h.assetB.String(), map[string]any{"description": "x"})
	if after := len(h.auditRows("asset.updated")); after != before {
		t.Errorf("a refused update was audited")
	}
}

func TestAssetAudit_ImportCSV(t *testing.T) {
	h := newDSHarness(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.srv.URL+"/api/v1/assets/import/csv", strings.NewReader("name,type\naudit-import.example.com,domain\n"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/csv")
	req.Header.Set("X-Test-User", h.owner.String())
	req.Header.Set("X-Test-Admin", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("csv import = %d (body %.300s)", resp.StatusCode, b)
	}
	rows := h.auditRows("asset.imported")
	if len(rows) != 1 || !strings.Contains(rows[0].Metadata, "csv") || rows[0].Actor != h.owner.String() {
		t.Errorf("csv import audit = %+v, want one entry by the owner with the source", rows)
	}
}
