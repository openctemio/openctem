package routes

// POST /api/v1/assets with the name (or address) of an asset that already
// exists is a 409 and changes nothing (owner decision O4). The response names
// the existing asset only when it is in the caller's data scope; otherwise it
// is the same generic conflict for every match. Another tenant's assets never
// match. POST /api/v1/assets/repository (the SCM import) still attaches SCM
// data to a matching repository asset the caller may see.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (h *dsHarness) assetState(id string) (criticality, description string, updatedAt string) {
	h.t.Helper()
	var desc sql.NullString
	if err := h.db.QueryRow(`SELECT criticality, description, updated_at::text FROM assets WHERE id = $1`, id).
		Scan(&criticality, &desc, &updatedAt); err != nil {
		h.t.Fatal(err)
	}
	return criticality, desc.String, updatedAt
}

func (h *dsHarness) auditCount(action, resourceID string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2 AND resource_id = $3`,
		h.tenant.String(), action, resourceID).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// A scoped member re-creating an asset outside their scope gets a plain
// conflict: the existing asset is neither changed nor returned.
func TestAssetCreate_MatchOutOfScope_ConflictWithoutTouchingIt(t *testing.T) {
	h := newDSHarness(t)
	b := h.assetB.String()
	beforeCrit, beforeDesc, beforeUpdated := h.assetState(b)

	status, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/assets/", map[string]any{
		"name": dsMarkerAssetB, "type": "domain", "criticality": "low", "description": "pwned",
	})
	h.wantConflict(status, body, "")
	if strings.Contains(body, b) || strings.Contains(body, `"criticality"`) {
		t.Errorf("conflict response revealed the existing asset: %.300s", body)
	}
	crit, desc, updated := h.assetState(b)
	if crit != beforeCrit || desc != beforeDesc || updated != beforeUpdated {
		t.Errorf("out-of-scope asset changed: criticality %s->%s description %q->%q updated %s->%s",
			beforeCrit, crit, beforeDesc, desc, beforeUpdated, updated)
	}

	// The same through address correlation: B1 carries an IP, A's member
	// creates an asset named by that IP.
	h.exec(`UPDATE assets SET properties = '{"ip": "10.77.0.9"}' WHERE id = $1`, b)
	_, _, beforeUpdated = h.assetState(b)
	status, body = h.do(h.memberA, false, http.MethodPost, "/api/v1/assets/", map[string]any{
		"name": "10.77.0.9", "type": "ip_address", "criticality": "low",
	})
	h.wantConflict(status, body, "")
	if strings.Contains(body, b) {
		t.Errorf("scoped create correlated to an out-of-scope asset revealed it: %.300s", body)
	}
	if crit, _, updated := h.assetState(b); crit != "high" || updated != beforeUpdated {
		t.Errorf("IP-correlated out-of-scope asset changed: criticality %s updated %s->%s", crit, beforeUpdated, updated)
	}
}

// conflictBody decodes a 409 body.
type conflictBody struct {
	Code    string `json:"code"`
	Details *struct {
		ExistingAssetID string `json:"existing_asset_id"`
	} `json:"details"`
}

func (h *dsHarness) wantConflict(status int, body, wantID string) {
	h.t.Helper()
	if status != http.StatusConflict {
		h.t.Fatalf("create = %d, want 409 (body %.300s)", status, body)
	}
	var c conflictBody
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		h.t.Fatalf("409 body: %v (%.300s)", err, body)
	}
	got := ""
	if c.Details != nil {
		got = c.Details.ExistingAssetID
	}
	if got != wantID {
		h.t.Errorf("409 existing_asset_id = %q, want %q (body %.300s)", got, wantID, body)
	}
}

// A create of an asset the caller may see is a 409 that names it, for an
// in-scope member, an owner and a member whose organization lets members
// without an access group see everything. Nothing is changed or audited as
// a merge.
func TestAssetCreate_DuplicateInScope_ConflictWithID(t *testing.T) {
	h := newDSHarness(t)
	a := h.assetA.String()
	_, _, beforeUpdated := h.assetState(a)

	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"member in scope", h.memberA, false}, {"owner", h.owner, true}, {"member without a group (sees everything)", h.memberFree, false}} {
		status, body := h.do(who.user, who.admin, http.MethodPost, "/api/v1/assets/", map[string]any{
			"name": dsMarkerAssetA, "type": "domain", "criticality": "low", "description": "seen again",
		})
		h.wantConflict(status, body, a)
		if strings.Contains(body, `"criticality"`) || strings.Contains(body, dsMarkerAssetA) {
			t.Errorf("%s: 409 carried asset data: %.300s", who.name, body)
		}
	}
	if crit, desc, updated := h.assetState(a); crit != "high" || desc != "" || updated != beforeUpdated {
		t.Errorf("duplicate create changed the asset: criticality %s description %q updated %s->%s", crit, desc, beforeUpdated, updated)
	}
	if n := h.auditCount("asset.create_merged", a); n != 0 {
		t.Errorf("duplicate create audited as a merge %d times", n)
	}
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND name = $2`, h.tenant.String(), dsMarkerAssetA).Scan(&n); err != nil || n != 1 {
		t.Errorf("assets named %s = %d (err %v), want 1", dsMarkerAssetA, n, err)
	}
}

// A strict organization's member without an access group sees nothing, so a
// duplicate of any asset is the generic conflict.
func TestAssetCreate_DuplicateStrictMemberWithoutGroup_ConflictWithoutID(t *testing.T) {
	h := newDSHarness(t)
	h.setPolicy("nothing")
	status, body := h.do(h.memberStrict, false, http.MethodPost, "/api/v1/assets/", map[string]any{
		"name": dsMarkerAssetA, "type": "domain", "criticality": "low",
	})
	h.wantConflict(status, body, "")
	if strings.Contains(body, h.assetA.String()) {
		t.Errorf("409 revealed the asset id: %.300s", body)
	}
}

// Another tenant's asset of the same name is invisible: the create succeeds
// as a new asset of the caller's tenant, and the response says nothing about
// the other one.
func TestAssetCreate_SameNameOtherTenant_CreatesWithoutLeak(t *testing.T) {
	h := newDSHarness(t)
	other, foreign := shared.NewID().String(), shared.NewID().String()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other, "dup-other-"+other)
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, description) VALUES ($1, $2, 'dup-x.example.com', 'domain', 'critical', 'foreign-secret')`,
		foreign, other)

	status, body := h.do(h.owner, true, http.MethodPost, "/api/v1/assets/", map[string]any{
		"name": "dup-x.example.com", "type": "domain", "criticality": "low",
	})
	if status != http.StatusCreated {
		t.Fatalf("create of a name only another tenant uses = %d, want 201 (body %.300s)", status, body)
	}
	if strings.Contains(body, foreign) || strings.Contains(body, "foreign-secret") || strings.Contains(body, other) {
		t.Errorf("response revealed the other tenant's asset: %.300s", body)
	}
	var crit, desc string
	if err := h.db.QueryRow(`SELECT criticality, description FROM assets WHERE id = $1`, foreign).Scan(&crit, &desc); err != nil ||
		crit != "critical" || desc != "foreign-secret" {
		t.Errorf("other tenant's asset changed: %s %q (err %v)", crit, desc, err)
	}
}

// The repository create (POST /assets/repository, the SCM import) still
// attaches SCM data to a matching asset the caller may see, and is a plain
// conflict for one outside their scope.
func TestAssetCreateRepository_MatchOutOfScope_ConflictAndKeepsCriticality(t *testing.T) {
	h := newDSHarness(t)
	repoB := shared.NewID().String()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'dsb-repo', 'repository', 'private', 'high')`,
		repoB, h.tenant.String())
	req := map[string]any{"name": "dsb-repo", "full_name": "acme/dsb-repo", "criticality": "low"}

	status, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/assets/repository", req)
	if status != http.StatusConflict || strings.Contains(body, repoB) {
		t.Errorf("scoped repository create of an out-of-scope name = %d (body %.300s), want 409 without its data", status, body)
	}
	if crit, _, _ := h.assetState(repoB); crit != "high" {
		t.Errorf("out-of-scope repository asset criticality changed to %s", crit)
	}

	status, body = h.do(h.owner, true, http.MethodPost, "/api/v1/assets/repository", req)
	if status != http.StatusCreated || !strings.Contains(body, repoB) {
		t.Fatalf("owner repository re-create = %d (body %.300s), want the existing asset", status, body)
	}
	if crit, _, _ := h.assetState(repoB); crit != "high" {
		t.Errorf("repository merge changed criticality to %s", crit)
	}
	if n := h.auditCount("asset.create_merged", repoB); n != 1 {
		t.Errorf("repository merge audited %d times, want 1", n)
	}
}
