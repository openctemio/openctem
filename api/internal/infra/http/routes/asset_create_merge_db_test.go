package routes

// POST /api/v1/assets with the name (or address) of an asset that already
// exists merges into that asset instead of creating a second one. The merge
// must respect the caller's data scope, must not change fields the create
// does not own, and must leave an audit trail.

import (
	"database/sql"
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
	if status != http.StatusConflict {
		t.Errorf("scoped create of an out-of-scope name = %d, want 409 (body %.300s)", status, body)
	}
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
	if status != http.StatusConflict || strings.Contains(body, b) {
		t.Errorf("scoped create correlated to an out-of-scope asset = %d (body %.300s), want 409 without its data", status, body)
	}
	if crit, _, updated := h.assetState(b); crit != "high" || updated != beforeUpdated {
		t.Errorf("IP-correlated out-of-scope asset changed: criticality %s updated %s->%s", crit, beforeUpdated, updated)
	}
}

// A merge the caller may make never rewrites the existing criticality, and
// is audited.
func TestAssetCreate_MergeKeepsCriticalityAndIsAudited(t *testing.T) {
	h := newDSHarness(t)
	a := h.assetA.String()

	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"member in scope", h.memberA, false}, {"owner", h.owner, true}} {
		status, body := h.do(who.user, who.admin, http.MethodPost, "/api/v1/assets/", map[string]any{
			"name": dsMarkerAssetA, "type": "domain", "criticality": "low", "description": "seen again",
		})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("%s re-create of an in-scope name = %d (body %.300s)", who.name, status, body)
		}
		if !strings.Contains(body, a) {
			t.Errorf("%s merge response does not return the existing asset (body %.300s)", who.name, body)
		}
		if crit, desc, _ := h.assetState(a); crit != "high" || desc != "seen again" {
			t.Errorf("%s merge: criticality=%s (want unchanged high) description=%q (want the sent one)", who.name, crit, desc)
		}
	}
	if n := h.auditCount("asset.create_merged", a); n != 2 {
		t.Errorf("merges audited %d times, want 2", n)
	}
}

// The repository create (POST /assets/repository) merges the same way.
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
