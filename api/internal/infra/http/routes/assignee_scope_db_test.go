package routes

// Being assigned grants view of the assigned item (docs/architecture/
// authorization-matrix.md, "Data scope"): the assignee of a finding sees that
// finding, never its asset or the asset's other findings; the assignee of a
// remediation campaign sees the campaign and the findings it tracks, but may
// not change it beyond their own scope. Unassigning removes the view at once;
// other members are unaffected. Requires DATABASE_URL.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAssigneeScope_FindingAssigneeSeesOnlyTheAssignedFinding(t *testing.T) {
	h := newDSHarness(t)
	sam := h.memberStrict // no group, no grant, owns nothing
	fa, fb := h.findingA.String(), h.findingB.String()
	status := func(user shared.ID, path string) int {
		t.Helper()
		s, _ := h.do(user, false, http.MethodGet, path, nil)
		return s
	}

	if s := status(sam, "/api/v1/findings/"+fb); s != http.StatusNotFound {
		t.Fatalf("before assignment GET finding = %d, want 404", s)
	}
	h.exec(`UPDATE findings SET assigned_to = $2 WHERE id = $1`, fb, sam.String())

	if s := status(sam, "/api/v1/findings/"+fb); s != http.StatusOK {
		t.Errorf("assignee GET assigned finding = %d, want 200", s)
	}
	// Never the asset or the asset's other findings.
	if s := status(sam, "/api/v1/assets/"+h.assetB.String()); s != http.StatusNotFound {
		t.Errorf("assignee GET the finding's asset = %d, want 404", s)
	}
	if s := status(sam, "/api/v1/findings/"+fa); s != http.StatusNotFound {
		t.Errorf("assignee GET an unassigned finding = %d, want 404", s)
	}
	code, body := h.do(sam, false, http.MethodGet, "/api/v1/findings/", nil)
	if code != http.StatusOK || !strings.Contains(body, fb) || strings.Contains(body, fa) {
		t.Errorf("assignee findings list = %d, want only the assigned finding (%.300s)", code, body)
	}
	// Other members are unaffected.
	if s := status(h.memberFree, "/api/v1/findings/"+fb); s != http.StatusNotFound {
		t.Errorf("another member GET = %d, want 404", s)
	}
	// An organization API key (no user) never matches an assignee.
	if s := status(shared.ID{}, "/api/v1/findings/"+fb); s != http.StatusNotFound {
		t.Errorf("organization key GET = %d, want 404", s)
	}

	// Unassigned: the view goes at once.
	h.exec(`UPDATE findings SET assigned_to = NULL WHERE id = $1`, fb)
	if s := status(sam, "/api/v1/findings/"+fb); s != http.StatusNotFound {
		t.Errorf("ex-assignee GET = %d, want 404", s)
	}
	code, body = h.do(sam, false, http.MethodGet, "/api/v1/findings/", nil)
	if code != http.StatusOK || strings.Contains(body, fb) {
		t.Errorf("ex-assignee findings list still has the finding (%.300s)", body)
	}
}

// The assignee check is tenant-scoped: a finding of another tenant assigned
// (by bad data) to a member never shows in that member's tenant.
func TestAssigneeScope_CrossTenant(t *testing.T) {
	h := newDSHarness(t)
	other, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "as-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'as-other.example', 'domain')`, otherAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, assigned_to)
		VALUES ($1::uuid, $2, $3, 'sast', 't', 'as other tenant', 'critical', $1::text, 'confirmed', $4)`,
		otherFinding.String(), other.String(), otherAsset.String(), h.memberStrict.String())
	if s, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/findings/"+otherFinding.String(), nil); s != http.StatusNotFound {
		t.Errorf("another tenant's finding assigned to the member = %d, want 404 (%.200s)", s, body)
	}
	if _, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/findings/", nil); strings.Contains(body, otherFinding.String()) {
		t.Errorf("findings list leaked another tenant's finding")
	}
}
