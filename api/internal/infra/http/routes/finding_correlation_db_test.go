package routes

// The correlation endpoints over the real routes and a migrated database:
// the path finding is held to the caller's data scope by the route guard,
// the finding named in a confirm body is checked too, and another
// tenant's finding is a 404.

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestFindingCorrelationEndpoints_ScopeAndTenant(t *testing.T) {
	h := newDSHarness(t)
	// In scope (asset A): 200 with empty lists.
	if code, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/findings/"+h.findingA.String()+"/detections", nil); code != http.StatusOK {
		t.Fatalf("own finding: %d %s", code, body)
	}
	// Out of the member's scope (asset B): 404.
	if code, _ := h.do(h.memberA, false, http.MethodGet, "/api/v1/findings/"+h.findingB.String()+"/detections", nil); code != http.StatusNotFound {
		t.Fatalf("out-of-scope finding: %d, want 404", code)
	}
	// Confirm naming an out-of-scope finding in the body: 404, nothing changes.
	code, _ := h.do(h.memberA, false, http.MethodPost, "/api/v1/findings/"+h.findingA.String()+"/correlation/approve",
		map[string]string{"finding_id": h.findingB.String()})
	if code != http.StatusNotFound {
		t.Fatalf("confirm with an out-of-scope finding: %d, want 404", code)
	}
	// Release of a finding that is not a correlated duplicate: 409.
	if code, _ := h.do(h.memberA, false, http.MethodPost, "/api/v1/findings/"+h.findingA.String()+"/correlation/release", nil); code != http.StatusConflict {
		t.Fatalf("release of an uncorrelated finding: %d, want 409", code)
	}
	// Another tenant's finding: 404 even for this tenant's owner.
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "corr-"+other.String())
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	foreign := shared.NewID()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'dast', 't', 'm', 'high', $1::text, 'new')`, foreign.String(), other.String())
	if code, _ := h.do(h.owner, true, http.MethodGet, "/api/v1/findings/"+foreign.String()+"/detections", nil); code != http.StatusNotFound {
		t.Fatalf("another tenant's finding: %d, want 404", code)
	}
}
