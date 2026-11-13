package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// GET /dashboard/overview answers each part through the real router with the
// caller's credentials: a part's body is exactly what the caller gets from
// that endpoint directly, data scope included (research/81).
func TestDashboardOverview_PartsAreTheCallersOwnReads(t *testing.T) {
	h := newDSHarness(t)
	for _, c := range []struct {
		name    string
		isAdmin bool
	}{
		{"scoped member", false},
		{"owner", true},
	} {
		user := h.memberA
		if c.isAdmin {
			user = h.owner
		}
		code, overview := h.do(user, c.isAdmin, http.MethodGet, "/api/v1/dashboard/overview", nil)
		if code != http.StatusOK {
			t.Fatalf("%s: overview status %d: %s", c.name, code, overview)
		}
		var resp struct {
			Parts map[string]struct {
				Status int             `json:"status"`
				Body   json.RawMessage `json:"body"`
			} `json:"parts"`
		}
		if err := json.Unmarshal([]byte(overview), &resp); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		part, ok := resp.Parts["/api/v1/dashboard/stats"]
		if !ok || part.Status != http.StatusOK {
			t.Fatalf("%s: dashboard/stats part: %+v", c.name, part)
		}
		_, direct := h.do(user, c.isAdmin, http.MethodGet, "/api/v1/dashboard/stats", nil)
		if strings.TrimSpace(string(part.Body)) != strings.TrimSpace(direct) {
			t.Errorf("%s: overview part differs from the direct read:\n part   %s\n direct %s", c.name, part.Body, direct)
		}
		// Neither carries an out-of-scope marker for the member.
		if !c.isAdmin && strings.Contains(overview, dsMarkerAssetB) {
			t.Errorf("member overview leaked an out-of-scope row: %.400s", overview)
		}
	}
}
