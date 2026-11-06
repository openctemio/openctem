package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type findingViewBody struct {
	Parts map[string]struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	} `json:"parts"`
}

func decodeFindingView(t *testing.T, body string) findingViewBody {
	t.Helper()
	var v findingViewBody
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("view body: %v: %.300s", err, body)
	}
	return v
}

// GET /findings/{id}/view answers each part through the real router with the
// caller's credentials (research/335): a part is exactly what the caller gets
// from that endpoint directly, and a finding the caller may not open, out of
// its data scope or in another tenant, yields that refusal alone.
func TestFindingView_PartsAreTheCallersOwnReads(t *testing.T) {
	h := newDSHarness(t)
	fa := "/api/v1/findings/" + h.findingA.String()

	code, body := h.do(h.memberA, false, http.MethodGet, fa+"/view", nil)
	if code != http.StatusOK {
		t.Fatalf("view status %d: %s", code, body)
	}
	view := decodeFindingView(t, body)
	for _, part := range []string{fa, fa + "/comments", fa + "/identity"} {
		p, ok := view.Parts[part]
		if !ok {
			t.Fatalf("part %s missing", part)
		}
		directCode, direct := h.do(h.memberA, false, http.MethodGet, part, nil)
		if p.Status != directCode {
			t.Errorf("%s: view status %d, direct %d", part, p.Status, directCode)
		}
		if directCode == http.StatusOK && strings.TrimSpace(string(p.Body)) != strings.TrimSpace(direct) {
			t.Errorf("%s: view part differs from the direct read:\n part   %.300s\n direct %.300s", part, p.Body, direct)
		}
	}
	if strings.Contains(body, "dsB-SECRET") || strings.Contains(body, dsMarkerAssetB) {
		t.Errorf("view of an in-scope finding leaked out-of-scope data: %.400s", body)
	}
}

func TestFindingView_OutOfScopeFindingIsRefusedLikeTheFinding(t *testing.T) {
	h := newDSHarness(t)
	fb := "/api/v1/findings/" + h.findingB.String()

	// The data-scope guard covers /findings/{id}/**, so the view of a finding
	// outside the member's scope is refused before any part runs, with the
	// same answer as the finding itself.
	code, body := h.do(h.memberA, false, http.MethodGet, fb+"/view", nil)
	directCode, direct := h.do(h.memberA, false, http.MethodGet, fb, nil)
	if code != http.StatusNotFound || code != directCode || strings.TrimSpace(body) != strings.TrimSpace(direct) {
		t.Fatalf("view %d %s, direct %d %s: want the same 404", code, body, directCode, direct)
	}
	if strings.Contains(body, "dsB-SECRET") || strings.Contains(body, dsMarkerAssetB) {
		t.Errorf("out-of-scope view leaked: %.400s", body)
	}
}

func TestFindingView_AnotherTenantsFindingYieldsOnlyItsRefusal(t *testing.T) {
	h := newDSHarness(t)
	other, asset, finding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "dsx-"+other.String())
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'dsx-foreign.example.com', 'domain', 'public', 'high')`,
		asset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 'ds-tool', 'dsX-FOREIGN finding', 'high', $1::text, 'confirmed')`,
		finding.String(), other.String(), asset.String())
	h.exec(`INSERT INTO finding_comments (finding_id, author_id, content, tenant_id) VALUES ($1, $2, 'dsX-FOREIGN comment', $3)`,
		finding.String(), h.owner.String(), other.String())

	f := "/api/v1/findings/" + finding.String()
	// The organization's owner is never narrowed by data scope, and still
	// gets nothing of another organization's finding.
	code, body := h.do(h.owner, true, http.MethodGet, f+"/view", nil)
	if code != http.StatusOK {
		t.Fatalf("view status %d: %s", code, body)
	}
	view := decodeFindingView(t, body)
	if len(view.Parts) != 1 || view.Parts[f].Status != http.StatusNotFound {
		t.Fatalf("foreign finding: parts %+v, want only the finding's 404", view.Parts)
	}
	if strings.Contains(body, "dsX-FOREIGN") || strings.Contains(body, "dsx-foreign") {
		t.Errorf("cross-tenant view leaked: %.400s", body)
	}
}

// The view itself needs findings:read; a caller without it gets the route's
// refusal and no part is answered.
func TestFindingView_NeedsFindingsRead(t *testing.T) {
	h := newDSHarness(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		h.srv.URL+"/api/v1/findings/"+h.findingA.String()+"/view", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", h.memberA.String())
	req.Header.Set("X-Test-Perms", "assets:read")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
}
