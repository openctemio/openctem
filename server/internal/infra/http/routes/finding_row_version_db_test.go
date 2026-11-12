package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Optimistic concurrency on finding writes over the real routes
// (docs/architecture/finding-row-version.md): a write that names the
// row_version it saw (If-Match) lands only while the finding is still at that
// version, and is otherwise refused with 409 FINDING_CHANGED. Another
// tenant's finding and an out-of-scope finding answer 404 with or without
// the header, never 409. Requires DATABASE_URL.

func (h *dsHarness) doIfMatch(user shared.ID, isAdmin bool, method, path, ifMatch string, body any) (int, map[string]any) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth := "Test " + user.String()
	if isAdmin {
		req.Header.Set("X-Test-Admin", "1")
		auth += " admin"
	}
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("Authorization", auth)
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func rowVersionOf(t *testing.T, body map[string]any) string {
	t.Helper()
	if data, ok := body["data"].(map[string]any); ok {
		body = data
	}
	v, ok := body["row_version"].(float64)
	if !ok {
		t.Fatalf("response has no row_version: %v", body)
	}
	b, _ := json.Marshal(int64(v))
	return `"` + string(b) + `"`
}

func TestFindingWrite_IfMatchRefusesStaleVersion(t *testing.T) {
	h := newDSHarness(t)
	path := "/api/v1/findings/" + h.findingA.String()

	status, got := h.doIfMatch(h.owner, true, http.MethodGet, path, "", nil)
	if status != http.StatusOK {
		t.Fatalf("GET finding: %d %v", status, got)
	}
	seen := rowVersionOf(t, got)

	status, got = h.doIfMatch(h.owner, true, http.MethodPut, path+"/tags", seen, map[string]any{"tags": []string{"first"}})
	if status != http.StatusOK {
		t.Fatalf("write on the version seen: %d %v", status, got)
	}
	next := rowVersionOf(t, got)
	if next == seen {
		t.Errorf("row_version did not move on a write (%s)", next)
	}

	// The same stale version again: refused, nothing written.
	status, got = h.doIfMatch(h.owner, true, http.MethodPut, path+"/tags", seen, map[string]any{"tags": []string{"stale"}})
	if status != http.StatusConflict || got["code"] != "FINDING_CHANGED" {
		t.Fatalf("stale If-Match: got %d %v, want 409 FINDING_CHANGED", status, got)
	}
	if d, _ := got["details"].(map[string]any); d == nil || rowVersionOf(t, d) != next {
		t.Errorf("409 should name the current row_version %s, got %v", next, got["details"])
	}
	row := h.db.QueryRowContext(context.Background(), `SELECT COALESCE(array_to_string(tags, ','), '') FROM findings WHERE id = $1`, h.findingA.String())
	var joined string
	if err := row.Scan(&joined); err != nil {
		t.Fatalf("read tags: %v", err)
	}
	if joined != "first" {
		t.Errorf("tags = %q after the refused write, want first", joined)
	}

	// No header: the server writes on its own read.
	if status, got = h.doIfMatch(h.owner, true, http.MethodPut, path+"/tags", "", map[string]any{"tags": []string{"plain"}}); status != http.StatusOK {
		t.Errorf("write without If-Match: %d %v", status, got)
	}
	// A malformed header is a bad request.
	if status, _ = h.doIfMatch(h.owner, true, http.MethodPut, path+"/tags", `"abc"`, map[string]any{"tags": []string{"x"}}); status != http.StatusBadRequest {
		t.Errorf("malformed If-Match: %d, want 400", status)
	}
}

func TestFindingWrite_IfMatchOtherTenantAndOutOfScopeAre404(t *testing.T) {
	h := newDSHarness(t)

	// Another tenant's finding, at row_version 0.
	other, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "rv-"+other.String())
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'rv-other.example.com', 'domain')`,
		otherAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 'rv-tool', 'other tenant', 'high', $1::text, 'confirmed')`,
		otherFinding.String(), other.String(), otherAsset.String())

	for _, ifMatch := range []string{`"0"`, `"999"`, ""} {
		status, got := h.doIfMatch(h.owner, true, http.MethodPut, "/api/v1/findings/"+otherFinding.String()+"/tags", ifMatch,
			map[string]any{"tags": []string{"cross"}})
		if status != http.StatusNotFound {
			t.Errorf("other tenant's finding with If-Match %q: got %d %v, want 404", ifMatch, status, got)
		}
	}
	// Out of the member's data scope: 404, not 409, whatever the version.
	for _, ifMatch := range []string{`"0"`, `"999"`} {
		status, got := h.doIfMatch(h.memberA, false, http.MethodPut, "/api/v1/findings/"+h.findingB.String()+"/tags", ifMatch,
			map[string]any{"tags": []string{"scope"}})
		if status != http.StatusNotFound {
			t.Errorf("out-of-scope finding with If-Match %q: got %d %v, want 404", ifMatch, status, got)
		}
	}
	var otherTags, bTags string
	_ = h.db.QueryRowContext(context.Background(), `SELECT COALESCE(array_to_string(tags, ','), '') FROM findings WHERE id = $1`, otherFinding.String()).Scan(&otherTags)
	_ = h.db.QueryRowContext(context.Background(), `SELECT COALESCE(array_to_string(tags, ','), '') FROM findings WHERE id = $1`, h.findingB.String()).Scan(&bTags)
	if otherTags != "" || bTags != "" {
		t.Errorf("a refused write changed tags: other=%q B=%q", otherTags, bTags)
	}
}
