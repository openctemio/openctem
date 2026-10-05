package routes

// Findings export (RFC-048) over the real routes: the export holds exactly
// the rows the caller can list (scope, pentest rule, filter), needs
// findings:export, neutralizes spreadsheet formulas and is audit-logged
// without filter values.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func (h *gsHarness) export(t *testing.T, c flCaller, method, query string, body any, perms string) (*http.Response, string) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+"/api/v1/findings/export?"+query, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", c.user.String())
	if c.admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	if perms != "" {
		req.Header.Set("X-Test-Perms", perms)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, string(out)
}

func csvIDs(t *testing.T, body string) []string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv: %v (%.200s)", err, body)
	}
	if len(rows) == 0 || rows[0][0] != "id" {
		t.Fatalf("csv header: %v", rows)
	}
	ids := make([]string, 0, len(rows)-1)
	for _, r := range rows[1:] {
		ids = append(ids, r[0])
	}
	return sorted(ids...)
}

func TestFindingsExport_ScopeFilterAndContract(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa, fb, fb2, fp := h.findingA.String(), h.findingB.String(), h.findingB2.String(), h.findingP.String()
	h.exec(`UPDATE findings SET title = '=HYPERLINK("http://evil.example","x")' WHERE id = $1`, fa)
	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	exportPerms := strings.Join(append(append([]string{}, dsMemberPerms...), permission.FindingsExport.String()), ",")

	for _, c := range []struct {
		caller flCaller
		query  string
		want   []string
	}{
		{admin, "", sorted(fa, fb, fb2, fp)},
		{admin, "severity=critical", sorted(fb)},
		{memberA, "", sorted(fa)},
		{memberA, "asset_id=" + h.assetB.String(), nil},
		{memberA, "source=pentest", nil},
	} {
		resp, body := h.export(t, c.caller, http.MethodGet, c.query, nil, exportPerms)
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
			t.Fatalf("%s export ?%s = %d %.200s", c.caller.name, c.query, resp.StatusCode, body)
		}
		if got := csvIDs(t, body); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s export ?%s ids = %v, want %v", c.caller.name, c.query, got, c.want)
		}
		if resp.Trailer.Get("X-Export-Truncated") != "false" {
			t.Errorf("trailer: %v", resp.Trailer)
		}
		// The export and the list agree (the count contract).
		if _, total, _ := h.listIDs(t, c.caller, c.query); int(total) != len(c.want) {
			t.Errorf("%s list total %d != export rows %d", c.caller.name, total, len(c.want))
		}
		if c.caller == memberA && (strings.Contains(body, dsMarkerAssetB) || strings.Contains(body, fb)) {
			t.Errorf("memberA export leaked out-of-scope data")
		}
	}

	// Formula neutralized.
	_, body := h.export(t, admin, http.MethodGet, "id="+fa, nil, "")
	if !strings.Contains(body, `'=HYPERLINK`) {
		t.Errorf("formula not neutralized: %s", body)
	}

	// POST with a FilterDocument; NDJSON.
	resp, body := h.export(t, memberA, http.MethodPost, "format=ndjson",
		map[string]any{"filter": map[string]any{"any": []any{
			map[string]any{"field": "severity", "op": "in", "value": []any{"critical"}},
			map[string]any{"field": "source", "op": "in", "value": []any{"sast"}},
		}}}, exportPerms)
	if resp.StatusCode != http.StatusOK || strings.Count(strings.TrimSpace(body), "\n") != 0 || !strings.Contains(body, fa) {
		t.Errorf("ndjson export: %d %.300s", resp.StatusCode, body)
	}

	// Permission: a member without findings:export is refused.
	if resp, _ := h.export(t, memberA, http.MethodGet, "", nil, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("export without findings:export = %d, want 403", resp.StatusCode)
	}
	// Bad filter / format.
	if resp, _ := h.export(t, admin, http.MethodGet, "severity=urgent", nil, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad filter = %d", resp.StatusCode)
	}
	if resp, _ := h.export(t, admin, http.MethodGet, "format=xlsx", nil, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad format = %d", resp.StatusCode)
	}

	// Audit: one row per export, with the filter shape and no values.
	var n int
	var meta string
	if err := h.db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(metadata::text), '') FROM audit_logs
		WHERE tenant_id = $1 AND action = 'data.exported' AND metadata->>'format' = 'csv' AND metadata::text LIKE '%severity:in%'`,
		h.tenant.String()).Scan(&n, &meta); err != nil {
		t.Fatal(err)
	}
	if n == 0 || strings.Contains(meta, "critical") {
		t.Errorf("audit rows = %d, metadata %s (must hold the shape, not the values)", n, meta)
	}
}
