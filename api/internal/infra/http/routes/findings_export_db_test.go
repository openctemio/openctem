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

// The export follows the list's sort, rejects unknown params, refuses an
// honest 403 naming the permission, holds one export per user across
// replicas (the slot is a database lock, not process memory), carries only
// the allowlisted fields and records the sort in the audit row.
func TestFindingsExport_SortStrictSlotAndAllowlist(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa, fb, fb2, fp := h.findingA.String(), h.findingB.String(), h.findingB2.String(), h.findingP.String()
	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	h.exec(`UPDATE findings SET cvss_score = 9.1, snippet = 'EVIDENCE-SNIPPET', metadata = '{"k":"META-VALUE"}' WHERE id = $1`, fb)
	h.exec(`UPDATE findings SET cvss_score = 7.0 WHERE id = $1`, fa)
	h.exec(`UPDATE findings SET cvss_score = 5.0 WHERE id = $1`, fb2)
	h.exec(`UPDATE findings SET cvss_score = 1.0 WHERE id = $1`, fp)

	// Sort: rows come in the requested order, the same as the list's.
	resp, body := h.export(t, admin, http.MethodGet, "sort=-cvss_score", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sorted export = %d %.200s", resp.StatusCode, body)
	}
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(rows)-1)
	for _, r := range rows[1:] {
		got = append(got, r[0])
	}
	if want := []string{fb, fa, fb2, fp}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sort=-cvss_score order = %v, want %v", got, want)
	}
	if resp.Header.Get("X-Export-Max-Rows") != "10000" {
		t.Errorf("X-Export-Max-Rows = %q", resp.Header.Get("X-Export-Max-Rows"))
	}

	// NDJSON: exactly the allowlisted keys, no evidence or metadata.
	resp, body = h.export(t, admin, http.MethodGet, "format=ndjson&id="+fb, nil, "")
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &row); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("ndjson: %d %v %.200s", resp.StatusCode, err, body)
	}
	if _, ok := row["snippet"]; ok || strings.Contains(body, "EVIDENCE-SNIPPET") || strings.Contains(body, "META-VALUE") {
		t.Errorf("ndjson row carries evidence or metadata: %s", body)
	}
	if _, ok := row["asset_name"]; !ok || len(row) != 40 {
		t.Errorf("ndjson keys (%d) = %v", len(row), row)
	}

	// Unknown param: 400 INVALID_FILTER, not a wider export.
	resp, body = h.export(t, admin, http.MethodGet, "severty=critical", nil, "")
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "INVALID_FILTER") || !strings.Contains(body, "severty") {
		t.Errorf("unknown param export = %d %s", resp.StatusCode, body)
	}

	// No findings:export: an honest 403 that names the permission (the web
	// explains it; there is no fallback that exports one page instead).
	resp, body = h.export(t, memberA, http.MethodGet, "", nil, strings.Join(dsMemberPerms, ","))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, permission.FindingsExport.String()) {
		t.Errorf("export without findings:export = %d %s", resp.StatusCode, body)
	}

	// One export per user across replicas: another connection (another API
	// instance) holding the user's slot makes this request 429.
	ctx := context.Background()
	conn, err := h.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('findings_export'), hashtext($1))`,
		h.tenant.String()+":"+h.owner.String()); err != nil {
		t.Fatal(err)
	}
	if resp, body := h.export(t, admin, http.MethodGet, "", nil, ""); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("export while the slot is held elsewhere = %d %.200s, want 429", resp.StatusCode, body)
	}
	_ = tx.Rollback()
	if resp, _ := h.export(t, admin, http.MethodGet, "", nil, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("export after the slot was released = %d", resp.StatusCode)
	}

	// The audit row records the sort.
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'data.exported'
		AND metadata->'sort' @> '["-cvss_score"]'::jsonb`, h.tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("audit rows with the sort = %d, want 1", n)
	}
}
