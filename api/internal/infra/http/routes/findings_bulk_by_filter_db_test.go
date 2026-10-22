package routes

// Bulk changes by filter over the real routes, services and a migrated
// database: the filter is recompiled in the caller's scope, the expected
// count guards the selection, false positive and acceptance are never bulk,
// a retried request replays its operation, the cap and the tenant budget
// hold, more than 1,000 findings run in the background, and an operation is
// readable by its creator only.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type bfOperation struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	Total     int    `json:"total"`
	Processed int    `json:"processed"`
	Succeeded int    `json:"succeeded"`
	Skipped   int    `json:"skipped"`
	Failed    int    `json:"failed"`
	Self      string `json:"self"`
}

type bfError struct {
	Code    string         `json:"code"`
	Details map[string]any `json:"details"`
}

func newBulkByFilterHarness(t *testing.T) *gsHarness {
	t.Helper()
	h := newGroupScopeHarness(t)
	db := &postgres.DB{DB: h.db}
	h.vuln.SetOperationStore(postgres.NewOperationRepository(db))
	h.vuln.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
	return h
}

func (h *gsHarness) bulkByFilter(t *testing.T, user shared.ID, admin bool, verb string, body map[string]any) (int, bfOperation, bfError, string) {
	t.Helper()
	path := map[string]string{"status": "status", "assign": "assignee"}[verb]
	status, raw := h.do(user, admin, http.MethodPost, "/api/v1/findings/bulk/by-filter/"+path, body)
	var ok struct {
		Operation bfOperation `json:"operation"`
	}
	var e bfError
	_ = json.Unmarshal([]byte(raw), &ok)
	_ = json.Unmarshal([]byte(raw), &e)
	return status, ok.Operation, e, raw
}

func (h *gsHarness) findingStatus(t *testing.T, id shared.ID) string {
	t.Helper()
	var st string
	if err := h.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id.String()).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestFindingsBulkByFilter_ScopeCountAndRules(t *testing.T) {
	h := newBulkByFilterHarness(t)
	h.exec(`UPDATE findings SET status = 'new' WHERE tenant_id = $1 AND source <> 'pentest'`, h.tenant.String())

	// Out of scope: memberA's filter for asset B1 selects nothing, so the
	// count the client claims is refused and nothing changes.
	status, _, e, raw := h.bulkByFilter(t, h.memberA, false, "status", map[string]any{
		"filter": map[string]any{"asset_id": h.assetB.String()}, "expected_count": 1, "status": "confirmed"})
	if status != http.StatusConflict || e.Code != "SELECTION_CHANGED" || e.Details["count"] != float64(0) {
		t.Fatalf("out-of-scope by filter = %d %s, want 409 SELECTION_CHANGED count 0", status, raw)
	}
	// The whole list as memberA: one finding (FA), not three.
	status, _, e, raw = h.bulkByFilter(t, h.memberA, false, "status", map[string]any{
		"filter": map[string]any{}, "expected_count": 3, "status": "confirmed"})
	if status != http.StatusConflict || e.Details["count"] != float64(1) {
		t.Fatalf("expected_count 3 for a member who sees 1 = %d %s, want 409 count 1", status, raw)
	}
	status, op, _, raw := h.bulkByFilter(t, h.memberA, false, "status", map[string]any{
		"filter": map[string]any{"severity": "high,critical"}, "expected_count": 1, "status": "confirmed",
		"idempotency_key": "k-1"})
	if status != http.StatusOK || op.Status != "succeeded" || op.Total != 1 || op.Succeeded != 1 || op.Kind != "findings_bulk_status" {
		t.Fatalf("in-scope by filter = %d %s", status, raw)
	}
	if h.findingStatus(t, h.findingA) != "confirmed" || h.findingStatus(t, h.findingB) != "new" || h.findingStatus(t, h.findingB2) != "new" {
		t.Fatal("a by-filter change reached outside memberA's scope, or missed FA")
	}

	// A retry with the same key replays the operation; another request with
	// the same key is refused.
	status, again, _, raw := h.bulkByFilter(t, h.memberA, false, "status", map[string]any{
		"filter": map[string]any{"severity": "high,critical"}, "expected_count": 1, "status": "confirmed",
		"idempotency_key": "k-1"})
	if status != http.StatusOK || again.ID != op.ID {
		t.Fatalf("replay = %d %s, want the first operation %s", status, raw, op.ID)
	}
	status, _, e, raw = h.bulkByFilter(t, h.memberA, false, "status", map[string]any{
		"filter": map[string]any{"severity": "critical"}, "expected_count": 1, "status": "confirmed",
		"idempotency_key": "k-1"})
	if status != http.StatusUnprocessableEntity || e.Code != "IDEMPOTENCY_KEY_REUSED" {
		t.Fatalf("key reuse with another request = %d %s", status, raw)
	}

	// Strict filters; selection only (no view, paging or sort).
	for _, f := range []map[string]any{{"severty": "high"}, {"view": shared.NewID().String()}, {"sort": "-created_at"}} {
		status, _, e, raw = h.bulkByFilter(t, h.owner, true, "status", map[string]any{
			"filter": f, "expected_count": 1, "status": "confirmed"})
		if status != http.StatusBadRequest || e.Code != "INVALID_FILTER" {
			t.Errorf("filter %v = %d %s, want 400 INVALID_FILTER", f, status, raw)
		}
	}
	// False positive, acceptance and duplicate are never bulk by filter.
	for _, st := range []string{"false_positive", "accepted", "duplicate"} {
		status, _, e, raw = h.bulkByFilter(t, h.owner, true, "status", map[string]any{
			"filter": map[string]any{}, "expected_count": 3, "status": st, "resolution": "noise"})
		if status != http.StatusBadRequest || e.Code != "BULK_NOT_ALLOWED" {
			t.Errorf("%s by filter = %d %s, want 400 BULK_NOT_ALLOWED", st, status, raw)
		}
	}
	// A closing change needs a note.
	status, _, e, raw = h.bulkByFilter(t, h.owner, true, "status", map[string]any{
		"filter": map[string]any{}, "expected_count": 3, "status": "resolved"})
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		t.Errorf("resolve without a note = %d %s", status, raw)
	}
	_ = e

	// Assign by filter as the owner: every critical finding the owner sees
	// (FB on B1), each with its own audit row, plus the summary rows.
	status, op, _, raw = h.bulkByFilter(t, h.owner, true, "assign", map[string]any{
		"filter": map[string]any{"severity": "critical"}, "expected_count": 1, "user_id": h.owner.String()})
	if status != http.StatusOK || op.Succeeded != 1 {
		t.Fatalf("assign by filter = %d %s", status, raw)
	}
	var assignee string
	if err := h.db.QueryRow(`SELECT COALESCE(assigned_to::text, '') FROM findings WHERE id = $1`, h.findingB.String()).Scan(&assignee); err != nil || assignee != h.owner.String() {
		t.Fatalf("FB assignee = %q, %v", assignee, err)
	}
	var summaries, perFinding int
	if err := h.db.QueryRow(`SELECT
		COUNT(*) FILTER (WHERE action = 'finding.bulk_updated' AND metadata->>'operation_id' = $2 AND metadata->>'by_filter' = 'true'),
		COUNT(*) FILTER (WHERE action = 'finding.assigned' AND resource_id = $3)
		FROM audit_logs WHERE tenant_id = $1`, h.tenant.String(), op.ID, h.findingB.String()).Scan(&summaries, &perFinding); err != nil {
		t.Fatal(err)
	}
	if summaries != 2 || perFinding != 1 {
		t.Errorf("audit: %d summary rows (want started + succeeded), %d per-finding rows (want 1)", summaries, perFinding)
	}

	// The operation is its creator's: memberA gets 404 for the owner's.
	if status, raw := h.do(h.owner, true, http.MethodGet, op.Self, nil); status != http.StatusOK || !strings.Contains(raw, op.ID) {
		t.Errorf("creator reads the operation = %d %s", status, raw)
	}
	if status, _ := h.do(h.memberA, false, http.MethodGet, op.Self, nil); status != http.StatusNotFound {
		t.Errorf("another member reads the owner's operation = %d, want 404", status)
	}
	if status, _ := h.do(h.owner, true, http.MethodGet, "/api/v1/operations/"+shared.NewID().String(), nil); status != http.StatusNotFound {
		t.Errorf("unknown operation = %d, want 404", status)
	}

	// One running operation per person; a stale one no longer blocks.
	h.exec(`INSERT INTO operations (tenant_id, created_by, kind, status, total) VALUES ($1, $2, 'findings_bulk_assign', 'running', 1)`,
		h.tenant.String(), h.memberA.String())
	status, _, e, raw = h.bulkByFilter(t, h.memberA, false, "assign", map[string]any{
		"filter": map[string]any{}, "expected_count": 1, "user_id": h.memberA.String()})
	if status != http.StatusConflict || e.Code != "OPERATION_RUNNING" {
		t.Errorf("second running operation = %d %s, want 409 OPERATION_RUNNING", status, raw)
	}
	h.exec(`UPDATE operations SET updated_at = now() - interval '1 hour' WHERE tenant_id = $1 AND created_by = $2 AND status = 'running'`,
		h.tenant.String(), h.memberA.String())
	if status, _, _, raw = h.bulkByFilter(t, h.memberA, false, "assign", map[string]any{
		"filter": map[string]any{}, "expected_count": 1, "user_id": h.memberA.String()}); status != http.StatusOK {
		t.Errorf("after the stale operation = %d %s, want 200", status, raw)
	}

	// The tenant's hourly budget is shared by every replica (it is in the
	// database): a spent budget refuses the next change.
	h.exec(`INSERT INTO operations (tenant_id, created_by, kind, status, total) VALUES ($1, $2, 'findings_bulk_status', 'succeeded', 19999)`,
		h.tenant.String(), h.owner.String())
	status, _, _, raw = h.bulkByFilter(t, h.owner, true, "status", map[string]any{
		"filter": map[string]any{}, "expected_count": 4, "status": "in_progress"}) // the owner sees FA, FB, FB2 and FP
	if status != http.StatusTooManyRequests {
		t.Errorf("over the hourly budget = %d %s, want 429", status, raw)
	}
}

func TestFindingsBulkByFilter_BackgroundAndCap(t *testing.T) {
	h := newBulkByFilterHarness(t)
	gen := func(n int, tool string) {
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			SELECT g.id, $1, $2, 'sast', $3, 'bulk gen', 'low', g.id::text, 'new'
			FROM (SELECT uuid_generate_v7() AS id FROM generate_series(1, $4)) g`,
			h.tenant.String(), h.assetA.String(), tool, n)
	}
	// More than 10,000 matching: refused before anything changes.
	gen(10001, "bf-cap")
	status, _, e, raw := h.bulkByFilter(t, h.owner, true, "status", map[string]any{
		"filter": map[string]any{"tool_name": "bf-cap"}, "expected_count": 10000, "status": "confirmed"})
	if status != http.StatusBadRequest || e.Code != "BULK_TOO_LARGE" {
		t.Fatalf("over the cap = %d %s, want 400 BULK_TOO_LARGE", status, raw)
	}

	// More than 1,000: 202 and an operation that finishes in the background.
	gen(1001, "bf-async")
	status, op, _, raw := h.bulkByFilter(t, h.owner, true, "status", map[string]any{
		"filter": map[string]any{"tool_name": "bf-async"}, "expected_count": 1001, "status": "confirmed"})
	if status != http.StatusAccepted || op.Status != "running" || op.Total != 1001 {
		t.Fatalf("1,001 by filter = %d %s, want 202 running", status, raw)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		_, raw = h.do(h.owner, true, http.MethodGet, op.Self, nil)
		var got bfOperation
		_ = json.Unmarshal([]byte(raw), &got)
		if got.Status != "running" {
			if got.Status != "succeeded" || got.Processed != 1001 || got.Succeeded != 1001 {
				t.Fatalf("background operation = %s", raw)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background operation still running: %s", raw)
		}
		time.Sleep(200 * time.Millisecond)
	}
	var confirmed int
	if err := h.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND tool_name = 'bf-async' AND status = 'confirmed'`,
		h.tenant.String()).Scan(&confirmed); err != nil || confirmed != 1001 {
		t.Fatalf("confirmed = %d, %v; want 1001", confirmed, err)
	}
}
