package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Research 458 B2, B6, B7, B8: a cycle's writes never fail silently.

func openCycleDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed handler test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return raw
}

func cycleBodyRequest(method, path, tenantID, cycleID string, body any) *http.Request {
	req := cycleRequest(method, path, tenantID, cycleID)
	if body != nil {
		b, _ := json.Marshal(body)
		req.Body = ioNopCloser(bytes.NewReader(b))
		req.ContentLength = int64(len(b))
	}
	return req
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func ioNopCloser(r *bytes.Reader) nopCloser { return nopCloser{r} }

// A cycle created without a charter stores {} (never JSON null), so the
// scope refinement notes can be written once it is in review; the
// description is kept on create, and an update that omits it keeps it.
func TestCTEMCycleHandler_CharterlessCycleTakesNotesAndKeepsDescription(t *testing.T) {
	db := openCycleDB(t)
	ctx := context.Background()
	tenantID := seedHandlerTenant(ctx, t, db)
	h := NewCTEMCycleHandler(db, nil, logger.NewNop())

	w := httptest.NewRecorder()
	h.Create(w, cycleBodyRequest(http.MethodPost, "/api/v1/ctem-cycles", tenantID, "",
		map[string]any{"name": "Q4", "description": "  External surface of the payment service  "}))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body.String())
	}
	var created CTEMCycleResponse
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.Description != "External surface of the payment service" {
		t.Fatalf("description = %q", created.Description)
	}
	var kind string
	if err := db.QueryRowContext(ctx, `SELECT jsonb_typeof(charter) FROM ctem_cycles WHERE id = $1`, created.ID).Scan(&kind); err != nil || kind != "object" {
		t.Fatalf("stored charter type = %q (%v), want object", kind, err)
	}

	// The charter editor's update sends no description: it is kept.
	w = httptest.NewRecorder()
	h.Update(w, cycleBodyRequest(http.MethodPut, "/api/v1/ctem-cycles/"+created.ID, tenantID, created.ID,
		map[string]any{"name": "Q4 renamed"}))
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d %s", w.Code, w.Body.String())
	}
	var updated CTEMCycleResponse
	_ = json.Unmarshal(w.Body.Bytes(), &updated)
	if updated.Description != "External surface of the payment service" || updated.Name != "Q4 renamed" {
		t.Fatalf("after update = %q / %q", updated.Name, updated.Description)
	}

	// A too long description is refused.
	w = httptest.NewRecorder()
	h.Update(w, cycleBodyRequest(http.MethodPut, "/api/v1/ctem-cycles/"+created.ID, tenantID, created.ID,
		map[string]any{"name": "Q4", "description": strings.Repeat("x", maxCycleDescription+1)}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("long description = %d", w.Code)
	}

	if _, err := db.ExecContext(ctx, `UPDATE ctem_cycles SET status = 'review' WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.UpdateScopeRefinement(w, cycleBodyRequest(http.MethodPost, "/api/v1/ctem-cycles/"+created.ID+"/scope-refinement",
		tenantID, created.ID, map[string]any{"scope_refinement_notes": "add the partner API next cycle"}))
	if w.Code != http.StatusOK {
		t.Fatalf("refinement notes on a charterless cycle = %d %s", w.Code, w.Body.String())
	}
	var notes string
	if err := db.QueryRowContext(ctx, `SELECT charter->>'scope_refinement_notes' FROM ctem_cycles WHERE id = $1`, created.ID).Scan(&notes); err != nil || notes != "add the partner API next cycle" {
		t.Fatalf("stored notes = %q (%v)", notes, err)
	}

	// Another tenant cannot write the notes.
	other := seedHandlerTenant(ctx, t, db)
	w = httptest.NewRecorder()
	h.UpdateScopeRefinement(w, cycleBodyRequest(http.MethodPost, "/api/v1/ctem-cycles/"+created.ID+"/scope-refinement",
		other, created.ID, map[string]any{"scope_refinement_notes": "x"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross-tenant notes = %d, want 400", w.Code)
	}
}

// A snapshot that fails rolls the activation back: the cycle stays in
// planning, without an activation stamp, and the caller sees the error.
func TestCTEMCycleHandler_ActivateFailsWhenSnapshotFails(t *testing.T) {
	// A private database: the failing-insert trigger is DDL, which the
	// least-privilege app role may not run, and it must not touch the shared
	// test database.
	db := testdb.PrivateDatabase(t, "cyclesnap", "../../../../migrations")
	ctx := context.Background()
	tenantID := seedHandlerTenant(ctx, t, db)
	var cycleID string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, created_by) VALUES ($1, 'snap', gen_random_uuid()) RETURNING id`,
		tenantID).Scan(&cycleID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, 'snap.example.test', 'domain')`, tenantID); err != nil {
		t.Fatal(err)
	}
	// A trigger that refuses this cycle's snapshot rows stands in for a
	// failing insert.
	fn := "test_refuse_snapshot_" + strings.ReplaceAll(cycleID, "-", "")
	if _, err := db.ExecContext(ctx, `CREATE FUNCTION `+fn+`() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.cycle_id = '`+cycleID+`'::uuid THEN RAISE EXCEPTION 'snapshot refused'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER `+fn+` BEFORE INSERT ON ctem_cycle_scope_snapshots FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS `+fn+` ON ctem_cycle_scope_snapshots`)
		_, _ = db.ExecContext(context.Background(), `DROP FUNCTION IF EXISTS `+fn+`()`)
	})

	h := NewCTEMCycleHandler(db, nil, logger.NewNop())
	w := httptest.NewRecorder()
	h.Activate(w, cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycleID+"/activate", tenantID, cycleID))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "not activated") {
		t.Fatalf("activate with a failing snapshot = %d %s", w.Code, w.Body.String())
	}
	var status string
	var activated sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT status, activated_at FROM ctem_cycles WHERE id = $1`, cycleID).Scan(&status, &activated); err != nil {
		t.Fatal(err)
	}
	if status != "planning" || activated.Valid {
		t.Fatalf("after a failed snapshot: status %q, activated %v", status, activated.Valid)
	}

	// With the snapshot working again, activation succeeds with its rows.
	if _, err := db.ExecContext(ctx, `DROP TRIGGER `+fn+` ON ctem_cycle_scope_snapshots`); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.Activate(w, cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycleID+"/activate", tenantID, cycleID))
	if w.Code != http.StatusOK {
		t.Fatalf("activate = %d %s", w.Code, w.Body.String())
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM ctem_cycle_scope_snapshots WHERE cycle_id = $1`, cycleID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("snapshot rows = %d (%v), want 1", n, err)
	}
}

type recordingAudit struct {
	events []auditapp.AuditEvent
	actx   []auditapp.AuditContext
	err    error
}

func (a *recordingAudit) LogEvent(_ context.Context, actx auditapp.AuditContext, e auditapp.AuditEvent) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, e)
	a.actx = append(a.actx, actx)
	return nil
}

// When the coverage check cannot run, closing is refused; an override with
// a reason closes it and is audited first; an override that cannot be
// audited is refused; an override never lifts an enforced SLO breach.
func TestCTEMCycleHandler_CloseRefusedWhenCoverageCheckFails(t *testing.T) {
	db := openCycleDB(t)
	ctx := context.Background()
	repo := postgres.NewCTEMCycleMetricsRepository(&postgres.DB{DB: db})
	tenantID := seedHandlerTenant(ctx, t, db)
	cycleID := seedReviewCycleBelowSLO(ctx, t, db, tenantID)

	failing := func(context.Context, string, string, string) (validation.ValidationCoverage, error) {
		return validation.ValidationCoverage{}, errors.New("db down")
	}
	h := NewCTEMCycleHandler(db, repo, logger.NewNop())
	h.coverageQuery = failing
	status := func() string {
		var s string
		if err := db.QueryRowContext(ctx, `SELECT status FROM ctem_cycles WHERE id = $1`, cycleID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	closeWith := func(body any) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.Close(w, cycleBodyRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycleID+"/close", tenantID, cycleID, body))
		return w
	}

	if w := closeWith(nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), string(CodeCoverageCheckFailed)) {
		t.Fatalf("close with a failed check = %d %s", w.Code, w.Body.String())
	}
	if s := status(); s != "review" {
		t.Fatalf("status after refusal = %s", s)
	}
	// An override needs a reason.
	if w := closeWith(map[string]any{"override_coverage_check": true, "override_reason": "ok"}); w.Code != http.StatusBadRequest {
		t.Fatalf("override without a real reason = %d", w.Code)
	}
	// No audit log wired: the override is refused.
	if w := closeWith(map[string]any{"override_coverage_check": true, "override_reason": "coverage store is down; evidence reviewed by hand"}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("override without audit = %d", w.Code)
	}
	// The audit write fails: refused.
	h.WithAudit(&recordingAudit{err: errors.New("audit down")})
	if w := closeWith(map[string]any{"override_coverage_check": true, "override_reason": "coverage store is down; evidence reviewed by hand"}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("override with a failing audit = %d", w.Code)
	}
	if s := status(); s != "review" {
		t.Fatalf("status after refused overrides = %s", s)
	}

	audit := &recordingAudit{}
	h.WithAudit(audit)
	if w := closeWith(map[string]any{"override_coverage_check": true, "override_reason": "coverage store is down; evidence reviewed by hand"}); w.Code != http.StatusOK {
		t.Fatalf("override = %d %s", w.Code, w.Body.String())
	}
	if s := status(); s != "closed" {
		t.Fatalf("status after override = %s", s)
	}
	if len(audit.events) != 1 || audit.events[0].Action != auditdom.ActionCTEMCycleCloseOverridden ||
		audit.events[0].ResourceID != cycleID || audit.events[0].Metadata["reason"] != "coverage store is down; evidence reviewed by hand" ||
		audit.actx[0].TenantID != tenantID {
		t.Fatalf("audit = %+v %+v", audit.events, audit.actx)
	}

	// An enforced SLO breach is not lifted by an override.
	strict := seedHandlerTenant(ctx, t, db)
	strictCycle := seedReviewCycleBelowSLO(ctx, t, db, strict)
	h2 := NewCTEMCycleHandler(db, repo, logger.NewNop()).
		WithCyclePolicy(&stubCyclePolicy{enforce: map[string]bool{strict: true}}).WithAudit(&recordingAudit{})
	w := httptest.NewRecorder()
	h2.Close(w, cycleBodyRequest(http.MethodPost, "/api/v1/ctem-cycles/"+strictCycle+"/close", strict, strictCycle,
		map[string]any{"override_coverage_check": true, "override_reason": "we accept the shortfall this time"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("override of an enforced breach = %d %s", w.Code, w.Body.String())
	}
}

// Cycles whose charter is SQL NULL or JSON null (written before this fix, or
// by the previous release during a rolling deploy) take refinement notes.
func TestCTEMCycleHandler_RefinementNotesOnNullCharter(t *testing.T) {
	db := openCycleDB(t)
	ctx := context.Background()
	tenantID := seedHandlerTenant(ctx, t, db)
	h := NewCTEMCycleHandler(db, nil, logger.NewNop())
	for _, charter := range []string{"NULL", "'null'::jsonb"} {
		var id string
		if err := db.QueryRowContext(ctx, `INSERT INTO ctem_cycles (tenant_id, name, status, created_by, charter)
			VALUES ($1, 'n', 'review', gen_random_uuid(), `+charter+`) RETURNING id`, tenantID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.UpdateScopeRefinement(w, cycleBodyRequest(http.MethodPost, "/api/v1/ctem-cycles/"+id+"/scope-refinement",
			tenantID, id, map[string]any{"scope_refinement_notes": "keep the VPN out"}))
		if w.Code != http.StatusOK {
			t.Fatalf("notes on a %s charter = %d %s", charter, w.Code, w.Body.String())
		}
		var notes string
		if err := db.QueryRowContext(ctx, `SELECT charter->>'scope_refinement_notes' FROM ctem_cycles WHERE id = $1`, id).Scan(&notes); err != nil || notes != "keep the VPN out" {
			t.Fatalf("stored notes on a %s charter = %q (%v)", charter, notes, err)
		}
	}
}
