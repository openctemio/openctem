package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func openGovernanceDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	return db
}

// A compensating control lowers the priority and SLA of every finding on the
// assets it covers (backend audit B7-R2): it needs a review date, and every
// change, test and link leaves a High audit row with the actor.
func TestCompensatingControlHandler_GovernanceAndAudit(t *testing.T) {
	db := openGovernanceDB(t)
	ctx := context.Background()
	tenantID := shared.NewID().String()
	userID := shared.NewID().String()
	assetID := shared.NewID().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1,'Controls Org',$2)`, tenantID, "controls-"+tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1,$2,'Admin')`, userID, "admin-"+userID+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,'app.example.com','domain')`, assetID, tenantID); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_log_chain WHERE tenant_id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM compensating_controls WHERE tenant_id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE tenant_id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, userID)
	})

	h := NewCompensatingControlHandler(db, logger.NewNop())
	h.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(&postgres.DB{DB: db}), logger.NewNop()))
	do := func(method, path, id string, body any, fn http.HandlerFunc) *httptest.ResponseRecorder {
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		c := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.UserIDKey, userID)
		r = r.WithContext(c)
		if id != "" {
			r = withURLParam(r, "id", id)
		}
		rec := httptest.NewRecorder()
		fn(rec, r)
		return rec
	}
	control := func(expires any) map[string]any {
		m := map[string]any{"name": "WAF", "control_type": "runtime", "reduction_factor": 0.5}
		if expires != nil {
			m["expires_at"] = expires
		}
		return m
	}

	// A past review date, or one beyond the review period: refused.
	for name, exp := range map[string]any{
		"past":     time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"too late": time.Now().Add(MaxControlReviewPeriod + 48*time.Hour).UTC().Format(time.RFC3339),
	} {
		if rec := do(http.MethodPost, "/compensating-controls", "", control(exp), h.Create); rec.Code != http.StatusBadRequest {
			t.Errorf("%s review date: create = %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM compensating_controls WHERE tenant_id=$1`, tenantID).Scan(&n)
	if n != 0 {
		t.Fatalf("%d controls stored by refused creates", n)
	}

	review := time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	rec := do(http.MethodPost, "/compensating-controls", "", control(review), h.Create)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created.ID

	upd := control(review)
	upd["reduction_factor"] = 0.3
	if rec := do(http.MethodPut, "/compensating-controls/"+id, id, upd, h.Update); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	// An update without a review date keeps the stored one (it never clears it).
	upd2 := control(nil)
	upd2["reduction_factor"] = 0.3
	if rec := do(http.MethodPut, "/compensating-controls/"+id, id, upd2, h.Update); rec.Code != http.StatusOK {
		t.Fatalf("update without a review date: %d %s", rec.Code, rec.Body.String())
	}
	var kept sql.NullTime
	_ = db.QueryRowContext(ctx, `SELECT expires_at FROM compensating_controls WHERE id=$1`, id).Scan(&kept)
	if !kept.Valid {
		t.Fatal("an update without a review date cleared it")
	}
	// A control created without a review date gets the default one.
	rec = do(http.MethodPost, "/compensating-controls", "", control(nil), h.Create)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create without a review date: %d %s", rec.Code, rec.Body.String())
	}
	var dflt struct {
		ExpiresAt *time.Time `json:"expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &dflt)
	if dflt.ExpiresAt == nil || dflt.ExpiresAt.After(time.Now().Add(DefaultControlReviewPeriod+time.Hour)) || dflt.ExpiresAt.Before(time.Now().Add(DefaultControlReviewPeriod-time.Hour)) {
		t.Fatalf("default review date = %v, want about %s ahead", dflt.ExpiresAt, DefaultControlReviewPeriod)
	}
	if rec := do(http.MethodPost, "/compensating-controls/"+id+"/test", id, map[string]any{"test_result": "pass", "test_evidence": "blocked"}, h.RecordTest); rec.Code != http.StatusOK {
		t.Fatalf("test: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodPost, "/compensating-controls/"+id+"/assets", id, map[string]any{"asset_ids": []string{assetID}}, h.LinkAssets); rec.Code != http.StatusNoContent {
		t.Fatalf("link assets: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodDelete, "/compensating-controls/"+id, id, nil, h.Delete); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}

	rows, err := db.QueryContext(ctx, `SELECT action, severity, COALESCE(changes::text,'') FROM audit_logs
		WHERE tenant_id=$1 AND resource_id=$2 AND actor_id=$3 ORDER BY logged_at`, tenantID, id, userID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	sawDiff := false
	for rows.Next() {
		var action, severity, changes string
		if err := rows.Scan(&action, &severity, &changes); err != nil {
			t.Fatal(err)
		}
		if severity != "high" {
			t.Errorf("%s severity = %s, want high", action, severity)
		}
		if action == string(auditdom.ActionCompensatingControlUpdated) {
			var c map[string]map[string]any
			_ = json.Unmarshal([]byte(changes), &c)
			if fmt.Sprint(c["before"]["reduction_factor"]) == "0.5" && fmt.Sprint(c["after"]["reduction_factor"]) == "0.3" {
				sawDiff = true
			}
		}
		got[action] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !sawDiff {
		t.Error("no update audit row with the diff reduction_factor 0.5 -> 0.3")
	}
	for _, want := range []auditdom.Action{
		auditdom.ActionCompensatingControlCreated, auditdom.ActionCompensatingControlUpdated,
		auditdom.ActionCompensatingControlTested, auditdom.ActionCompensatingControlAssetsLinked,
		auditdom.ActionCompensatingControlDeleted,
	} {
		if !got[string(want)] {
			t.Errorf("no audit row for %s (got %v)", want, got)
		}
	}
}
