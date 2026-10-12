package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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

// A priority rule can re-classify every finding of the tenant (and so move
// SLA deadlines): create, update and delete each leave a High audit row with
// the actor and a diff.
func TestPriorityRuleHandler_ChangesAreAudited(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()
	tenantID := shared.NewID().String()
	userID := shared.NewID().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1,'Rules Org',$2)`, tenantID, "rules-"+tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1,$2,'Admin')`, userID, "admin-"+userID+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_log_chain WHERE tenant_id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM priority_override_rules WHERE tenant_id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, userID)
	})

	h := NewPriorityRuleHandler(db, logger.NewNop())
	h.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(&postgres.DB{DB: db}), logger.NewNop()))
	withCtx := func(r *http.Request) *http.Request {
		c := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.UserIDKey, userID)
		return r.WithContext(c)
	}

	body, _ := json.Marshal(map[string]any{
		"name": "KEV first", "priority_class": "P0", "is_active": true,
		"conditions": json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
	})
	rec := httptest.NewRecorder()
	h.Create(rec, withCtx(httptest.NewRequest(http.MethodPost, "/priority-rules", bytes.NewReader(body))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec = httptest.NewRecorder()
	req := withURLParam(withCtx(httptest.NewRequest(http.MethodPut, "/priority-rules/"+created.ID, bytes.NewReader([]byte(`{"priority_class":"P3"}`)))), "id", created.ID)
	h.Update(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.Delete(rec, withURLParam(withCtx(httptest.NewRequest(http.MethodDelete, "/priority-rules/"+created.ID, nil)), "id", created.ID))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}

	rows, err := db.QueryContext(ctx, `SELECT action, severity, COALESCE(changes::text,'') FROM audit_logs
		WHERE tenant_id=$1 AND resource_id=$2 AND actor_id=$3 ORDER BY logged_at`, tenantID, created.ID, userID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action, severity, changes string
		_ = rows.Scan(&action, &severity, &changes)
		if severity != "high" {
			t.Errorf("%s severity = %s, want high", action, severity)
		}
		if action == string(auditdom.ActionPriorityRuleUpdated) {
			var c map[string]map[string]any
			_ = json.Unmarshal([]byte(changes), &c)
			if c["before"]["priority_class"] != "P0" || c["after"]["priority_class"] != "P3" {
				t.Errorf("update diff = %s, want priority_class P0 -> P3", changes)
			}
		}
		got = append(got, action)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	want := []string{"priority_rule.created", "priority_rule.updated", "priority_rule.deleted"}
	if len(got) != len(want) {
		t.Fatalf("audit actions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit actions = %v, want %v", got, want)
		}
	}
}

func TestSLAChangeSeverity_LongerWindowIsHigh(t *testing.T) {
	before := SLAPolicyResponse{Name: "Default", CriticalDays: 2, HighDays: 7}
	longer := before
	longer.CriticalDays = 30
	if got := slaChangeSeverity(before, longer); got != auditdom.SeverityHigh {
		t.Fatalf("longer critical window: %s, want high", got)
	}
	shorter := before
	shorter.HighDays = 3
	if got := slaChangeSeverity(before, shorter); got != auditdom.SeverityMedium {
		t.Fatalf("shorter window: %s, want medium", got)
	}
	renamed := before
	renamed.Name = "Renamed"
	if got := slaChangeSeverity(before, renamed); got != auditdom.SeverityMedium {
		t.Fatalf("rename: %s, want medium", got)
	}
}

func TestIntegrationAuditView_DropsVolatileFields(t *testing.T) {
	v := integrationAuditView(IntegrationResponse{ID: "1", Name: "Jira", BaseURL: "https://jira.example", Status: "connected", UpdatedAt: time.Now()})
	m, _ := v.(map[string]any)
	if m["status"] != nil || m["updated_at"] != nil {
		t.Fatalf("volatile fields kept: %v", m)
	}
	if m["base_url"] != "https://jira.example" || m["name"] != "Jira" {
		t.Fatalf("config fields dropped: %v", m)
	}
}
