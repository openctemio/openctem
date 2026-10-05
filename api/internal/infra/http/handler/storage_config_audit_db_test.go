package handler

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Changing where evidence files are stored is audited (High) with a diff,
// and the stored S3 keys never appear in it.
func TestUpdateStorageConfig_IsAuditedWithoutKeys(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	db := &postgres.DB{DB: raw}
	tenantID := shared.NewID().String()
	actor := shared.NewID().String()
	if _, err := raw.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1,'Storage Org',$2)`, tenantID, "storage-"+tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO users (id, email, name) VALUES ($1,$2,'Admin')`, actor, "admin-"+actor+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = raw.ExecContext(ctx, `DELETE FROM audit_log_chain WHERE tenant_id=$1`, tenantID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id=$1`, tenantID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM settings WHERE tenant_id=$1`, tenantID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, actor)
	})

	resolver := app.NewSettingsStorageResolver(raw, crypto.NewNoOpEncryptor(), logger.NewNop())
	const secretKey = "SEKRET-s3-key-value"
	if _, err := raw.Exec(`INSERT INTO settings (id, tenant_id, key, category, value_type, value_json, description)
		VALUES (gen_random_uuid(), $1, 'storage_config', 'storage', 'json',
		        jsonb_build_object('provider','s3','bucket','evidence','region','eu-west-1','access_key','AKIAEXAMPLE','secret_key',$2::text), 'test')`,
		tenantID, secretKey); err != nil {
		t.Fatalf("seed storage config: %v", err)
	}

	h := NewAttachmentHandler(nil, logger.NewNop())
	h.SetStorageResolver(resolver)
	h.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop()))

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/attachments/storage-config", strings.NewReader(`{"provider":"local"}`))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, middleware.UserIDKey, actor)
	w := httptest.NewRecorder()
	h.UpdateStorageConfig(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}

	var severity, changes string
	if err := raw.QueryRow(`SELECT severity, changes::text FROM audit_logs
		WHERE tenant_id=$1 AND action='storage_config.updated' AND actor_id=$2`, tenantID, actor).Scan(&severity, &changes); err != nil {
		t.Fatalf("no storage_config.updated row: %v", err)
	}
	if severity != "high" {
		t.Fatalf("severity = %s, want high", severity)
	}
	if strings.Contains(changes, secretKey) || strings.Contains(changes, "AKIAEXAMPLE") {
		t.Fatalf("audit diff leaks storage keys: %s", changes)
	}
	if !strings.Contains(changes, `"provider": "s3"`) && !strings.Contains(changes, `"provider":"s3"`) {
		t.Fatalf("diff does not show the provider change: %s", changes)
	}
}
