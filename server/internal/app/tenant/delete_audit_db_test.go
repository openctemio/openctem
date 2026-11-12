package tenant_test

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Deleting a tenant must leave a durable audit record. The event used to be
// written with the deleted tenant's id, which audit_logs.tenant_id (a FK to
// tenants) refused, so an organization deletion left no audit row at all.
func TestDeleteTenant_WritesPlatformAuditRecord(t *testing.T) {
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
	ctx := context.Background()
	db := &postgres.DB{DB: raw}

	tenantID := shared.NewID().String()
	if _, err := raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1,'Doomed Org',$2)`,
		tenantID, "doomed-"+tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	log := logger.NewNop()
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	svc := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log, tenantapp.WithTenantAuditService(auditSvc))

	actor := shared.NewID().String()
	if _, err := raw.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1,$2,'Owner')`,
		actor, "owner-"+actor+"@example.com"); err != nil {
		t.Fatalf("seed actor: %v", err)
	}
	t.Cleanup(func() { _, _ = raw.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, actor) })
	if err := svc.DeleteTenant(ctx, auditapp.AuditContext{TenantID: tenantID, ActorID: actor, ActorEmail: "owner@example.com"}, tenantID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}

	var n int
	var tenantCol sql.NullString
	if err := raw.QueryRowContext(ctx, `
		SELECT count(*), max(tenant_id::text)
		  FROM audit_logs
		 WHERE action = 'tenant.deleted' AND resource_id = $1`, tenantID).Scan(&n, &tenantCol); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("tenant.deleted audit rows = %d, want 1", n)
	}
	if tenantCol.Valid {
		t.Fatalf("tenant.deleted row tenant_id = %q, want NULL (platform chain)", tenantCol.String)
	}
}
