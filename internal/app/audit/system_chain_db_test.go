package audit_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/internal/infra/postgres"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/logger"
)

// package audit_test, not audit: this test needs the real postgres repository,
// and internal/infra/postgres -> internal/app -> internal/app/audit, so an
// in-package test would be an import cycle. An external test package can
// depend on packages that depend on the one under test.
//
// Driven through the real repository against a real database, because the
// question this answers is not "does the Go branch take the right path" but
// "does a row land in audit_log_chain". A mock would answer the first and
// prove nothing about the second — and the whole reason this gap existed for
// months is that the components were each individually correct.

func openAuditDB(t *testing.T) *postgres.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping audit system-chain DB tests")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return &postgres.DB{DB: db}
}

// logSystemAuthEvent writes one tenant-less auth event the way the production
// helper does, and returns its audit_log id.
func logSystemAuthEvent(ctx context.Context, t *testing.T, db *postgres.DB) string {
	t.Helper()

	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	// No TenantID: this is what every auth.login carries.
	if err := svc.LogUserLogin(ctx, auditapp.AuditContext{}, "", "chain-test@example.test"); err != nil {
		t.Fatalf("log login event: %v", err)
	}

	var id string
	if err := db.QueryRowContext(ctx, `
		SELECT id FROM audit_logs
		 WHERE tenant_id IS NULL AND resource_name = $1
		 ORDER BY logged_at DESC LIMIT 1`,
		"chain-test@example.test").Scan(&id); err != nil {
		t.Fatalf("read back the audit log: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM audit_log_chain WHERE audit_log_id = $1`, id)
		_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE id = $1`, id)
	})
	return id
}

// The defect: an auth event produced no chain row at all, so deleting or
// editing it left no evidence.
func TestSystemChain_AuthEventIsChained(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)

	id := logSystemAuthEvent(ctx, t, db)

	var tenantID, hash string
	err := db.QueryRowContext(ctx,
		`SELECT tenant_id, hash FROM audit_log_chain WHERE audit_log_id = $1`, id,
	).Scan(&tenantID, &hash)
	if err != nil {
		t.Fatalf("no chain row for a tenant-less auth event (%v). It is stored in "+
			"audit_logs with no tamper evidence: an intruder can delete the record "+
			"of their own login and the verifier will report the trail intact, "+
			"because it only walks rows that were chained", err)
	}

	if tenantID != auditdom.SystemChainTenantID.String() {
		t.Errorf("chain row tenant_id = %s, want the system chain sentinel %s",
			tenantID, auditdom.SystemChainTenantID)
	}
	if len(hash) != 64 {
		t.Errorf("hash = %q, want 64 hex chars", hash)
	}
}

// A chain is only evidence if verification agrees with what was written. This
// catches a write/verify payload mismatch — the failure mode that produced
// months of false "chain break" alerts once before.
func TestSystemChain_VerifiesClean(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)

	id := logSystemAuthEvent(ctx, t, db)

	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	res, err := svc.VerifyChain(ctx, auditdom.SystemChainTenantID, 10_000)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Total == 0 {
		t.Fatal("the system chain verified 0 entries: nothing is being checked")
	}

	for _, b := range res.Breaks {
		if b.AuditLogID == id {
			t.Fatalf("the entry just written verifies as broken (%s). Note "+
				"audit_log_missing here means the verifier looked the row up with "+
				"the tenant-scoped getter, which cannot see tenant_id IS NULL rows "+
				"— a fabricated tamper signal on the chain that exists to detect "+
				"real ones", b.Reason)
		}
	}
}

// Tenant-scoped events must keep going to their own chain. A fix that swept
// everything into the system chain would destroy per-tenant isolation of the
// audit trail.
func TestSystemChain_TenantEventsStillUseTheirOwnChain(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)

	var tenantID string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO tenants (id, name, slug)
		 VALUES (gen_random_uuid(), 'chain test', 'chain-test-' || gen_random_uuid())
		 RETURNING id`).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg,
			`DELETE FROM audit_log_chain WHERE audit_log_id IN
			 (SELECT id FROM audit_logs WHERE tenant_id = $1)`, tenantID)
		_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	if err := svc.LogUserLogin(ctx, auditapp.AuditContext{TenantID: tenantID},
		"", "tenant-scoped@example.test"); err != nil {
		t.Fatalf("log tenant event: %v", err)
	}

	var chainTenant string
	if err := db.QueryRowContext(ctx, `
		SELECT c.tenant_id
		  FROM audit_log_chain c
		  JOIN audit_logs l ON l.id = c.audit_log_id
		 WHERE l.tenant_id = $1
		 ORDER BY c.chain_position DESC LIMIT 1`, tenantID).Scan(&chainTenant); err != nil {
		t.Fatalf("no chain row for a tenant-scoped event: %v", err)
	}

	if chainTenant == auditdom.SystemChainTenantID.String() {
		t.Fatal("a tenant's audit event was appended to the SYSTEM chain, merging " +
			"tenants' trails into one shared chain")
	}
	if chainTenant != tenantID {
		t.Errorf("chain tenant = %s, want %s", chainTenant, tenantID)
	}
}
