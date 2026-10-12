package audit_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Two API replicas write audit events for the same tenant at the same time.
// Each replica has its own service (its own in-process mutex) and its own
// connection pool, as in production. The chain must stay a single line: no
// two entries may extend the same prev_hash, and verification must pass.
// Before the per-tenant advisory lock, both replicas read the same tail and
// forked the chain, and every later verification reported breaks.
func TestAuditChain_TwoReplicasDoNotFork(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping audit chain replica test")
	}
	ctx := context.Background()

	replica := func() (*auditapp.AuditService, *sql.DB) {
		db, err := sql.Open("postgres", dbURL)
		if err != nil {
			t.Fatalf("open db: %v", err)
		}
		if err := db.PingContext(ctx); err != nil {
			t.Skipf("cannot reach DATABASE_URL: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return auditapp.NewAuditService(postgres.NewAuditRepository(&postgres.DB{DB: db}), logger.NewNop()), db
	}
	a, db := replica()
	b, _ := replica()

	tenantID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'chain replicas', $2)`,
		tenantID.String(), "chainrep-"+tenantID.String()[28:]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM audit_log_chain WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	})

	const perReplica = 25
	var wg sync.WaitGroup
	for i := 0; i < perReplica; i++ {
		for r, svc := range []*auditapp.AuditService{a, b} {
			wg.Add(1)
			go func(svc *auditapp.AuditService, n int) {
				defer wg.Done()
				ev := auditapp.NewSuccessEvent(auditdom.ActionSettingsUpdated, auditdom.ResourceTypeSettings, fmt.Sprintf("r%d-%d", r, n))
				if err := svc.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, ev); err != nil {
					t.Errorf("log event: %v", err)
				}
			}(svc, i)
		}
	}
	wg.Wait()

	var entries, distinctPrev int
	if err := db.QueryRowContext(ctx, `SELECT count(*), count(DISTINCT prev_hash) FROM audit_log_chain WHERE tenant_id = $1`,
		tenantID.String()).Scan(&entries, &distinctPrev); err != nil {
		t.Fatal(err)
	}
	if entries != 2*perReplica {
		t.Fatalf("chain has %d entries, want %d", entries, 2*perReplica)
	}
	if distinctPrev != entries {
		t.Fatalf("chain forked: %d entries extend only %d distinct prev hashes", entries, distinctPrev)
	}
	res, err := a.VerifyChain(ctx, tenantID, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || len(res.Breaks) != 0 {
		t.Fatalf("verify: ok=%v breaks=%d", res.OK, len(res.Breaks))
	}
}
