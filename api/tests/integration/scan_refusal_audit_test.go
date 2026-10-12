package integration

// research/22 §4.0 acceptance rows for the active-scan ownership gate that
// the gate's own test does not cover: a refused quick scan is audited in the
// caller's tenant, and only there. (Two quick scans in the same second, 22c
// B8, are covered by internal/app/scan/quick_name_test.go.) Architecture:
// docs/architecture/active-probe-gate.md.

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestScanOwnershipGate_RefusalAudited(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	seedScopeTarget(t, db, tenantA, "domain", "*.audited.example.com")

	rejected := seedOwnedAsset(t, db, tenantA, "www.audited.example.com", "subdomain")
	decide(t, db, tenantA, rejected, attribution.StateRejected)

	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(&postgres.DB{DB: db}), logger.NewNop())
	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithAttributionGate(ownershipGate(db)),
		scansvc.WithAuditService(app.NewScanAuditServiceAdapter(auditSvc)))

	countRefusals := func(tenant string) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'scan.target_refused' AND result = 'failure'`,
			tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("refused quick scan is audited in the caller's tenant", func(t *testing.T) {
		_, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenantA.String(), ScannerName: "httpx",
			Targets: []string{"www.audited.example.com"}})
		if err == nil {
			t.Fatal("quick scan of a rejected name was accepted")
		}
		if got := countRefusals(tenantA.String()); got != 1 {
			t.Fatalf("tenant A refusal audits = %d, want 1", got)
		}
		if got := countRefusals(tenantB.String()); got != 0 {
			t.Fatalf("tenant B got %d refusal audits for tenant A's request", got)
		}
		var meta string
		if err := db.QueryRowContext(ctx,
			`SELECT metadata::text FROM audit_logs WHERE tenant_id = $1 AND action = 'scan.target_refused'`,
			tenantA.String()).Scan(&meta); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"quick_scan"`, `"www.audited.example.com"`, `"rejected"`} {
			if !strings.Contains(meta, want) {
				t.Fatalf("metadata %s lacks %s", meta, want)
			}
		}
	})
}
