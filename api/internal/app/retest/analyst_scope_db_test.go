package retest_test

// An AI analyst reaches the network only through platform commands, as its
// own principal (docs/architecture/ai-analysis.md). A retest it requests
// names a finding, never a target: the platform derives the target from the
// finding and runs the same active-probe gate as for a person, so an
// out-of-scope target is refused before any job exists.

import (
	"context"
	"errors"
	"testing"

	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/app/validation"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (fx *fixture) newAnalyst() shared.ID {
	fx.t.Helper()
	id := shared.NewID()
	fx.exec(`INSERT INTO users (id, email, name, kind, service_tenant_id) VALUES ($1, $2, 'AI analyst', 'service', $3)`,
		id.String(), "svc-"+id.String()+"@service-accounts.invalid", fx.tenant.String())
	fx.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'viewer')`, id.String(), fx.tenant.String())
	fx.exec(`DELETE FROM user_roles WHERE user_id = $1`, id.String())
	fx.exec(`INSERT INTO ai_analysts (user_id, tenant_id, preset, attest_due_at) VALUES ($1, $2, 'triage', now() + interval '90 days')`,
		id.String(), fx.tenant.String())
	fx.t.Cleanup(func() { _, _ = fx.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}

func TestRetestDB_AnalystCannotReachAnOutOfScopeTarget(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	analyst := fx.newAnalyst()
	ctx := context.Background()

	// In scope: the analyst's request queues the same scoped commands a
	// person's would, recorded as its own.
	inScope := fx.newFinding(fx.asset, "confirmed", "CVE-2024-1234")
	rt, err := svc.Request(ctx, retestapp.RequestInput{TenantID: fx.tenant, FindingID: inScope, Trigger: retestdom.TriggerManual, RequestedBy: &analyst})
	if err != nil {
		t.Fatalf("in-scope retest by the analyst: %v", err)
	}
	if rt.RequestedBy == nil || *rt.RequestedBy != analyst {
		t.Fatal("the retest is not recorded as the analyst's")
	}

	// The asset is then excluded from scope: the next request is refused
	// before any command is queued.
	fx.excludeDomain("shop.example.com")
	var before int
	_ = fx.db.QueryRow(`SELECT COUNT(*) FROM commands WHERE tenant_id = $1`, fx.tenant.String()).Scan(&before)
	excluded := fx.newFinding(fx.asset, "confirmed", "CVE-2024-5678")
	if _, err := svc.Request(ctx, retestapp.RequestInput{TenantID: fx.tenant, FindingID: excluded, Trigger: retestdom.TriggerManual, RequestedBy: &analyst}); !errors.Is(err, validation.ErrTargetRefused) {
		t.Fatalf("the analyst's retest of an out-of-scope target: %v, want refused", err)
	}
	var after int
	_ = fx.db.QueryRow(`SELECT COUNT(*) FROM commands WHERE tenant_id = $1`, fx.tenant.String()).Scan(&after)
	if after != before {
		t.Fatalf("%d commands queued for an out-of-scope target", after-before)
	}
}
