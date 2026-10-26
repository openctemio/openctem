package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// risk_score_pending means "an input of this score changed and the new score
// is queued": the daily and start-up reconcile queues every asset behind
// real changes, and those rows are housekeeping, not pending changes.
func TestAssetRisk_PendingIgnoresReconcileRows(t *testing.T) {
	fx := newRiskFixture(t)
	ctx := context.Background()
	tid := fx.newTenant(t)
	other := fx.newTenant(t)
	aid := fx.ingestAsset(t, tid, "github.com/acme/risk-pending")
	oid := fx.ingestAsset(t, other, "github.com/other/risk-pending")
	fx.drain(t, aid, oid)
	t.Cleanup(func() {
		_, _ = fx.db.Exec(`DELETE FROM asset_risk_queue WHERE tenant_id = ANY($1)`, "{"+tid.String()+","+other.String()+"}")
	})

	if _, err := fx.svc.EnqueueRiskReconcile(ctx, 3600e9); err != nil {
		t.Fatal(err)
	}
	if !fx.queued(t, aid) {
		t.Fatal("reconcile did not queue the asset")
	}
	if a := fx.get(t, tid, aid); a.RiskScorePending() {
		t.Fatal("a reconcile row shows the score as pending")
	}

	// The other organization's asset gets a real change: only it is pending.
	fx.ingestFindings(t, other, oid, vulnerability.SeverityHigh, 1, "pend-other")
	if a := fx.get(t, other, oid); !a.RiskScorePending() {
		t.Fatal("a real change in the other organization is not pending")
	}
	if a := fx.get(t, tid, aid); a.RiskScorePending() {
		t.Fatal("another organization's change shows this asset as pending")
	}

	// A real change pulls this asset's row forward: pending.
	fx.ingestFindings(t, tid, aid, vulnerability.SeverityHigh, 1, "pend")
	if a := fx.get(t, tid, aid); !a.RiskScorePending() {
		t.Fatal("a finding change is not shown as pending")
	}
	fx.drain(t, aid, oid)
	if a := fx.get(t, tid, aid); a.RiskScorePending() {
		t.Fatal("still pending after the rescore")
	}
}
