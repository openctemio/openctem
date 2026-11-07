package retest_test

import (
	"context"
	"encoding/json"
	"testing"

	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// settleFixed runs a retest of the finding whose check no longer matches on
// a target that still answers: a confirmed fix.
func (fx *fixture) settleFixed(svc *retestapp.Service, f shared.ID, url string) *retestdom.Retest {
	fx.t.Helper()
	rt := fx.request(svc, f)
	fx.finishAttempt(rt.CheckCommandID, "not_detected", url, 404)
	fx.finish(rt.ReachCommandID, "detected", "target answered")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)
	return fx.retest(rt.ID)
}

// statusAudit is the finding's finding.status_changed audit rows (tenant
// filtered by the caller's choice) as severity + metadata.
func (fx *fixture) statusAudit(tenantCond string, f shared.ID) []map[string]any {
	fx.t.Helper()
	rows, err := fx.db.QueryContext(context.Background(), `SELECT severity, metadata FROM audit_logs
		WHERE action = 'finding.status_changed' AND resource_type = 'finding' AND resource_id = $1 AND `+tenantCond,
		f.String(), fx.tenant.String())
	if err != nil {
		fx.t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var sev string
		var raw []byte
		if err := rows.Scan(&sev, &raw); err != nil {
			fx.t.Fatal(err)
		}
		m := map[string]any{}
		_ = json.Unmarshal(raw, &m)
		m["_severity"] = sev
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		fx.t.Fatal(err)
	}
	return out
}

func (fx *fixture) pendingProposals(f shared.ID) (n int, method string) {
	fx.t.Helper()
	var m []byte
	if err := fx.db.QueryRowContext(context.Background(), `SELECT count(*), COALESCE(max(method), '') FROM finding_closure_proposals
		WHERE tenant_id = $1 AND finding_id = $2 AND state = 'pending'`, fx.tenant.String(), f.String()).Scan(&n, &m); err != nil {
		fx.t.Fatal(err)
	}
	return n, string(m)
}

// A confirmed fix with auto_resolve on passes the organization's closing
// mode: auto resolves (and audits), review proposes, off keeps and proposes
// nothing. The policy read is the retest's own tenant, never another one.
func TestRetestDB_ConfirmedFixFollowsClosingMode(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	fx.autoResolve(true)

	// Another organization in auto mode must not decide for this one.
	other := shared.NewID()
	fx.exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'other', $2, '{"closure":{"mode":"auto"},"retest":{"auto_resolve":true}}')`,
		other.String(), "retest-other-"+other.String())
	t.Cleanup(func() {
		_, _ = fx.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})

	t.Run("auto: resolved, audited high for a critical finding", func(t *testing.T) {
		fx.closingMode("auto")
		f := fx.newFinding(fx.newAsset("cm-auto.example.com"), "confirmed", "cm-auto")
		fx.exec(`UPDATE findings SET severity = 'critical', file_path = 'https://cm-auto.example.com/admin' WHERE id = $1`, f.String())
		if got := fx.settleFixed(svc, f, "https://cm-auto.example.com/admin"); got.ResultStatus != "resolved" {
			t.Fatalf("auto: retest = %+v, want resolved", got)
		}
		rows := fx.statusAudit("tenant_id = $2", f)
		if len(rows) != 1 || rows[0]["_severity"] != "high" || rows[0]["old_status"] != "confirmed" || rows[0]["new_status"] != "resolved" ||
			rows[0]["verification"] != "retest" || rows[0]["actor_kind"] != "system" || rows[0]["closure_decision"] != "close" {
			t.Fatalf("auto: audit rows = %v, want one high finding.status_changed confirmed -> resolved", rows)
		}
		if leaked := fx.statusAudit("tenant_id <> $2", f); len(leaked) != 0 {
			t.Fatalf("audit rows outside the tenant: %v", leaked)
		}
	})
	t.Run("review: kept open and proposed to a person", func(t *testing.T) {
		fx.closingMode("review")
		f := fx.newFinding(fx.newAsset("cm-review.example.com"), "confirmed", "cm-review")
		fx.exec(`UPDATE findings SET file_path = 'https://cm-review.example.com/admin' WHERE id = $1`, f.String())
		got := fx.settleFixed(svc, f, "https://cm-review.example.com/admin")
		if got.Outcome != retestdom.OutcomeConfirmedFixed || got.ResultStatus != "confirmed" {
			t.Fatalf("review: retest = %+v, want confirmed_fixed with the status kept", got)
		}
		if n, method := fx.pendingProposals(f); n != 1 || method != "retest_verified" {
			t.Fatalf("review: proposals = %d (%s), want one retest_verified", n, method)
		}
		if rows := fx.statusAudit("tenant_id = $2", f); len(rows) != 0 {
			t.Fatalf("review: no status moved, audit rows = %v", rows)
		}
		// A person confirms it: closed as fixed, verification retest.
		var pid string
		if err := fx.db.QueryRowContext(context.Background(), `SELECT id::text FROM finding_closure_proposals WHERE tenant_id = $1 AND finding_id = $2 AND state = 'pending'`,
			fx.tenant.String(), f.String()).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		id, _ := shared.IDFromString(pid)
		res, err := postgres.NewFindingRepository(fx.pg).ConfirmClosureProposals(context.Background(), fx.tenant, nil, []shared.ID{id}, fx.user, "analyst", "")
		if err != nil || len(res.Skipped) != 0 {
			t.Fatalf("confirm: %+v, %v", res, err)
		}
		if status, method, _ := fx.findingState(f); status != "resolved" || method != "fixed/retest" {
			t.Fatalf("confirmed proposal: finding = %s/%s, want resolved fixed/retest", status, method)
		}
	})
	t.Run("off: kept open, nothing proposed", func(t *testing.T) {
		fx.closingMode("off")
		f := fx.newFinding(fx.newAsset("cm-off.example.com"), "confirmed", "cm-off")
		fx.exec(`UPDATE findings SET file_path = 'https://cm-off.example.com/admin' WHERE id = $1`, f.String())
		got := fx.settleFixed(svc, f, "https://cm-off.example.com/admin")
		if got.Outcome != retestdom.OutcomeConfirmedFixed || got.ResultStatus != "confirmed" {
			t.Fatalf("off: retest = %+v, want confirmed_fixed with the status kept", got)
		}
		if n, _ := fx.pendingProposals(f); n != 0 {
			t.Fatalf("off: %d proposals, want none", n)
		}
		if status, _, _ := fx.findingState(f); status != "confirmed" {
			t.Fatalf("off: finding = %s, want confirmed", status)
		}
	})
}

// A retest that reopens a resolved finding writes the same audit row.
func TestRetestDB_RegressionMoveIsAudited(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	f := fx.newFinding(fx.asset, "resolved", "tpl-regress-audit")
	rt := fx.request(svc, f)
	fx.finish(rt.CheckCommandID, "detected", "exposure still reproducible")
	fx.finish(rt.ReachCommandID, "detected", "")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)
	if got := fx.retest(rt.ID); got.ResultStatus != "confirmed" {
		t.Fatalf("retest = %+v, want confirmed", got)
	}
	rows := fx.statusAudit("tenant_id = $2", f)
	if len(rows) != 1 || rows[0]["_severity"] != "medium" || rows[0]["old_status"] != "resolved" ||
		rows[0]["new_status"] != "confirmed" || rows[0]["regression"] != true || rows[0]["retest_id"] != rt.ID.String() {
		t.Fatalf("audit rows = %v, want one medium resolved -> confirmed regression", rows)
	}
}
