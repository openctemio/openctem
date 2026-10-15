package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func acceptanceEnd(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (string, *time.Time) {
	t.Helper()
	var status string
	var end sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT status, acceptance_expires_at FROM findings WHERE id = $1`, id.String()).
		Scan(&status, &end); err != nil {
		t.Fatal(err)
	}
	if !end.Valid {
		return status, nil
	}
	return status, &end.Time
}

func aboutDefaultEnd(end *time.Time) bool {
	if end == nil {
		return false
	}
	d := time.Until(*end)
	return d > vulnerability.DefaultAcceptanceDuration-time.Hour && d <= vulnerability.DefaultAcceptanceDuration+time.Minute
}

// Every path that makes a finding accepted records when the acceptance ends:
// an approved accepted-risk rule (its expiry, else the 90-day default), ingest
// suppression by such a rule, a person-free full-row write (pentest), and an
// identity merge that inherits an acceptance. An accepted risk always ends.
func TestAcceptanceEnd_EveryAcceptPath_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	pdb := &DB{DB: db}
	repo := NewSuppressionRepository(pdb)
	tenant := seedTestTenant(ctx, t, db)
	requester := seedGroupsUser(ctx, t, db, "acc.end.req")
	approver := seedGroupsUser(ctx, t, db, "acc.end.appr")
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)

	// Approved accepted-risk rule without an expiry: the default end.
	noEnd, reviewed := newPendingRule(ctx, t, repo, tenant, requester, approver, suppression.SuppressionTypeAcceptedRisk,
		func(r *suppression.Rule) { r.SetRuleIDPattern("acc_noend*") })
	f1 := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "acc_noend.x", status: "new"})
	if _, err := repo.Approve(ctx, noEnd, reviewed, approver, nil, 100); err != nil {
		t.Fatalf("approve rule: %v", err)
	}
	if st, end := acceptanceEnd(ctx, t, db, f1); st != "accepted" || !aboutDefaultEnd(end) {
		t.Errorf("rule without expiry: status=%s end=%v, want accepted ending in about 90 days", st, end)
	}

	// Approved rule with an expiry: that expiry.
	ruleEnd := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	withEnd, reviewed2 := newPendingRule(ctx, t, repo, tenant, requester, approver, suppression.SuppressionTypeAcceptedRisk,
		func(r *suppression.Rule) { r.SetRuleIDPattern("acc_end*"); r.SetExpiresAt(&ruleEnd) })
	f2 := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "acc_end.x", status: "confirmed"})
	if _, err := repo.Approve(ctx, withEnd, reviewed2, approver, nil, 100); err != nil {
		t.Fatalf("approve rule: %v", err)
	}
	if st, end := acceptanceEnd(ctx, t, db, f2); st != "accepted" || end == nil || !end.Equal(ruleEnd) {
		t.Errorf("rule with expiry: status=%s end=%v, want accepted until %v", st, end, ruleEnd)
	}

	// Ingest suppression (RecordSuppression) by the rule without an expiry.
	f3 := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "acc_noend.y", status: "accepted"})
	if err := repo.RecordSuppression(ctx, f3, noEnd.ID(), "ingest"); err != nil {
		t.Fatalf("record suppression: %v", err)
	}
	if _, end := acceptanceEnd(ctx, t, db, f3); !aboutDefaultEnd(end) {
		t.Errorf("ingest suppression without rule expiry: end=%v, want about 90 days", end)
	}

	// Full-row write of an accepted finding with no end (the pentest path).
	f4 := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "acc_pentest", status: "accepted"})
	findings := NewFindingRepository(pdb)
	loaded, err := findings.GetByID(ctx, tenant, f4)
	if err != nil {
		t.Fatal(err)
	}
	if err := findings.Update(ctx, loaded); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, end := acceptanceEnd(ctx, t, db, f4); !aboutDefaultEnd(end) {
		t.Errorf("full-row write of an accepted finding: end=%v, want about 90 days", end)
	}

	// Identity merge: the survivor inherits the loser's acceptance and its end.
	survivor := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "acc_merge.a", status: "new"})
	loser := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "acc_merge.b", status: "accepted"})
	if _, err := db.ExecContext(ctx, `UPDATE findings SET acceptance_expires_at = $2 WHERE id = $1`, loser.String(), ruleEnd); err != nil {
		t.Fatal(err)
	}
	if err := pdb.Transaction(ctx, func(tx *sql.Tx) error {
		return mergeFindingInto(ctx, tx, tenant.String(), survivor.String(), loser.String(), causeAssetMerge)
	}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if st, end := acceptanceEnd(ctx, t, db, survivor); st != "accepted" || end == nil || !end.Equal(ruleEnd) {
		t.Errorf("merge survivor: status=%s end=%v, want accepted until the loser's end %v", st, end, ruleEnd)
	}
}
