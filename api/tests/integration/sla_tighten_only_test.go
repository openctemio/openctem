package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SLA on a priority or policy change (docs/architecture/scoring-versions.md):
// an open finding's deadline only tightens, to min(old, change time + new
// SLA), with a timeline entry; a drop or a longer policy never extends it;
// a closed finding keeps its deadline.

func (fx scoringFixture) withSLA(t *testing.T) {
	t.Helper()
	svc := sla.NewService(postgres.NewSLAPolicyRepository(&postgres.DB{DB: fx.db}), logger.NewNop())
	fx.recl.SetSLARecomputer(sla.NewApplier(svc))
}

func (fx scoringFixture) setDefaultPolicy(t *testing.T, tid shared.ID, days int) {
	t.Helper()
	res, err := fx.db.Exec(`UPDATE sla_policies SET p0_days = $2, p1_days = $2, p2_days = $2, p3_days = $2,
		critical_days = $2, high_days = $2, medium_days = $2, low_days = $2, updated_at = now()
		WHERE tenant_id = $1 AND is_default`, tid.String(), days)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := fx.db.Exec(`INSERT INTO sla_policies (tenant_id, name, is_default, p0_days, p1_days, p2_days, p3_days,
			critical_days, high_days, medium_days, low_days)
			VALUES ($1, 'IT default', true, $2, $2, $2, $2, $2, $2, $2, $2)`, tid.String(), days); err != nil {
			t.Fatal(err)
		}
	}
}

func (fx scoringFixture) tightenings(t *testing.T, tid, fid shared.ID) []string {
	t.Helper()
	rows, err := fx.db.Query(`SELECT changes->>'reason' FROM finding_activities
		WHERE tenant_id = $1 AND finding_id = $2 AND activity_type = 'sla_deadline_tightened' ORDER BY created_at, id`,
		tid.String(), fid.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var r sql.NullString
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r.String)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func near(got time.Time, want time.Time) bool {
	d := got.Sub(want)
	return d > -2*time.Minute && d < 2*time.Minute
}

func TestSLATightenOnly_PriorityAndPolicyChanges(t *testing.T) {
	fx := newScoringFixture(t)
	fx.withSLA(t)
	tid := fx.newTenant(t)
	t.Cleanup(func() { _, _ = fx.db.Exec(`DELETE FROM sla_policies WHERE tenant_id = $1`, tid.String()) })
	fx.setDefaultPolicy(t, tid, 90)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-tighten")
	openID := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-open")
	closedID := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-closed")
	fx.drain(t, aid)

	// Detected 60 days ago; the deadline (30 days out) came from the 90-day
	// policy. The other finding is resolved with a deadline in the past.
	oldDeadline := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	if _, err := fx.db.Exec(`UPDATE findings SET first_detected_at = now() - interval '60 days', sla_deadline = $3
		WHERE tenant_id = $1 AND id = $2`, tid.String(), openID.String(), oldDeadline); err != nil {
		t.Fatal(err)
	}
	closedDeadline := time.Now().Add(-5 * 24 * time.Hour).UTC().Truncate(time.Second)
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'resolved', resolved_at = now(), sla_deadline = $3
		WHERE tenant_id = $1 AND id = $2`, tid.String(), closedID.String(), closedDeadline); err != nil {
		t.Fatal(err)
	}
	// The setup itself moved the deadline earlier (and so wrote an entry).
	if got := fx.tightenings(t, tid, openID); len(got) != 1 {
		t.Fatalf("setup tightenings = %v, want one", got)
	}
	if _, err := fx.db.Exec(`DELETE FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2`, tid.String(), openID.String()); err != nil {
		t.Fatal(err)
	}

	// 1. The priority rises (rule: high → P0, policy 7 days for P0): the
	// deadline becomes now + 7 days, not detection + 7 days (in the past).
	if _, err := fx.db.Exec(`UPDATE sla_policies SET p0_days = 7 WHERE tenant_id = $1 AND is_default`, tid.String()); err != nil {
		t.Fatal(err)
	}
	fx.drain(t, aid)
	fx.addRule(t, tid, "high", "P0")
	fx.drain(t, aid)
	r := fx.row(t, tid, openID)
	if r.class != "P0" || !near(r.deadline.Time, time.Now().Add(7*24*time.Hour)) {
		t.Fatalf("after rise: class=%s deadline=%v, want P0 and now + 7 days", r.class, r.deadline.Time)
	}
	if got := fx.tightenings(t, tid, openID); len(got) != 1 || got[0] != "priority_raised" {
		t.Fatalf("timeline after rise = %v, want [priority_raised]", got)
	}
	afterRise := r.deadline.Time

	// 2. The priority drops (rule removed): the deadline stays.
	if _, err := fx.db.Exec(`DELETE FROM priority_override_rules WHERE tenant_id = $1`, tid.String()); err != nil {
		t.Fatal(err)
	}
	fx.drain(t, aid)
	r = fx.row(t, tid, openID)
	if r.class == "P0" || !r.deadline.Time.Equal(afterRise) {
		t.Fatalf("after drop: class=%s deadline=%v, want a lower class and the deadline kept at %v", r.class, r.deadline.Time, afterRise)
	}

	// 3. A shorter policy tightens from the change time.
	fx.setDefaultPolicy(t, tid, 1)
	fx.drain(t, aid)
	r = fx.row(t, tid, openID)
	if !near(r.deadline.Time, time.Now().Add(24*time.Hour)) {
		t.Fatalf("after shorter policy: deadline=%v, want now + 1 day", r.deadline.Time)
	}
	if got := fx.tightenings(t, tid, openID); len(got) != 2 || got[1] != "sla_policy_changed" {
		t.Fatalf("timeline after policy = %v, want [priority_raised sla_policy_changed]", got)
	}
	afterPolicy := r.deadline.Time

	// 4. A longer policy never extends it.
	fx.setDefaultPolicy(t, tid, 180)
	fx.drain(t, aid)
	if r = fx.row(t, tid, openID); !r.deadline.Time.Equal(afterPolicy) {
		t.Fatalf("after longer policy: deadline=%v, want kept at %v", r.deadline.Time, afterPolicy)
	}
	if got := fx.tightenings(t, tid, openID); len(got) != 2 {
		t.Fatalf("a kept deadline wrote a timeline entry: %v", got)
	}

	// The closed finding never moved.
	if c := fx.row(t, tid, closedID); !c.deadline.Time.Equal(closedDeadline) {
		t.Fatalf("closed finding deadline = %v, want %v", c.deadline.Time, closedDeadline)
	}
	if got := fx.tightenings(t, tid, closedID); len(got) != 0 {
		t.Fatalf("closed finding got timeline entries: %v", got)
	}
}

// The ingest upsert keeps the same rule when a finding is written again
// (the race between two reports of one new finding).
func TestSLATightenOnly_UpsertNeverExtends(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-upsert")
	ctx := context.Background()

	mk := func(deadline time.Time) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tid, aid, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "sla-upsert")
		if err != nil {
			t.Fatal(err)
		}
		f.SetFingerprint("sla-upsert-" + aid.String()[:8])
		f.SetSLADeadline(deadline)
		return f
	}
	first := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	f1 := mk(first)
	if _, err := fx.findings.CreateBatchWithResult(ctx, []*vulnerability.Finding{f1}); err != nil {
		t.Fatal(err)
	}
	// A later write with a longer deadline keeps the first one.
	if _, err := fx.findings.CreateBatchWithResult(ctx, []*vulnerability.Finding{mk(first.Add(20 * 24 * time.Hour))}); err != nil {
		t.Fatal(err)
	}
	var got time.Time
	if err := fx.db.QueryRow(`SELECT sla_deadline FROM findings WHERE tenant_id = $1 AND fingerprint = $2`,
		tid.String(), "sla-upsert-"+aid.String()[:8]).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(first) {
		t.Fatalf("upsert extended the deadline to %v, want %v", got, first)
	}
	// A shorter one tightens.
	shorter := first.Add(-5 * 24 * time.Hour)
	if _, err := fx.findings.CreateBatchWithResult(ctx, []*vulnerability.Finding{mk(shorter)}); err != nil {
		t.Fatal(err)
	}
	if err := fx.db.QueryRow(`SELECT sla_deadline FROM findings WHERE tenant_id = $1 AND fingerprint = $2`,
		tid.String(), "sla-upsert-"+aid.String()[:8]).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(shorter) {
		t.Fatalf("upsert deadline = %v, want tightened to %v", got, shorter)
	}
}
