package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The tighten-only rule in the database (trg_findings_sla_deadline_guard):
// no writer can move an open finding's deadline later or clear it, except a
// transaction that marks itself as an SLA restart; closed findings are not
// guarded.

func (fx scoringFixture) setDeadline(t *testing.T, tid, fid shared.ID, d time.Time, status string) {
	t.Helper()
	if _, err := fx.db.Exec(`UPDATE findings SET sla_deadline = $3, sla_status = $4 WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String(), d, status); err != nil {
		t.Fatal(err)
	}
}

func (fx scoringFixture) slaStatus(t *testing.T, tid, fid shared.ID) string {
	t.Helper()
	var s string
	if err := fx.db.QueryRow(`SELECT sla_status FROM findings WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String()).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSLADeadlineGuard_StaleWriterCannotExtend(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-guard")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-guard-open")
	ctx := context.Background()

	// A full-row writer loads the finding while the deadline is 30 days out.
	far := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	fx.setDeadline(t, tid, fid, far, "on_track")
	stale, err := fx.findings.GetByID(ctx, tid, fid)
	if err != nil {
		t.Fatal(err)
	}
	// Meanwhile the deadline tightens to 2 days out (escalation) and the
	// status moves to warning.
	near := time.Now().Add(2 * 24 * time.Hour).UTC().Truncate(time.Second)
	fx.setDeadline(t, tid, fid, near, "on_track")
	if _, err := fx.db.Exec(`UPDATE findings SET sla_status = 'warning' WHERE tenant_id = $1 AND id = $2`, tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}

	// 1. The stale full-row Update writes its other columns but cannot put
	// the old, later deadline back.
	stale.SetDescription("edited by a stale writer")
	if err := fx.findings.Update(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(near) {
		t.Fatalf("stale Update extended the deadline to %v, want %v", r.deadline.Time, near)
	}
	if s := fx.slaStatus(t, tid, fid); s != "warning" {
		t.Fatalf("stale Update changed sla_status to %q, want warning", s)
	}
	var desc string
	if err := fx.db.QueryRow(`SELECT description FROM findings WHERE tenant_id = $1 AND id = $2`, tid.String(), fid.String()).Scan(&desc); err != nil {
		t.Fatal(err)
	}
	if desc != "edited by a stale writer" {
		t.Fatalf("the writer's other columns were dropped: description = %q", desc)
	}

	// 2. A recompute that computed a later deadline keeps the stored one.
	if _, err := fx.scoring.SavePriorities(ctx, tid, []*vulnerability.Finding{stale}); err != nil {
		t.Fatal(err)
	}
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(near) {
		t.Fatalf("SavePriorities extended the deadline to %v, want %v", r.deadline.Time, near)
	}

	// Another tenant's id never writes this finding (tenant-scoped update).
	sooner0 := near.Add(-12 * time.Hour)
	stale.SetSLADeadline(sooner0)
	if n, err := fx.scoring.SavePriorities(ctx, fx.newTenant(t), []*vulnerability.Finding{stale}); err != nil || n != 0 {
		t.Fatalf("cross-tenant SavePriorities = %d, %v; want 0 rows", n, err)
	}
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(near) {
		t.Fatalf("cross-tenant SavePriorities moved the deadline to %v", r.deadline.Time)
	}

	// 3. A raw write cannot extend it or clear it either.
	if _, err := fx.db.Exec(`UPDATE findings SET sla_deadline = now() + interval '90 days' WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.db.Exec(`UPDATE findings SET sla_deadline = NULL WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(near) {
		t.Fatalf("raw write moved the deadline to %v, want %v", r.deadline.Time, near)
	}

	// 4. Tightening still works.
	sooner := near.Add(-24 * time.Hour)
	fx.setDeadline(t, tid, fid, sooner, "warning")
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(sooner) {
		t.Fatalf("tightening was refused: deadline %v, want %v", r.deadline.Time, sooner)
	}
}

func TestSLADeadlineGuard_RestartPathSetsLaterDeadline(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-guard-restart")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-guard-restart")
	ctx := context.Background()

	past := time.Now().Add(-3 * 24 * time.Hour).UTC().Truncate(time.Second)
	fx.setDeadline(t, tid, fid, past, "overdue")
	later := time.Now().Add(14 * 24 * time.Hour).UTC().Truncate(time.Second)
	repo := postgres.NewFindingSLARestartRepository(&postgres.DB{DB: fx.db})
	wrote, err := repo.RestartSLA(ctx, tid, sladom.RegressionRestart{
		FindingID: fid, Deadline: later, PreviousDeadline: &past, PreviousStatus: "overdue",
		Trigger: "scan", RestartedAt: time.Now().UTC(),
	})
	if err != nil || !wrote {
		t.Fatalf("RestartSLA = %v, %v", wrote, err)
	}
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(later) {
		t.Fatalf("restart deadline = %v, want %v", r.deadline.Time, later)
	}
	if s := fx.slaStatus(t, tid, fid); s != "on_track" {
		t.Fatalf("restart sla_status = %q, want on_track", s)
	}

	// The mark is transaction-local: the next plain write is guarded again.
	if _, err := fx.db.Exec(`UPDATE findings SET sla_deadline = $3 WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String(), later.Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(later) {
		t.Fatalf("the restart mark leaked past its transaction: deadline %v, want %v", r.deadline.Time, later)
	}
}

func TestSLADeadlineGuard_ClosedFindingsUntouched(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-guard-closed")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-guard-closed")

	d := time.Now().Add(5 * 24 * time.Hour).UTC().Truncate(time.Second)
	fx.setDeadline(t, tid, fid, d, "on_track")
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'resolved', resolved_at = now() WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	// The guard does not apply to a closed finding: its row is written as given.
	later := d.Add(10 * 24 * time.Hour)
	fx.setDeadline(t, tid, fid, later, "on_track")
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(later) {
		t.Fatalf("closed finding deadline = %v, want %v (the guard must not touch closed findings)", r.deadline.Time, later)
	}
	// And a recompute never writes a closed finding (SavePriorities is open-only).
	f, err := fx.findings.GetByID(context.Background(), tid, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.SetSLADeadline(d)
	if n, err := fx.scoring.SavePriorities(context.Background(), tid, []*vulnerability.Finding{f}); err != nil || n != 0 {
		t.Fatalf("SavePriorities on a closed finding = %d, %v; want 0 rows", n, err)
	}
	if r := fx.row(t, tid, fid); !r.deadline.Time.Equal(later) {
		t.Fatalf("closed finding deadline moved to %v", r.deadline.Time)
	}
}
