package integration

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SLA episodes (api/docs/architecture/sla-escalation.md): the escalation job
// announces a breach or an at-risk deadline once per SLA episode, whoever set
// the SLA status, and a new clock or a reopen starts a new episode.

type slaEventLog struct {
	mu       sync.Mutex
	breaches []controller.SLABreachEvent
	warnings []controller.SLAWarningEvent
}

func (l *slaEventLog) Publish(_ context.Context, ev controller.SLABreachEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.breaches = append(l.breaches, ev)
	return nil
}

func (l *slaEventLog) PublishTx(ctx context.Context, _ *sql.Tx, ev controller.SLABreachEvent) error {
	return l.Publish(ctx, ev)
}

func (l *slaEventLog) PublishWarning(_ context.Context, ev controller.SLAWarningEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warnings = append(l.warnings, ev)
	return nil
}

func (l *slaEventLog) PublishWarningTx(ctx context.Context, _ *sql.Tx, ev controller.SLAWarningEvent) error {
	return l.PublishWarning(ctx, ev)
}

func (l *slaEventLog) breachesFor(id shared.ID) []controller.SLABreachEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []controller.SLABreachEvent
	for _, ev := range l.breaches {
		if ev.FindingID == id {
			out = append(out, ev)
		}
	}
	return out
}

func (l *slaEventLog) warningsFor(id shared.ID) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, ev := range l.warnings {
		if ev.FindingID == id {
			n++
		}
	}
	return n
}

func newEscalation(fx scoringFixture) (*controller.SLAEscalationController, *slaEventLog) {
	c := controller.NewSLAEscalationController(fx.db, logger.NewNop())
	log := &slaEventLog{}
	c.SetBreachPublisher(log)
	c.SetWarningPublisher(log)
	return c, log
}

func reconcile(t *testing.T, c *controller.SLAEscalationController) {
	t.Helper()
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

type slaEpisodeRow struct {
	started, breachNotified, atRiskNotified sql.NullTime
	status, slaStatus                       string
}

func (fx scoringFixture) slaEpisode(t *testing.T, tid, fid shared.ID) slaEpisodeRow {
	t.Helper()
	var r slaEpisodeRow
	if err := fx.db.QueryRow(`SELECT sla_started_at, sla_breach_notified_at, sla_at_risk_notified_at, status, COALESCE(sla_status, '')
		FROM findings WHERE tenant_id = $1 AND id = $2`, tid.String(), fid.String()).
		Scan(&r.started, &r.breachNotified, &r.atRiskNotified, &r.status, &r.slaStatus); err != nil {
		t.Fatal(err)
	}
	return r
}

func (fx scoringFixture) activityCount(t *testing.T, tid, fid shared.ID, kind string) int {
	t.Helper()
	var n int
	if err := fx.db.QueryRow(`SELECT count(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2 AND activity_type = $3`,
		tid.String(), fid.String(), kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A breach whose status was set outside the job (here the status trigger on a
// status change after the deadline) is announced once, with a timeline row and
// the finding's title; the next tick sends nothing.
func TestSLAEpisode_BreachSetOutsideJobIsAnnouncedOnce(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-episode-outside")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-episode-outside")
	fx.setDeadline(t, tid, fid, time.Now().Add(-2*time.Hour), "on_track")
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'confirmed', title = 'Outdated OpenSSL' WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	if s := fx.slaStatus(t, tid, fid); s != "overdue" {
		t.Fatalf("status trigger sla_status = %q, want overdue", s)
	}

	c, log := newEscalation(fx)
	reconcile(t, c)
	got := log.breachesFor(fid)
	if len(got) != 1 {
		t.Fatalf("breach events = %d, want 1", len(got))
	}
	if got[0].TenantID != tid || got[0].FindingTitle != "Outdated OpenSSL" {
		t.Fatalf("event = %+v, want tenant %s and the finding title", got[0], tid)
	}
	if n := fx.activityCount(t, tid, fid, "sla_breach"); n != 1 {
		t.Fatalf("sla_breach timeline rows = %d, want 1", n)
	}
	if r := fx.slaEpisode(t, tid, fid); !r.breachNotified.Valid {
		t.Fatal("sla_breach_notified_at not set")
	}

	reconcile(t, c)
	if n := len(log.breachesFor(fid)); n != 1 {
		t.Fatalf("second tick re-announced: %d events", n)
	}
}

// Reopening a closed finding after its deadline starts a new episode: the
// breach is announced again, once.
func TestSLAEpisode_ReopenPastDeadlineAnnouncesOnce(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-episode-reopen")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-episode-reopen")
	fx.setDeadline(t, tid, fid, time.Now().Add(-2*time.Hour), "overdue")
	c, log := newEscalation(fx)
	reconcile(t, c)
	if n := len(log.breachesFor(fid)); n != 1 {
		t.Fatalf("first episode events = %d, want 1", n)
	}

	if _, err := fx.db.Exec(`UPDATE findings SET status = 'resolved', resolution = 'fixed' WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	if r := fx.slaEpisode(t, tid, fid); !r.breachNotified.Valid {
		t.Fatal("closing a finding must not clear the announcement")
	}
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'confirmed' WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	if r := fx.slaEpisode(t, tid, fid); r.breachNotified.Valid || r.atRiskNotified.Valid {
		t.Fatal("a reopen must clear the notified-at columns")
	}
	reconcile(t, c)
	reconcile(t, c)
	if n := len(log.breachesFor(fid)); n != 2 {
		t.Fatalf("events after reopen = %d, want 2 (one per episode)", n)
	}
}

// Two replicas ticking at once announce each breach once.
func TestSLAEpisode_ConcurrentReplicasAnnounceOnce(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-episode-replicas")
	ids := make([]shared.ID, 0, 5)
	for i := 0; i < 5; i++ {
		fid := fx.newFinding(t, tid, aid, vulnerability.SeverityMedium, "sla-episode-replicas-"+string(rune('a'+i)))
		fx.setDeadline(t, tid, fid, time.Now().Add(-time.Hour), "on_track")
		ids = append(ids, fid)
	}
	a, logA := newEscalation(fx)
	b, logB := newEscalation(fx)
	var wg sync.WaitGroup
	for _, c := range []*controller.SLAEscalationController{a, b} {
		wg.Add(1)
		go func(c *controller.SLAEscalationController) {
			defer wg.Done()
			_, _ = c.Reconcile(context.Background())
		}(c)
	}
	wg.Wait()
	for _, fid := range ids {
		if n := len(logA.breachesFor(fid)) + len(logB.breachesFor(fid)); n != 1 {
			t.Fatalf("finding %s announced %d times across replicas, want 1", fid, n)
		}
		if n := fx.activityCount(t, tid, fid, "sla_breach"); n != 1 {
			t.Fatalf("finding %s has %d sla_breach rows, want 1", fid, n)
		}
	}
}

// Every timeline row the job writes carries its finding's own tenant.
func TestSLAEpisode_TimelineRowsStayInTheirTenant(t *testing.T) {
	fx := newScoringFixture(t)
	tenantA, tenantB := fx.newTenant(t), fx.newTenant(t)
	fa := fx.newFinding(t, tenantA, fx.newAsset(t, tenantA, "github.com/acme/sla-episode-a"), vulnerability.SeverityHigh, "sla-episode-a")
	fb := fx.newFinding(t, tenantB, fx.newAsset(t, tenantB, "github.com/acme/sla-episode-b"), vulnerability.SeverityHigh, "sla-episode-b")
	fx.setDeadline(t, tenantA, fa, time.Now().Add(-time.Hour), "on_track")
	fx.setDeadline(t, tenantB, fb, time.Now().Add(-time.Hour), "on_track")
	c, log := newEscalation(fx)
	reconcile(t, c)
	if ev := log.breachesFor(fa); len(ev) != 1 || ev[0].TenantID != tenantA {
		t.Fatalf("tenant A events = %+v", ev)
	}
	if ev := log.breachesFor(fb); len(ev) != 1 || ev[0].TenantID != tenantB {
		t.Fatalf("tenant B events = %+v", ev)
	}
	var cross int
	if err := fx.db.QueryRow(`SELECT count(*) FROM finding_activities a JOIN findings f ON f.id = a.finding_id
		WHERE a.finding_id = ANY($1::uuid[]) AND a.activity_type = 'sla_breach' AND a.tenant_id <> f.tenant_id`,
		"{"+fa.String()+","+fb.String()+"}").Scan(&cross); err != nil {
		t.Fatal(err)
	}
	if cross != 0 {
		t.Fatalf("%d sla_breach rows carry another tenant", cross)
	}
}

// The at-risk warning is measured from the start of the current clock: a
// finding detected long ago whose clock restarted yesterday is not at risk;
// one far into its window is, once.
func TestSLAEpisode_WarningMeasuredFromClockStart(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-episode-warn")
	fresh := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-episode-warn-fresh")
	late := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-episode-warn-late")
	for _, fid := range []shared.ID{fresh, late} {
		if _, err := fx.db.Exec(`UPDATE findings SET first_detected_at = NOW() - interval '200 days' WHERE tenant_id = $1 AND id = $2`,
			tid.String(), fid.String()); err != nil {
			t.Fatal(err)
		}
	}
	setClock := func(fid shared.ID, start, deadline time.Time) {
		t.Helper()
		if _, err := fx.db.Exec(`UPDATE findings SET sla_started_at = $3, sla_deadline = $4, sla_status = 'on_track' WHERE tenant_id = $1 AND id = $2`,
			tid.String(), fid.String(), start, deadline); err != nil {
			t.Fatal(err)
		}
	}
	setClock(fresh, time.Now().Add(-24*time.Hour), time.Now().Add(29*24*time.Hour))
	setClock(late, time.Now().Add(-29*24*time.Hour), time.Now().Add(24*time.Hour))

	c, log := newEscalation(fx)
	reconcile(t, c)
	if n := log.warningsFor(fresh); n != 0 {
		t.Fatalf("a restarted clock warned at once (%d events)", n)
	}
	if n := log.warningsFor(late); n != 1 {
		t.Fatalf("late finding warnings = %d, want 1", n)
	}
	if s := fx.slaStatus(t, tid, late); s != "warning" {
		t.Fatalf("late finding sla_status = %q, want warning", s)
	}
	if n := fx.activityCount(t, tid, late, "sla_warning"); n != 1 {
		t.Fatalf("sla_warning timeline rows = %d, want 1", n)
	}
	reconcile(t, c)
	if n := log.warningsFor(late); n != 1 {
		t.Fatalf("second tick re-warned: %d", n)
	}
}

// A first deadline starts its clock at first detection; a regression restart
// starts a new clock and a new episode, once per reopen.
func TestSLAEpisode_ClockStartAndRestartOncePerReopen(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-episode-restart")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-episode-restart")
	var firstDetected time.Time
	if err := fx.db.QueryRow(`UPDATE findings SET first_detected_at = NOW() - interval '40 days', sla_deadline = NOW() - interval '10 days'
		WHERE tenant_id = $1 AND id = $2 RETURNING first_detected_at`, tid.String(), fid.String()).Scan(&firstDetected); err != nil {
		t.Fatal(err)
	}
	if r := fx.slaEpisode(t, tid, fid); !r.started.Valid || !r.started.Time.Equal(firstDetected) {
		t.Fatalf("first clock start = %v, want first_detected_at %v", r.started, firstDetected)
	}
	c, log := newEscalation(fx)
	reconcile(t, c)

	// A regression: resolved, then seen again (sets last_reopened_at).
	for _, st := range []string{"resolved", "confirmed"} {
		if _, err := fx.db.Exec(`UPDATE findings SET status = $3 WHERE tenant_id = $1 AND id = $2`, tid.String(), fid.String(), st); err != nil {
			t.Fatal(err)
		}
	}
	repo := postgres.NewFindingSLARestartRepository(&postgres.DB{DB: fx.db})
	restart := func() bool {
		t.Helper()
		later := time.Now().Add(14 * 24 * time.Hour)
		wrote, err := repo.RestartSLA(context.Background(), tid, sladom.RegressionRestart{
			FindingID: fid, Deadline: later, PreviousStatus: "overdue", Trigger: "scan", RestartedAt: time.Now(),
		})
		if err != nil {
			t.Fatalf("RestartSLA: %v", err)
		}
		return wrote
	}
	if !restart() {
		t.Fatal("the first restart for this reopen did not write")
	}
	r := fx.slaEpisode(t, tid, fid)
	if !r.started.Valid || time.Since(r.started.Time) > time.Minute {
		t.Fatalf("restart clock start = %v, want now", r.started)
	}
	if r.breachNotified.Valid || r.atRiskNotified.Valid {
		t.Fatal("a new clock must clear the notified-at columns")
	}
	if restart() {
		t.Fatal("a second restart for the same reopen extended the clock again")
	}
	reconcile(t, c)
	if n := len(log.breachesFor(fid)); n != 1 {
		t.Fatalf("breach events = %d, want 1 (the new clock is not due)", n)
	}
}

// A pentest finding's first clock counts from its publication, not from when
// the draft was written.
func TestSLAEpisode_PentestClockStartsAtPublication(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/sla-episode-pentest")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "sla-episode-pentest")
	if _, err := fx.db.Exec(`UPDATE findings SET source = 'pentest', first_detected_at = NOW() - interval '30 days' WHERE tenant_id = $1 AND id = $2`,
		tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.db.Exec(`UPDATE findings SET sla_deadline = NULL WHERE tenant_id = $1 AND id = $2`, tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.db.Exec(`UPDATE findings SET sla_deadline = NOW() + interval '14 days' WHERE tenant_id = $1 AND id = $2`, tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	if r := fx.slaEpisode(t, tid, fid); !r.started.Valid || time.Since(r.started.Time) > time.Minute {
		t.Fatalf("pentest clock start = %v, want now", r.started)
	}
}
