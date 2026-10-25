// Finding regression semantics (research 154 section 1.5, D3, D8; research 18):
// what a scan that reports a finding again does to a finding in each state,
// end to end through the v2 ingest path against a real database.
//
// Same asset, same rule, same fingerprint unless a test says otherwise. The
// repository default-branch coverage proof closes a finding when a full,
// cleanly completed scan of the same tool no longer reports it.

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type recordedNotice struct {
	event string
	id    string
	title string
}

type noticeRecorder struct {
	mu   sync.Mutex
	list []recordedNotice
}

func (n *noticeRecorder) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	id := ""
	if p.AggregateID != nil {
		id = p.AggregateID.String()
	}
	n.list = append(n.list, recordedNotice{event: p.EventType, id: id, title: p.Title})
	return nil
}

func (n *noticeRecorder) count(event string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, x := range n.list {
		if x.event == event {
			c++
		}
	}
	return c
}

type regRig struct {
	*crossToolRig
	notes *noticeRecorder
}

func newRegRig(t *testing.T) *regRig {
	t.Helper()
	notes := &noticeRecorder{}
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		svc.SetResultQuarantine(postgres.NewSensorResultRepository(db), sensorresult.DefaultLimits())
		svc.SetCommandReader(postgres.NewCommandRepository(db))
		svc.SetCoverageAutoResolve(ingest.CoverageAutoResolveDryRun, ingest.DefaultBlindingGuard())
		restarter := sla.NewRegressionRestarter(fixedSLA{}, postgres.NewFindingSLARestartRepository(db), logger.NewNop())
		announcer := retest.NewChangeAnnouncer(postgres.NewFindingRepository(db), nil, notes, logger.NewNop())
		svc.SetRegressionHandler(retest.NewScanRegressions(restarter, announcer, logger.NewNop()))
	})
	return &regRig{crossToolRig: &crossToolRig{r: r, tn: r.newTenant("trivy", "grype")}, notes: notes}
}

type regRow struct {
	rows        int
	id          string
	status      string
	isRegr      bool
	reopenCount int
	lastReopen  sql.NullTime
	firstSeen   time.Time
	slaStarted  sql.NullTime
	resolution  sql.NullString
	closure     sql.NullString
	verif       sql.NullString
	acts        []string
}

func (r *regRig) row(t *testing.T, rule string) regRow {
	t.Helper()
	var x regRow
	db := r.r.db
	tenant := r.tn.tenant.String()
	if err := db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id=$1 AND rule_id=$2`, tenant, rule).Scan(&x.rows); err != nil {
		t.Fatal(err)
	}
	if x.rows == 0 {
		return x
	}
	if err := db.QueryRow(`SELECT id, status, COALESCE(is_regression,false), COALESCE(reopen_count,0), last_reopened_at, first_detected_at,
		sla_started_at, resolution, closure_reason, verification FROM findings WHERE tenant_id=$1 AND rule_id=$2 ORDER BY created_at LIMIT 1`, tenant, rule).
		Scan(&x.id, &x.status, &x.isRegr, &x.reopenCount, &x.lastReopen, &x.firstSeen, &x.slaStarted, &x.resolution, &x.closure, &x.verif); err != nil {
		t.Fatal(err)
	}
	rs, err := db.Query(`SELECT activity_type FROM finding_activities WHERE finding_id=$1 ORDER BY created_at, id`, x.id)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	for rs.Next() {
		var a string
		_ = rs.Scan(&a)
		x.acts = append(x.acts, a)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x regRow) String() string {
	return fmt.Sprintf("rows=%d status=%s regr=%v n=%d lastReopen=%v sla_started=%v resolution=%q closure=%q verif=%q acts=%s",
		x.rows, x.status, x.isRegr, x.reopenCount, x.lastReopen.Valid, x.slaStarted.Valid, x.resolution.String, x.closure.String, x.verif.String, strings.Join(x.acts, ","))
}

func (r *regRig) scan(t *testing.T, coverage string, fs ...ctis.Finding) {
	t.Helper()
	for i := range fs {
		fs[i].AssetRef = "repo"
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "trivy"},
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC(), CoverageType: coverage,
			Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + r.tn.repo}},
		Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: r.tn.repo}},
		Findings: fs}
	cmd := r.r.runCommand(r.tn, "trivy", "", "completed", 0)
	st := r.r.sendWhole(r.tn, r.r.openAs(r.tn, shared.NewID().String(), "worker", &cmd, rep), rep)
	if st.State != protov2.StateCompleted || st.Rejected.Findings != 0 {
		t.Fatalf("scan: %+v", st)
	}
}

func (r *regRig) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := r.r.db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// agedOut makes the automatic close of rule older than the flap window, so a
// re-detection is a regression and not "seen again".
func (r *regRig) agedOut(t *testing.T, rule string) {
	t.Helper()
	r.exec(t, `UPDATE findings SET resolved_at = NOW() - interval '10 days' WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), rule)
}

// triaged records that someone moved the finding to confirmed once, the way
// the timeline of a triaged finding shows it.
func (r *regRig) triaged(t *testing.T, rule string) {
	t.Helper()
	r.exec(t, `INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source)
		SELECT tenant_id, id, 'status_changed', 'user', '{"old_status":"new","new_status":"confirmed"}'::jsonb, 'manual'
		FROM findings WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), rule)
}

func (x regRow) has(act string) bool {
	for _, a := range x.acts {
		if a == act {
			return true
		}
	}
	return false
}

func (r *regRig) lastReopenReason(t *testing.T, rule string) string {
	t.Helper()
	var reason, msg sql.NullString
	err := r.r.db.QueryRow(`SELECT a.changes->>'reason', a.message FROM finding_activities a JOIN findings f ON f.id=a.finding_id
		WHERE f.tenant_id=$1 AND f.rule_id=$2 AND a.activity_type='auto_reopened' ORDER BY a.created_at DESC LIMIT 1`,
		r.tn.tenant.String(), rule).Scan(&reason, &msg)
	if err != nil {
		t.Fatalf("reopen activity: %v", err)
	}
	return reason.String + " | " + msg.String
}

const lodashRule = "CVE-2021-23337"

// 1. found -> a full covered scan without it auto-resolves -> found again after
// the flap window: the SAME record reopens as a regression. Untriaged it comes
// back as new, a triaged one as confirmed. The counters, a new SLA clock (age
// keeps first_detected_at), the timeline and the notification all follow.
func TestRegressionSemantics_AutoResolvedThenFoundAgain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		triaged bool
		want    string
	}{{"untriaged reopens as new", false, "new"}, {"triaged reopens as confirmed", true, "confirmed"}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegRig(t)
			r.scan(t, "full", lodashFinding(), anchorFinding())
			first := r.row(t, lodashRule)
			if tc.triaged {
				r.triaged(t, lodashRule)
			}
			r.scan(t, "full", anchorFinding())
			if got := r.row(t, lodashRule); got.status != "resolved" || got.verif.String != "covered_scan" {
				t.Fatalf("scan 2 (full, without it): %s, want resolved by covered_scan", got)
			}
			r.agedOut(t, lodashRule)
			r.scan(t, "full", lodashFinding(), anchorFinding())

			got := r.row(t, lodashRule)
			if got.rows != 1 || got.id != first.id {
				t.Fatalf("rows=%d id=%s, want the same single record %s", got.rows, got.id, first.id)
			}
			if got.status != tc.want {
				t.Errorf("status = %s, want %s", got.status, tc.want)
			}
			if !got.isRegr || got.reopenCount != 1 || !got.lastReopen.Valid {
				t.Errorf("is_regression=%v reopen_count=%d last_reopened=%v, want true 1 set", got.isRegr, got.reopenCount, got.lastReopen.Valid)
			}
			if !got.firstSeen.Equal(first.firstSeen) {
				t.Errorf("first_detected_at moved: %v -> %v (age must be kept)", first.firstSeen, got.firstSeen)
			}
			if !got.slaStarted.Valid || !got.slaStarted.Time.After(got.firstSeen) {
				t.Errorf("sla_started_at = %v, want a new clock after first_detected_at %v", got.slaStarted, got.firstSeen)
			}
			if !got.has("sla_restarted") {
				t.Errorf("no sla_restarted entry: %v", got.acts)
			}
			if why := r.lastReopenReason(t, lodashRule); !strings.Contains(why, "regression_detected_again") || !strings.Contains(why, "closed as fixed") {
				t.Errorf("timeline entry = %q", why)
			}
			if r.notes.count("finding_reopened") != 1 {
				t.Errorf("regression notices = %d, want 1", r.notes.count("finding_reopened"))
			}
			if got.resolution.Valid && got.resolution.String != "" || got.verif.Valid {
				t.Errorf("closure left on an open finding: %s", got)
			}
		})
	}
}

// 2. A fix a retest verified that is seen again is the strongest regression.
// Even a fix verified a minute ago is not damped.
func TestRegressionSemantics_VerifiedFixRegressed(t *testing.T) {
	r := newRegRig(t)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	r.scan(t, "full", anchorFinding())
	r.exec(t, `UPDATE findings SET verification='retest', resolved_at = NOW() WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), lodashRule)
	r.scan(t, "full", lodashFinding(), anchorFinding())

	got := r.row(t, lodashRule)
	if !got.isRegr || got.reopenCount != 1 || !got.has("sla_restarted") {
		t.Fatalf("verified fix seen again: %s, want a counted regression with a new SLA clock", got)
	}
	if why := r.lastReopenReason(t, lodashRule); !strings.Contains(why, "verified fix") {
		t.Errorf("timeline entry = %q, want it to say the verified fix did not hold", why)
	}
	found := false
	for _, n := range r.notes.list {
		if strings.HasPrefix(n.title, "Verified fix regressed") {
			found = true
		}
	}
	if !found {
		t.Errorf("notices %v: no \"Verified fix regressed\" announcement", r.notes.list)
	}
}

// 3. A scan that is not a coverage proof never closes a finding, so the next
// sighting is just a sighting.
func TestRegressionSemantics_NoCoverageProofNoAutoResolve(t *testing.T) {
	r := newRegRig(t)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	r.scan(t, "partial", anchorFinding())
	if got := r.row(t, lodashRule); got.status != "new" || got.has("auto_resolved") {
		t.Fatalf("partial scan without it: %s, want it left open", got)
	}
	// Another tool's full scan is no proof about this tool's finding either.
	r.fullScan(t, "grype", anchorFinding())
	if got := r.row(t, lodashRule); got.status != "new" {
		t.Fatalf("other tool's full scan without it: %s, want it left open", got)
	}
	// A run that did not complete cleanly is no proof.
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "trivy"},
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC(), CoverageType: "full",
			Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + r.tn.repo}},
		Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: r.tn.repo}},
		Findings: []ctis.Finding{func() ctis.Finding { f := anchorFinding(); f.AssetRef = "repo"; return f }()}}
	cmd := r.r.runCommand(r.tn, "trivy", "", "failed", 1)
	r.r.sendWhole(r.tn, r.r.openAs(r.tn, shared.NewID().String(), "worker", &cmd, rep), rep)
	if got := r.row(t, lodashRule); got.status != "new" {
		t.Fatalf("failed run without it: %s, want it left open", got)
	}

	r.scan(t, "full", lodashFinding(), anchorFinding())
	got := r.row(t, lodashRule)
	if got.rows != 1 || got.isRegr || got.reopenCount != 0 || got.status != "new" {
		t.Fatalf("seen again after non-proof scans: %s, want a plain sighting", got)
	}
	if r.notes.count("finding_reopened") != 0 {
		t.Errorf("a sighting was announced as a regression")
	}
}

// 4. Deliberate dispositions are not reopened by detection; an accepted risk
// whose end has passed returns to confirmed (D8).
func TestRegressionSemantics_DispositionsStayUnlessAcceptanceEnds(t *testing.T) {
	r := newRegRig(t)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	r.exec(t, `UPDATE findings SET status='false_positive', last_seen_at = NOW() - interval '5 days' WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), lodashRule)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	var seen time.Time
	if err := r.r.db.QueryRow(`SELECT last_seen_at FROM findings WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), lodashRule).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	got := r.row(t, lodashRule)
	if got.status != "false_positive" || got.isRegr || time.Since(seen) > time.Minute {
		t.Fatalf("false positive seen again: %s last_seen age %v, want it kept and seen just now", got, time.Since(seen))
	}
	// ...and a scan that no longer reports it does not resolve it.
	r.scan(t, "full", anchorFinding())
	if got := r.row(t, lodashRule); got.status != "false_positive" {
		t.Fatalf("false positive after a scan without it: %s", got)
	}

	// Accepted risk within its end: kept.
	r = newRegRig(t)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	r.exec(t, `UPDATE findings SET status='accepted', resolved_at = NOW(), acceptance_expires_at = NOW() + interval '30 days' WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), lodashRule)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	if got := r.row(t, lodashRule); got.status != "accepted" || got.isRegr {
		t.Fatalf("accepted risk within its end, seen again: %s, want it kept", got)
	}

	// Its end passes: the expiry returns it to confirmed (not a regression).
	requester, approver := shared.NewID(), shared.NewID()
	for _, u := range []shared.ID{requester, approver} {
		r.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'reg')`, u.String(), u.String()+"@example.com")
		uid := u
		t.Cleanup(func() { _, _ = r.r.db.Exec(`DELETE FROM users WHERE id = $1`, uid.String()) })
	}
	ended := time.Now().Add(-time.Hour)
	r.exec(t, `UPDATE findings SET acceptance_expires_at = $3, resolved_at = NOW() - interval '30 days' WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), lodashRule, ended)
	r.exec(t, `INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, requested_by, justification, approved_by, approved_at, status, expires_at)
		SELECT $3, tenant_id, id, 'accepted', $4, 'risk ok', $5, NOW() - interval '30 days', 'approved', $6 FROM findings WHERE tenant_id=$1 AND rule_id=$2`,
		r.tn.tenant.String(), lodashRule, shared.NewID().String(), requester.String(), approver.String(), ended)
	exp := controller.NewApprovalExpirationController(postgres.NewFindingAcceptanceExpiryRepository(&postgres.DB{DB: r.r.db}), fixedSLA{}, nil)
	if _, err := exp.Reconcile(context.Background()); err != nil {
		t.Fatalf("expiry: %v", err)
	}
	if got := r.row(t, lodashRule); got.status != "confirmed" || got.isRegr {
		t.Fatalf("accepted risk past its end: %s, want confirmed and not a regression", got)
	}
}

// 5. A duplicate is never reopened; seeing it again is a sighting of the
// finding it was folded into, which is kept open (not auto-resolved) and
// reopens when it had been closed.
func TestRegressionSemantics_DuplicateSightingGoesToTheTarget(t *testing.T) {
	r := newRegRig(t)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	r.exec(t, `UPDATE findings SET status='duplicate', duplicate_of=(SELECT id FROM findings WHERE tenant_id=$1 AND rule_id='anchor-1')
		WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), lodashRule)

	// Only the duplicate is reported: the target is seen through it.
	r.scan(t, "full", lodashFinding())
	if got := r.row(t, "anchor-1"); got.status != "new" {
		t.Fatalf("target after a scan that reported only its duplicate: %s, want it still open", got)
	}
	if got := r.row(t, lodashRule); got.status != "duplicate" || got.isRegr {
		t.Fatalf("duplicate seen again: %s, want it left a duplicate", got)
	}

	// The target was closed long ago: seeing the duplicate reopens the target.
	r.exec(t, `UPDATE findings SET status='resolved', resolution='auto_fixed', closure_reason='fixed', verification='covered_scan', resolved_at = NOW() - interval '10 days'
		WHERE tenant_id=$1 AND rule_id='anchor-1'`, r.tn.tenant.String())
	r.scan(t, "full", lodashFinding())
	target := r.row(t, "anchor-1")
	if target.status == "resolved" || !target.isRegr || target.reopenCount != 1 {
		t.Fatalf("closed target after its duplicate was seen: %s, want a regression", target)
	}
	if got := r.row(t, lodashRule); got.status != "duplicate" || got.has("auto_reopened") {
		t.Fatalf("duplicate after that scan: %s, want it left a duplicate", got)
	}
}

// 6. A person's Undo is not a regression: see TestRegression_UndoIsNotARegression
// (finding_undo_not_regression_test.go).

// 7. A SAST finding whose code moved keeps one record when the report carries
// the code (identity by content); with only a line it is a new finding and the
// old one closes (RFC-043 known limit), and a renamed rule is a different
// finding.
func TestRegressionSemantics_IdentityAcrossAMove(t *testing.T) {
	r := newRegRig(t)
	withCode := func(line int) ctis.Finding {
		f := anchorFinding()
		f.Location = &ctis.FindingLocation{Path: "a.go", StartLine: line, EndLine: line, Snippet: "exec(userInput)"}
		return f
	}
	r.scan(t, "full", withCode(1))
	r.scan(t, "full", withCode(9))
	var n int
	if err := r.r.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id=$1 AND status NOT IN ('resolved','false_positive','accepted','duplicate')`, r.tn.tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	var all int
	_ = r.r.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id=$1`, r.tn.tenant.String()).Scan(&all)
	t.Logf("code carried, line moved 1 -> 9: %d record(s), %d open", all, n)
	if all != 1 || n != 1 {
		t.Errorf("a line move with the code carried made %d record(s), %d open; want 1 and 1", all, n)
	}
}

// 8. Flapping: found / not found alternately within days reopens the finding
// each time but is not counted as a regression (no counter, no new SLA clock,
// no announcement). Once the automatic close has lasted the window, or a
// person closed it, the next sighting is a regression.
func TestRegressionSemantics_FlappingIsNotRegressionSpam(t *testing.T) {
	r := newRegRig(t)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	for i := 0; i < 3; i++ {
		r.scan(t, "full", anchorFinding())
		r.scan(t, "full", lodashFinding(), anchorFinding())
	}
	got := r.row(t, lodashRule)
	if got.rows != 1 || got.status != "new" || got.isRegr || got.reopenCount != 0 || got.lastReopen.Valid {
		t.Fatalf("after 3 flaps: %s, want one open record, no regression", got)
	}
	if got.has("sla_restarted") || r.notes.count("finding_reopened") != 0 {
		t.Fatalf("flaps restarted the SLA or announced: %s, notices %v", got, r.notes.list)
	}
	if why := r.lastReopenReason(t, lodashRule); !strings.Contains(why, "seen_again") {
		t.Errorf("timeline entry = %q, want seen_again", why)
	}

	// A person who closed it and sees it back within days: a failed fix.
	person := shared.NewID()
	r.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'reg')`, person.String(), person.String()+"@example.com")
	t.Cleanup(func() { _, _ = r.r.db.Exec(`DELETE FROM users WHERE id = $1`, person.String()) })
	r.scan(t, "full", anchorFinding())
	r.exec(t, `UPDATE findings SET resolved_by = $3 WHERE tenant_id=$1 AND rule_id=$2`, r.tn.tenant.String(), lodashRule, person.String())
	r.scan(t, "full", lodashFinding(), anchorFinding())
	if got := r.row(t, lodashRule); !got.isRegr || got.reopenCount != 1 {
		t.Fatalf("person-closed finding seen again within days: %s, want a regression", got)
	}

	// An automatic close that lasted the window.
	r.scan(t, "full", anchorFinding())
	r.agedOut(t, lodashRule)
	r.scan(t, "full", lodashFinding(), anchorFinding())
	if got := r.row(t, lodashRule); got.reopenCount != 2 {
		t.Fatalf("aged automatic close seen again: %s, want reopen_count 2", got)
	}
}
