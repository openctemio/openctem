package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	threatalertapp "github.com/openctemio/openctem/api/internal/app/threatalert"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatalert"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingOutbox struct {
	mu      sync.Mutex
	entries []outbox.EnqueueParams
}

func (o *recordingOutbox) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.entries = append(o.entries, p)
	return nil
}

// count returns the entries of one organization and event type, and how
// many of them are summaries.
func (o *recordingOutbox) count(tenant shared.ID, eventType string) (n, summaries int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, e := range o.entries {
		if e.TenantID == tenant && e.EventType == eventType {
			n++
			if s, _ := e.Metadata["summary"].(bool); s {
				summaries++
			}
		}
	}
	return n, summaries
}

func (o *recordingOutbox) all(tenant shared.ID) []outbox.EnqueueParams {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []outbox.EnqueueParams
	for _, e := range o.entries {
		if e.TenantID == tenant {
			out = append(out, e)
		}
	}
	return out
}

// Emerging-threat alerts end to end on a scratch database (RFC-117): a new
// organization gets a baseline and no page; a two-week-old KEV CVE on a
// newly found internet-facing asset pages; a burst of KEV additions sends
// five messages and one summary; nothing is sent twice; quiet hours hold
// and bundle (the override still pages); the digest goes once a day; one
// organization never sees another's alert; an out-of-scope member sees only
// in-scope assets and cannot suppress; a rejection resolves; the per-finding
// KEV escalation is covered by the alert. Requires DATABASE_URL.
//
//nolint:gocyclo,cyclop,maintidx // one scenario, step by step
func TestThreatAlerts_DB(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	reset := `DELETE FROM threat_alert_queue; DELETE FROM threat_alerts; DELETE FROM threat_alert_tenant_state;
		DELETE FROM vuln_events WHERE vuln_id LIKE 'CVE-2098-%'; DELETE FROM vuln_event_cursors WHERE name = 'planner';
		DELETE FROM kev_catalog WHERE cve_id LIKE 'CVE-2098-%'; DELETE FROM cve_records WHERE cve_id LIKE 'CVE-2098-%'`
	mustExec(t, db, reset)
	t.Cleanup(func() { _, _ = db.Exec(reset) })

	A, B, C, D := seedBatchTenant(t, db), seedBatchTenant(t, db), seedBatchTenant(t, db), seedBatchTenant(t, db)
	// Every other organization of the shared test database counts as
	// baselined, so the planner's baseline sweep reaches these four.
	mustExec(t, db, `INSERT INTO threat_alert_tenant_state (tenant_id, baseline_at)
		SELECT id, now() FROM tenants WHERE id NOT IN ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, A.String(), B.String(), C.String(), D.String())

	asset := func(tenant shared.ID, name, exposure, criticality string) shared.ID {
		t.Helper()
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'host', $4, $5)`,
			id.String(), tenant.String(), name, exposure, criticality)
		return id
	}
	finding := func(tenant, assetID shared.ID, cve string, confidence int) shared.ID {
		t.Helper()
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id, confidence)
			VALUES ($1, $2, $3, 'sca', 'test', 'm', 'critical', $4, 'new', $5, $6)`,
			id.String(), tenant.String(), assetID.String(), shared.NewID().String(), cve, confidence)
		return id
	}
	cve := func(id, severity, vector string) {
		t.Helper()
		mustExec(t, db, `INSERT INTO cve_records (cve_id, status, severity, cvss_vector, published_at) VALUES ($1, 'Analyzed', $2, NULLIF($3, ''), now())`,
			id, severity, vector)
	}
	kev := func(id string, added time.Time, ransomware bool) {
		t.Helper()
		use := "Unknown"
		if ransomware {
			use = "Known"
		}
		mustExec(t, db, `INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, known_ransomware_campaign_use) VALUES ($1, 'x', $2::date, $3)`,
			id, added, use)
	}
	event := func(id, kind string, at time.Time) {
		t.Helper()
		mustExec(t, db, `INSERT INTO vuln_events (vuln_id, kind, at) VALUES ($1, $2, $3)`, id, kind, at)
	}

	now := time.Now().UTC()
	clock := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.UTC)
	repo := NewThreatAlertRepository(pdb)
	box := &recordingOutbox{}
	planner := threatalertapp.NewPlanner(repo, NewTenantRepository(pdb), logger.NewNop())
	planner.SetSinks(box, nil, nil, nil, nil, "https://console.example.com")
	threatalertapp.SetClockForTest(planner, func() time.Time { return clock })
	run := func() threatalertapp.Stats {
		t.Helper()
		st, err := planner.Run(ctx, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// --- 1. A new organization: baseline only, no page --------------------
	a1 := asset(A, "edge-1.example.com", "public", "critical")
	a2 := asset(A, "internal-2.example.com", "private", "medium")
	b1 := asset(B, "b-host.example.com", "public", "high")
	cve("CVE-2098-0001", "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	kev("CVE-2098-0001", clock, true)
	event("CVE-2098-0001", "kev_added", clock.Add(-time.Hour))
	fA1 := finding(A, a1, "CVE-2098-0001", 100)
	finding(A, a2, "CVE-2098-0001", 70) // likely
	fB := finding(B, b1, "CVE-2098-0099", 100)

	if st := run(); st.Baselined < 4 {
		t.Fatalf("baselined %d organizations, want the 4 new ones", st.Baselined)
	}
	if n, _ := box.count(A, "emerging_threat"); n != 0 {
		t.Fatalf("baseline paged: %d immediate messages", n)
	}
	alertA, err := repo.AlertByVuln(ctx, A, "CVE-2098-0001")
	if err != nil || alertA == nil {
		t.Fatalf("baseline alert: %v %v", alertA, err)
	}
	if alertA.Level != threatalert.LevelImmediate || alertA.Tier != threatalert.TierConfirmed || !alertA.Baseline ||
		alertA.Confirmed != 2 || alertA.InternetFacing != 1 || alertA.ETS < 90 {
		t.Fatalf("baseline alert = %+v", alertA)
	}
	if st, _ := repo.TenantState(ctx, A); st.BaselineAt == nil || st.LastDigestOn == "" {
		// The digest ran in the same pass (12:00 is after 08:00).
		t.Fatalf("tenant state after baseline: %+v", st)
	}
	if n, _ := box.count(A, "emerging_threat_digest"); n != 1 {
		t.Fatalf("baseline digest: %d", n)
	}
	for _, e := range box.all(A) {
		if e.EventType == "emerging_threat_digest" && e.Title == "" {
			t.Fatal("digest without a title")
		}
	}
	if b, _ := repo.AlertByVuln(ctx, B, "CVE-2098-0001"); b != nil {
		t.Fatal("organization B got an alert for a CVE it does not run")
	}
	// A second pass the same day: no second digest, nothing sent.
	run()
	if n, _ := box.count(A, "emerging_threat_digest"); n != 1 {
		t.Fatalf("second digest the same day: %d", n)
	}

	// --- 2. A two-week-old KEV CVE on a newly found internet-facing asset
	cve("CVE-2098-0002", "high", "")
	kev("CVE-2098-0002", clock.Add(-14*24*time.Hour), false)
	event("CVE-2098-0002", "kev_added", clock.Add(-14*24*time.Hour))
	run() // the event is older than the cursor's start: nothing for nobody yet
	a3 := asset(A, "new-edge.example.com", "public", "high")
	finding(A, a3, "CVE-2098-0002", 100)
	if err := planner.QueueVulns(ctx, A, []string{"CVE-2098-0002"}); err != nil {
		t.Fatal(err)
	}
	run()
	if n, _ := box.count(A, "emerging_threat"); n != 1 {
		t.Fatalf("new asset on a KEV CVE: %d immediate messages, want 1", n)
	}
	for _, e := range box.all(A) {
		if e.EventType == "emerging_threat" && (e.Severity != "critical" || e.URL == "" || strings.Contains(e.Body, "new-edge.example.com")) {
			t.Fatalf("immediate message: %+v (asset names are off by default)", e)
		}
	}
	run()
	if n, _ := box.count(A, "emerging_threat"); n != 1 {
		t.Fatalf("re-plan sent again: %d", n)
	}

	// --- 3. Storm cap: seven KEV additions at once ------------------------
	c1 := asset(C, "c-edge.example.com", "public", "high")
	for i := range 7 {
		id := "CVE-2098-001" + string(rune('0'+i))
		cve(id, "critical", "")
		kev(id, clock, false)
		finding(C, c1, id, 100)
		event(id, "kev_added", clock.Add(-time.Hour))
	}
	run()
	n, summaries := box.count(C, "emerging_threat")
	if n != 6 || summaries != 1 {
		t.Fatalf("storm: %d messages (%d summaries), want 5 + 1 summary", n, summaries)
	}
	run()
	if n2, _ := box.count(C, "emerging_threat"); n2 != 6 {
		t.Fatalf("storm re-sent: %d", n2)
	}

	// --- 4. Quiet hours hold and bundle; the override pages ---------------
	mustExec(t, db, `UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'), '{emerging_threats}',
		'{"quiet_hours": {"enabled": true, "start_hour": 10, "end_hour": 14}}') WHERE id = $1`, D.String())
	d1 := asset(D, "d-edge.example.com", "public", "medium")
	d2 := asset(D, "d-crown.example.com", "public", "critical")
	for _, id := range []string{"CVE-2098-0021", "CVE-2098-0022"} {
		cve(id, "high", "")
		kev(id, clock, false)
		finding(D, d1, id, 100)
		event(id, "kev_added", clock.Add(-time.Hour))
	}
	cve("CVE-2098-0023", "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	kev("CVE-2098-0023", clock, true)
	finding(D, d2, "CVE-2098-0023", 100)
	event("CVE-2098-0023", "kev_added", clock.Add(-time.Hour))
	planner2 := threatalertapp.NewPlanner(repo, NewTenantRepository(pdb), logger.NewNop())
	planner2.SetSinks(box, nil, nil, nil, nil, "")
	threatalertapp.SetClockForTest(planner2, func() time.Time { return clock })
	if _, err := planner2.Run(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, s := box.count(D, "emerging_threat"); n != 1 || s != 0 {
		t.Fatalf("quiet hours: %d messages (%d summaries), want only the override alert", n, s)
	}
	clock = clock.Add(3 * time.Hour) // 15:00, the window ended
	run()
	if n, s := box.count(D, "emerging_threat"); n != 2 || s != 1 {
		t.Fatalf("after quiet hours: %d messages (%d summaries), want one bundle", n, s)
	}

	// --- 5. Isolation: another organization never sees the alert ----------
	svc := threatalertapp.NewService(repo, nil, logger.NewNop())
	items, total, _, err := svc.List(ctx, B, nil, threatalert.ListFilter{Page: 1, PerPage: 50})
	if err != nil || total != 0 || len(items) != 0 {
		t.Fatalf("organization B lists %d alerts (%v)", total, err)
	}
	if _, err := svc.Get(ctx, B, nil, alertA.ID); !errors.Is(err, threatalert.ErrNotFound) {
		t.Fatalf("organization B got A's alert: %v", err)
	}
	if _, err := svc.ChangeState(ctx, B, nil, alertA.ID, threatalertapp.StateChange{State: threatalert.StateAcknowledged, Actor: shared.NewID()},
		auditapp.AuditContext{}); !errors.Is(err, threatalert.ErrNotFound) {
		t.Fatalf("organization B triaged A's alert: %v", err)
	}
	if err := repo.SetState(ctx, B, alertA.ID, threatalert.StateNotAffected, "wrong_product", "", shared.NewID(), clock, nil); !errors.Is(err, threatalert.ErrNotFound) {
		t.Fatalf("a write with another organization changed the alert: %v", err)
	}

	// --- 6. Data scope: a member who sees only the internal asset ---------
	user := seedGroupsUser(ctx, t, db, "emerging-scope.test")
	mustExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		user.String(), A.String(), a2.String())
	scope := &shared.DataScope{TenantID: A, UserID: user}
	items, total, sum, err := svc.List(ctx, A, scope, threatalert.ListFilter{Page: 1, PerPage: 50})
	if err != nil || total != 1 || items[0].VulnID != "CVE-2098-0001" || items[0].Confirmed != 1 || items[0].InternetFacing != 0 || sum.InternetFacing != 0 {
		t.Fatalf("scoped list: %d %+v %+v %v", total, items, sum, err)
	}
	d, err := svc.Get(ctx, A, scope, alertA.ID)
	if err != nil || len(d.Assets) != 1 || d.Assets[0].AssetID != a2 || d.AllInScope {
		t.Fatalf("scoped detail: %+v %v", d, err)
	}
	if _, err := svc.ChangeState(ctx, A, scope, alertA.ID, threatalertapp.StateChange{State: threatalert.StateNotAffected, Reason: threatalert.ReasonWrongProduct, Actor: user}, auditapp.AuditContext{}); !errors.Is(err, threatalert.ErrOutOfScope) {
		t.Fatalf("out-of-scope suppression: %v", err)
	}
	// The other alert of A (only on internet-facing assets) is invisible.
	alert2, _ := repo.AlertByVuln(ctx, A, "CVE-2098-0002")
	if _, err := svc.Get(ctx, A, scope, alert2.ID); !errors.Is(err, threatalert.ErrNotFound) {
		t.Fatalf("an alert with no asset in scope was readable: %v", err)
	}
	stranger := seedGroupsUser(ctx, t, db, "emerging-stranger.test")
	if _, total, _, err := svc.List(ctx, A, &shared.DataScope{TenantID: A, UserID: stranger}, threatalert.ListFilter{Page: 1, PerPage: 50}); err != nil || total != 0 {
		t.Fatalf("a member with no scope row sees %d alerts (%v)", total, err)
	}

	// Unrestricted: not affected suppresses; KEV reasons reopen only by a
	// stronger match.
	d, err = svc.ChangeState(ctx, A, nil, alertA.ID, threatalertapp.StateChange{State: threatalert.StateNotAffected,
		Reason: threatalert.ReasonCompensatingControl, Note: "WAF rule", Actor: user}, auditapp.AuditContext{})
	if err != nil || d.Alert.State != threatalert.StateNotAffected || d.Alert.SuppressedUntil == nil {
		t.Fatalf("not affected: %+v %v", d, err)
	}
	if err := planner.QueueVulns(ctx, A, []string{"CVE-2098-0001"}); err != nil {
		t.Fatal(err)
	}
	run()
	if a, _ := repo.AlertByVuln(ctx, A, "CVE-2098-0001"); a.State != threatalert.StateNotAffected {
		t.Fatalf("a re-plan reopened a suppressed alert: %s", a.State)
	}
	if _, err := svc.ChangeState(ctx, A, nil, alertA.ID, threatalertapp.StateChange{State: threatalert.StateNotAffected, Actor: user},
		auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("not affected without a reason: %v", err)
	}

	// --- 7. The per-finding KEV escalation is covered by the alert --------
	mustExec(t, db, `UPDATE threat_alerts SET state = 'new' WHERE tenant_id = $1`, A.String())
	if ok, err := repo.CoveredByAlert(ctx, A, fA1); err != nil || !ok {
		t.Fatalf("covered: %v %v", ok, err)
	}
	if ok, err := repo.CoveredByAlert(ctx, B, fB); err != nil || ok {
		t.Fatalf("B's finding covered: %v %v", ok, err)
	}
	if ok, err := repo.CoveredByAlert(ctx, B, fA1); err != nil || ok {
		t.Fatalf("another organization's finding id answered: %v %v", ok, err)
	}

	// --- 8. A rejection resolves the alert --------------------------------
	event("CVE-2098-0002", "rejected", clock)
	run()
	if a, _ := repo.AlertByVuln(ctx, A, "CVE-2098-0002"); a.State != threatalert.StateResolved || a.StateReason != threatalert.ReasonRejectedUpstream {
		t.Fatalf("rejected: %s %s", a.State, a.StateReason)
	}
	if err := planner.QueueVulns(ctx, A, []string{"CVE-2098-0002"}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `UPDATE cve_records SET status = 'Rejected' WHERE cve_id = 'CVE-2098-0002'`)
	run()
	if a, _ := repo.AlertByVuln(ctx, A, "CVE-2098-0002"); a.State != threatalert.StateResolved {
		t.Fatalf("a re-plan reopened a rejected CVE's alert: %s", a.State)
	}

	// --- 9. Fixed everywhere: the alert resolves --------------------------
	mustExec(t, db, `UPDATE findings SET status = 'resolved' WHERE tenant_id = $1 AND cve_id = 'CVE-2098-0010'`, C.String())
	if err := planner.QueueVulns(ctx, C, []string{"CVE-2098-0010"}); err != nil {
		t.Fatal(err)
	}
	run()
	if a, _ := repo.AlertByVuln(ctx, C, "CVE-2098-0010"); a.State != threatalert.StateResolved || a.StateReason != threatalert.ReasonFixed {
		t.Fatalf("fixed: %s %s", a.State, a.StateReason)
	}
	var orphan sql.NullString
	_ = db.QueryRow(`SELECT tenant_id::text FROM threat_alert_assets WHERE tenant_id NOT IN ($1, $2, $3, $4) LIMIT 1`,
		A.String(), B.String(), C.String(), D.String()).Scan(&orphan)
	if orphan.Valid {
		t.Fatalf("alert assets of an unexpected organization: %s", orphan.String)
	}
}
