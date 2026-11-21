package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	threatalertapp "github.com/openctemio/openctem/server/internal/app/threatalert"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// An alert counts hosts everywhere: a host that serves two ports is one in
// the stored counters, the list, the detail header, the digest and the
// message; likely is its own number; the counts are those of the caller's
// organization and data scope only; one more port of a known host is not
// growth, a new host and a stronger tier are; the start-up backfill turns
// counters stored per asset into host counts without touching anything else.
// Requires DATABASE_URL.
//
//nolint:gocyclo,cyclop,maintidx // one scenario, step by step
func TestThreatAlertHostCounts_DB(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	const vuln = "CVE-2096-0001"
	reset := `DELETE FROM threat_alert_queue; DELETE FROM threat_alerts; DELETE FROM threat_alert_tenant_state;
		DELETE FROM vuln_events WHERE vuln_id LIKE 'CVE-2096-%'; DELETE FROM vuln_event_cursors WHERE name = 'planner';
		DELETE FROM kev_catalog WHERE cve_id LIKE 'CVE-2096-%'; DELETE FROM cve_records WHERE cve_id LIKE 'CVE-2096-%'`
	mustExec(t, db, reset)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), reset) })

	A, B := seedBatchTenant(t, db), seedBatchTenant(t, db)
	mustExec(t, db, `INSERT INTO threat_alert_tenant_state (tenant_id, baseline_at)
		SELECT id, now() FROM tenants FOR KEY SHARE ON CONFLICT DO NOTHING`)

	asset := func(tenant shared.ID, name, exposure, criticality string) shared.ID {
		t.Helper()
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'service', $4, $5)`,
			id.String(), tenant.String(), name, exposure, criticality)
		return id
	}
	finding := func(tenant, assetID shared.ID, confidence int) shared.ID {
		t.Helper()
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id, confidence)
			VALUES ($1, $2, $3, 'sca', 'test', 'm', 'critical', $4, 'new', $5, $6)`,
			id.String(), tenant.String(), assetID.String(), shared.NewID().String(), vuln, confidence)
		return id
	}

	now := time.Now().UTC()
	clock := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.UTC)
	mustExec(t, db, `INSERT INTO cve_records (cve_id, status, severity, cvss_vector, published_at)
		VALUES ($1, 'Analyzed', 'critical', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', now())`, vuln)
	mustExec(t, db, `INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, known_ransomware_campaign_use) VALUES ($1, 'x', $2::date, 'Unknown')`,
		vuln, clock)
	mustExec(t, db, `INSERT INTO vuln_events (vuln_id, kind, at) VALUES ($1, 'kev_added', $2)`, vuln, clock.Add(-time.Hour))

	repo := NewThreatAlertRepository(pdb)
	box := &recordingOutbox{}
	planner := threatalertapp.NewPlanner(repo, NewTenantRepository(pdb), logger.NewNop())
	planner.SetSinks(box, nil, nil, nil, nil, "https://console.example.com")
	threatalertapp.SetClockForTest(planner, func() time.Time { return clock })
	plan := func(tenant shared.ID) *threatalert.Alert {
		t.Helper()
		for _, id := range []shared.ID{A, B} {
			if err := planner.QueueVulns(ctx, id, []string{vuln}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := planner.Run(ctx, time.Minute); err != nil {
			t.Fatal(err)
		}
		a, err := repo.AlertByVuln(ctx, tenant, vuln)
		if err != nil || a == nil {
			t.Fatalf("alert: %v %v", a, err)
		}
		return a
	}
	counts := func(a *threatalert.Alert) [4]int {
		return [4]int{a.Confirmed, a.Likely, a.Possible, a.InternetFacing}
	}

	// --- 1. Stored counters: two ports of one host are one host -----------
	// A: 192.0.2.20 on 80 and 443 (confirmed, public), web-01 (confirmed, a
	// crown jewel, not a URL), example.com on 443 (likely).
	h80 := asset(A, "http://192.0.2.20", "public", "medium")
	h443 := asset(A, "https://192.0.2.20", "public", "medium")
	web := asset(A, "web-01", "private", "critical")
	likely := asset(A, "https://example.com", "private", "medium")
	finding(A, h80, 100)
	finding(A, h443, 100)
	finding(A, web, 100)
	likelyFinding := finding(A, likely, 60)
	// B has the same host name: its own alert, its own count.
	finding(B, asset(B, "https://192.0.2.20", "public", "medium"), 100)

	alertA := plan(A)
	if got, want := counts(alertA), [4]int{2, 1, 0, 1}; got != want {
		t.Fatalf("stored counts (confirmed, likely, possible, internet-facing) = %v, want %v", got, want)
	}
	alertB, err := repo.AlertByVuln(ctx, B, vuln)
	if err != nil || alertB == nil || counts(alertB) != [4]int{1, 0, 0, 1} {
		t.Fatalf("organization B's alert: %+v %v", alertB, err)
	}

	// --- 2. The message says hosts, and likely on its own ------------------
	var body string
	for _, m := range box.all(A) {
		if m.EventType == "emerging_threat" {
			body = m.Body
			if m.Metadata["confirmed"] != 2 || m.Metadata["likely"] != 1 {
				t.Fatalf("message metadata: %v", m.Metadata)
			}
		}
	}
	if !strings.Contains(body, "Affects you: 2 hosts confirmed, 1 likely, 1 internet-facing") {
		t.Fatalf("message body: %q", body)
	}

	// --- 3. List, detail and digest read the same host counts -------------
	svc := threatalertapp.NewService(repo, nil, logger.NewNop())
	listed := func(tenant shared.ID, scope *shared.DataScope) threatalert.Alert {
		t.Helper()
		items, total, _, err := svc.List(ctx, tenant, scope, threatalert.ListFilter{Page: 1, PerPage: 50})
		if err != nil || total != 1 || len(items) != 1 {
			t.Fatalf("list: %d %+v %v", total, items, err)
		}
		return items[0]
	}
	if it := listed(A, nil); counts(&it) != [4]int{2, 1, 0, 1} || it.Critical != 1 {
		t.Fatalf("list counts: %+v", it)
	}
	detail, err := svc.Get(ctx, A, nil, alertA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if counts(&detail.Alert) != [4]int{2, 1, 0, 1} || len(detail.Assets) != 4 || !detail.AllInScope {
		t.Fatalf("detail: %+v, %d assets", detail.Alert, len(detail.Assets))
	}
	// The header numbers are the rows of the page's groups.
	for _, g := range threatalert.GroupByHost(detail.Assets) {
		want := map[threatalert.MatchKind]int{threatalert.MatchConfirmed: detail.Alert.Confirmed,
			threatalert.MatchLikely: detail.Alert.Likely, threatalert.MatchPossible: detail.Alert.Possible}[g.Kind]
		if len(g.Hosts) != want {
			t.Fatalf("group %s has %d host rows, the header says %d", g.Kind, len(g.Hosts), want)
		}
	}
	dg, err := repo.DigestSummary(ctx, A, clock.Add(-24*time.Hour), nil)
	if err != nil || len(dg.Top) != 1 || dg.Top[0].HostCounts().Sentence() != "2 hosts confirmed, 1 likely, 1 internet-facing" {
		t.Fatalf("digest: %+v %v", dg.Top, err)
	}

	// --- 4. Isolation: another organization, a narrower data scope --------
	if it := listed(B, nil); it.ID == alertA.ID || counts(&it) != [4]int{1, 0, 0, 1} || it.Critical != 0 {
		t.Fatalf("organization B's list: %+v", it)
	}
	if _, err := svc.Get(ctx, B, nil, alertA.ID); !errors.Is(err, threatalert.ErrNotFound) {
		t.Fatalf("organization B got A's alert: %v", err)
	}
	if got, err := repo.PlannedAssets(ctx, B, alertA.ID); err != nil || len(got) != 0 {
		t.Fatalf("organization B read A's planned assets: %v %v", got, err)
	}
	// A member who sees one port of the two-port host and nothing else: one
	// confirmed host, no likely one, no crown jewel.
	user := seedGroupsUser(ctx, t, db, "emerging-hosts.test")
	mustExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		user.String(), A.String(), h443.String())
	scope := &shared.DataScope{TenantID: A, UserID: user}
	if it := listed(A, scope); counts(&it) != [4]int{1, 0, 0, 1} || it.Critical != 0 {
		t.Fatalf("scoped list counts hosts out of scope: %+v", it)
	}
	scoped, err := svc.Get(ctx, A, scope, alertA.ID)
	if err != nil || counts(&scoped.Alert) != [4]int{1, 0, 0, 1} || scoped.AllInScope || len(scoped.Assets) != 1 {
		t.Fatalf("scoped detail: %+v %v", scoped, err)
	}
	sdg, err := repo.DigestSummary(ctx, A, clock.Add(-24*time.Hour), scope)
	if err != nil || len(sdg.Top) != 1 || sdg.Top[0].Confirmed != 1 || sdg.Top[0].Likely != 0 {
		t.Fatalf("scoped digest: %+v %v", sdg.Top, err)
	}
	// A member with no scope row sees no alert at all.
	nobody := seedGroupsUser(ctx, t, db, "emerging-hosts-none.test")
	if items, total, _, err := svc.List(ctx, A, &shared.DataScope{TenantID: A, UserID: nobody}, threatalert.ListFilter{Page: 1, PerPage: 50}); err != nil || total != 0 || len(items) != 0 {
		t.Fatalf("a member without scope lists %d alerts (%v)", total, err)
	}

	// --- 5. Growth: a new host or a stronger tier, never one more port ----
	pending := func() bool {
		t.Helper()
		var p bool
		if err := db.QueryRowContext(ctx, `SELECT digest_pending FROM threat_alerts WHERE tenant_id = $1 AND vuln_id = $2`, A.String(), vuln).Scan(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sent := func() {
		t.Helper()
		mustExec(t, db, `UPDATE threat_alerts SET digest_pending = false WHERE tenant_id = $1 AND vuln_id = $2`, A.String(), vuln)
	}
	if n, _ := box.count(A, "emerging_threat"); n != 1 {
		t.Fatalf("immediate messages = %d, want 1", n)
	}
	sent()
	finding(A, asset(A, "http://192.0.2.20:8080", "public", "medium"), 100)
	if a := plan(A); counts(a) != [4]int{2, 1, 0, 1} || pending() {
		t.Fatalf("a third port of a known host: counts %v, digest pending %v; want unchanged and not pending", counts(a), pending())
	}
	finding(A, asset(A, "https://192.0.2.99", "private", "medium"), 100)
	if a := plan(A); counts(a) != [4]int{3, 1, 0, 1} || !pending() {
		t.Fatalf("a new host: counts %v, digest pending %v; want one more confirmed host and pending", counts(a), pending())
	}
	sent()
	mustExec(t, db, `UPDATE findings SET confidence = 95 WHERE id = $1`, likelyFinding.String())
	if a := plan(A); counts(a) != [4]int{4, 0, 0, 1} || !pending() {
		t.Fatalf("likely became confirmed: counts %v, digest pending %v; want 4 confirmed and pending", counts(a), pending())
	}
	if n, _ := box.count(A, "emerging_threat"); n != 1 {
		t.Fatalf("immediate messages after growth = %d, want still 1 (nothing is sent twice)", n)
	}

	// --- 6. Backfill: counters stored per asset become host counts --------
	// As written before hosts were counted: no keys, one count per asset,
	// likely inside confirmed.
	mustExec(t, db, `UPDATE threat_alert_assets SET host_key = ''`)
	mustExec(t, db, `UPDATE threat_alerts SET confirmed_assets = 6, likely_assets = 0, internet_facing_assets = 3 WHERE tenant_id = $1`, A.String())
	if it := listed(A, nil); it.Confirmed != 6 {
		t.Fatalf("a keyless row counts as its own host until backfilled: %+v", it)
	}
	type marks struct {
		updatedAt, notifiedAt                 string
		level, notified, state                string
		ets                                   int
		pending                               bool
		confirmed, likely, possible, internet int
	}
	read := func(tenant shared.ID) marks {
		t.Helper()
		var m marks
		if err := db.QueryRowContext(ctx, `SELECT updated_at::text, COALESCE(notified_at::text, ''), level, notified_level, state, ets, digest_pending,
				confirmed_assets, likely_assets, possible_assets, internet_facing_assets
			FROM threat_alerts WHERE tenant_id = $1 AND vuln_id = $2`, tenant.String(), vuln).
			Scan(&m.updatedAt, &m.notifiedAt, &m.level, &m.notified, &m.state, &m.ets, &m.pending,
				&m.confirmed, &m.likely, &m.possible, &m.internet); err != nil {
			t.Fatal(err)
		}
		return m
	}
	before := read(A)
	n, err := BackfillThreatAlertHosts(ctx, db)
	if err != nil || n != 2 {
		t.Fatalf("backfill updated %d alerts (%v), want 2 (A's and B's)", n, err)
	}
	after := read(A)
	want := before
	want.confirmed, want.likely, want.possible, want.internet = 4, 0, 0, 1
	if after != want {
		t.Fatalf("after the backfill %+v, want %+v (only the counters change)", after, want)
	}
	if b := read(B); b.confirmed != 1 || b.internet != 1 {
		t.Fatalf("organization B after the backfill: %+v", b)
	}
	var keyless int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM threat_alert_assets WHERE host_key = ''`).Scan(&keyless); err != nil || keyless != 0 {
		t.Fatalf("%d alert assets without a host key after the backfill (%v)", keyless, err)
	}
	var key string
	if err := db.QueryRowContext(ctx, `SELECT host_key FROM threat_alert_assets WHERE tenant_id = $1 AND asset_id = $2`, A.String(), h80.String()).Scan(&key); err != nil || key != "h:192.0.2.20" {
		t.Fatalf("host key of http://192.0.2.20 = %q (%v)", key, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT host_key FROM threat_alert_assets WHERE tenant_id = $1 AND asset_id = $2`, A.String(), web.String()).Scan(&key); err != nil || key != "a:"+web.String() {
		t.Fatalf("host key of web-01 = %q (%v)", key, err)
	}
	if it := listed(A, nil); counts(&it) != [4]int{4, 0, 0, 1} {
		t.Fatalf("list after the backfill: %+v", it)
	}
	if n, err := BackfillThreatAlertHosts(ctx, db); err != nil || n != 0 {
		t.Fatalf("a second backfill updated %d alerts (%v), want 0", n, err)
	}
	if n, _ := box.count(A, "emerging_threat"); n != 1 {
		t.Fatalf("the backfill sent a message: %d immediate messages", n)
	}
}
