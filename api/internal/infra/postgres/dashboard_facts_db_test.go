package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The dashboard fact layer (migration dashboard_fact_tables): facts equal
// direct queries over findings for every stored dimension, are per tenant,
// and every write path marks the changed (tenant, asset) dirty.

type factFinding struct {
	asset       *shared.ID
	severity    string
	priority    string // "" = unclassified
	status      string
	slaStatus   string
	slaDeadline string // interval from now, "" = none
	source      string
	campaign    *shared.ID
	kev         bool
	reachable   bool
	branchOnly  bool
	epss        string // "" = NULL
	detectedAgo string // interval
	resolvedAgo string // "" = NULL
	reopenedAgo string // "" = NULL
	createdAgo  string
	duplicateOf *shared.ID
}

func seedFactFinding(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, f factFinding) shared.ID {
	t.Helper()
	id := shared.NewID()
	var asset, campaign, prio, epss, deadline, resolved, reopened, dup any
	if f.duplicateOf != nil {
		dup = f.duplicateOf.String()
	}
	if f.asset != nil {
		asset = f.asset.String()
	}
	if f.campaign != nil {
		campaign = f.campaign.String()
	}
	if f.priority != "" {
		prio = f.priority
	}
	if f.epss != "" {
		epss = f.epss
	}
	if f.slaDeadline != "" {
		deadline = f.slaDeadline
	}
	if f.resolvedAgo != "" {
		resolved = f.resolvedAgo
	}
	if f.reopenedAgo != "" {
		reopened = f.reopenedAgo
	}
	created := f.createdAgo
	if created == "" {
		created = f.detectedAgo
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
			priority_class, sla_status, sla_deadline, pentest_campaign_id, is_in_kev, is_reachable, branch_only,
			epss_score, first_detected_at, created_at, resolved_at, last_reopened_at, duplicate_of)
		VALUES ($1, $2, $3, $4, 'test', 'msg', $5, $6, $7, $8, $9, now() + $10::interval, $11, $12, $13, $14,
			$15::numeric, now() - $16::interval, now() - $17::interval, now() - $18::interval, now() - $19::interval, $20)`,
		id.String(), tenant.String(), asset, f.source, f.severity, id.String(), f.status,
		prio, f.slaStatus, deadline, campaign, f.kev, f.reachable, f.branchOnly,
		epss, f.detectedAgo, created, resolved, reopened, dup); err != nil {
		t.Fatalf("seed finding %+v: %v", f, err)
	}
	return id
}

func seedFactCampaign(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ($1, $2, 'facts campaign')`,
		id.String(), tenant.String()); err != nil {
		t.Fatalf("seed campaign: %v", err)
	}
	return id
}

// seedFactMatrix writes findings across every dimension the facts store,
// plus rows the facts must leave out (draft, in_review, branch-only).
func seedFactMatrix(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, assets []shared.ID, campaign shared.ID) {
	t.Helper()
	severities := []string{"critical", "high", "medium", "low", "info"}
	priorities := []string{"P0", "P1", "P2", "P3", ""}
	statuses := []string{"new", "confirmed", "in_progress", "fix_applied", "resolved", "false_positive",
		"accepted", "duplicate", "draft", "in_review"}
	slas := []string{"on_track", "warning", "overdue", "exceeded", "not_applicable"}
	ages := []string{"2 days", "40 days", "75 days", "200 days"}
	sources := []string{"sast", "dast", "pentest", "pentest", "sca"}
	var first *shared.ID
	for i := 0; i < 160; i++ {
		var asset *shared.ID
		if i%9 != 8 { // every ninth finding has no asset
			a := assets[i%len(assets)]
			asset = &a
		}
		status := statuses[i%len(statuses)]
		src := sources[i%len(sources)]
		var camp *shared.ID
		if src == "pentest" && i%4 != 0 { // some pentest findings have no campaign
			camp = &campaign
		}
		f := factFinding{
			asset: asset, severity: severities[i%len(severities)], priority: priorities[(i/2)%len(priorities)],
			status: status, slaStatus: slas[(i/3)%len(slas)], source: src, campaign: camp,
			kev: i%3 == 0, reachable: i%4 == 1, branchOnly: i%17 == 5,
			detectedAgo: ages[(i/5)%len(ages)],
		}
		if status == "duplicate" {
			f.duplicateOf = first
		}
		if i%2 == 0 {
			f.epss = fmt.Sprintf("0.%05d", (i*37)%99999)
		}
		if i%3 != 2 {
			f.slaDeadline = fmt.Sprintf("%d days", (i%21)-10)
		}
		switch status {
		case "resolved", "false_positive", "accepted", "duplicate":
			if i%7 != 3 { // some closed findings have no close date
				f.resolvedAgo = fmt.Sprintf("%d hours", i%48)
			}
		}
		if i%11 == 4 {
			f.reopenedAgo = "1 day"
		}
		id := seedFactFinding(ctx, t, db, tenant, f)
		if first == nil {
			first = &id
		}
	}
}

func lensSQL(column string) string {
	q := func(sts []vulnerability.FindingStatus) string {
		parts := make([]string, len(sts))
		for i, s := range sts {
			parts[i] = "'" + string(s) + "'"
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf(`CASE WHEN %[1]s IN (%[2]s) THEN 'open' WHEN %[1]s IN (%[3]s) THEN 'fixed' WHEN %[1]s IN (%[4]s) THEN 'dispositioned' END`,
		column, q(vulnerability.OpenStatuses()), q(vulnerability.FixedStatuses()), q(vulnerability.DispositionedStatuses()))
}

// directStateSQL is F1 written independently of the dash_* helpers, from the
// Go lens sets, for tenant $1.
func directStateSQL() string {
	return `
		SELECT COALESCE(f.asset_id, '00000000-0000-0000-0000-000000000000'::uuid) AS asset_id,
		       ` + lensSQL("f.status") + ` AS lens, f.severity,
		       COALESCE(f.priority_class, 'none') AS priority_class,
		       CASE WHEN f.sla_status = 'on_track' THEN 'ok' WHEN f.sla_status = 'warning' THEN 'warning'
		            WHEN f.sla_status IN ('overdue', 'exceeded') THEN 'breached' ELSE 'none' END AS sla_state,
		       f.source, COALESCE(f.is_in_kev, false) AS kev, COALESCE(f.is_reachable, false) AS reachable,
		       CASE WHEN f.status NOT IN ('new', 'confirmed', 'in_progress', 'fix_applied') THEN 'na'
		            WHEN now() - COALESCE(f.first_detected_at, f.created_at) < interval '31 days' THEN '0-30'
		            WHEN now() - COALESCE(f.first_detected_at, f.created_at) < interval '61 days' THEN '31-60'
		            WHEN now() - COALESCE(f.first_detected_at, f.created_at) < interval '91 days' THEN '61-90'
		            ELSE '90+' END AS age_band,
		       CASE WHEN f.source = 'pentest' THEN COALESCE(f.pentest_campaign_id, '00000000-0000-0000-0000-000000000000'::uuid)
		            ELSE '00000000-0000-0000-0000-000000000000'::uuid END AS campaign,
		       count(*)::integer AS finding_count, COALESCE(sum(f.epss_score), 0)::numeric(14,5) AS epss_sum
		FROM findings f
		WHERE f.tenant_id = $1 AND NOT f.branch_only AND ` + lensSQL("f.status") + ` IS NOT NULL
		GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10`
}

const factStateSQL = `
		SELECT asset_id, lens, severity, priority_class, sla_state, source, kev, reachable, age_band,
		       pentest_campaign_id, finding_count, epss_sum
		FROM dash_asset_state WHERE tenant_id = $1`

// symmetricDiff returns how many rows are in one query and not the other.
func symmetricDiff(ctx context.Context, t *testing.T, db *sql.DB, a, b string, args ...any) int {
	t.Helper()
	var n int
	q := fmt.Sprintf(`SELECT (SELECT count(*) FROM ((%[1]s) EXCEPT ALL (%[2]s)) x) + (SELECT count(*) FROM ((%[2]s) EXCEPT ALL (%[1]s)) y)`, a, b)
	if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		t.Fatalf("compare: %v", err)
	}
	return n
}

func TestDashboardFacts_EqualDirectQueries_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardFactsRepository(&DB{DB: db})

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	assets := []shared.ID{seedOwnedAsset(ctx, t, db, tenant, nil), seedOwnedAsset(ctx, t, db, tenant, nil),
		seedOwnedAsset(ctx, t, db, tenant, nil)}
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)
	seedFactMatrix(ctx, t, db, tenant, assets, seedFactCampaign(ctx, t, db, tenant))
	seedFactMatrix(ctx, t, db, other, []shared.ID{otherAsset}, seedFactCampaign(ctx, t, db, other))

	if _, err := repo.RebuildTenant(ctx, tenant, 2); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	t.Run("F1 equals findings for every dimension", func(t *testing.T) {
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("F1 differs from a direct query over findings in %d rows", d)
		}
		var stored, published, drafts int
		_ = db.QueryRowContext(ctx, `SELECT COALESCE(sum(finding_count), 0) FROM dash_asset_state WHERE tenant_id = $1`, tenant.String()).Scan(&stored)
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND NOT branch_only
			AND status NOT IN ('draft', 'in_review')`, tenant.String()).Scan(&published)
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status IN ('draft', 'in_review')`, tenant.String()).Scan(&drafts)
		if stored != published || drafts == 0 {
			t.Fatalf("stored %d facts for %d published findings (drafts seeded: %d)", stored, published, drafts)
		}
		var pentestWithCampaign int
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM dash_asset_state WHERE tenant_id = $1 AND source = 'pentest'
			AND pentest_campaign_id <> '00000000-0000-0000-0000-000000000000'`, tenant.String()).Scan(&pentestWithCampaign)
		if pentestWithCampaign == 0 {
			t.Fatal("pentest facts must carry their campaign id")
		}
		var nonPentestCampaign int
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM dash_asset_state WHERE tenant_id = $1 AND source <> 'pentest'
			AND pentest_campaign_id <> '00000000-0000-0000-0000-000000000000'`, tenant.String()).Scan(&nonPentestCampaign)
		if nonPentestCampaign != 0 {
			t.Fatalf("%d non-pentest facts carry a campaign id", nonPentestCampaign)
		}
	})

	t.Run("F1 headline numbers per dimension", func(t *testing.T) {
		for _, dim := range []string{"severity", "priority_class", "sla_state", "source", "kev", "reachable", "age_band", "lens"} {
			facts := `SELECT ` + dim + `::text, sum(finding_count)::bigint FROM dash_asset_state WHERE tenant_id = $1 GROUP BY 1`
			direct := `SELECT ` + dim + `::text, sum(finding_count)::bigint FROM (` + directStateSQL() + `) d GROUP BY 1`
			if d := symmetricDiff(ctx, t, db, facts, direct, tenant.String()); d != 0 {
				t.Errorf("totals by %s differ in %d buckets", dim, d)
			}
		}
		var overdueFacts, overdueDirect int
		_ = db.QueryRowContext(ctx, `SELECT COALESCE(sum(finding_count), 0) FROM dash_asset_state
			WHERE tenant_id = $1 AND lens = 'open' AND sla_state = 'breached'`, tenant.String()).Scan(&overdueFacts)
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND NOT branch_only
			AND `+vulnerability.OpenStatusSQL("status")+` AND sla_status IN ('overdue', 'exceeded')`, tenant.String()).Scan(&overdueDirect)
		if overdueFacts != overdueDirect || overdueDirect == 0 {
			t.Fatalf("open SLA breaches: facts %d, findings %d", overdueFacts, overdueDirect)
		}
	})

	t.Run("F2 per-day events equal finding timestamps", func(t *testing.T) {
		day := func(col string) string { return `(` + col + ` AT TIME ZONE 'UTC')::date` }
		key := `COALESCE(asset_id, '00000000-0000-0000-0000-000000000000'::uuid), severity, COALESCE(priority_class, 'none')`
		base := `FROM findings WHERE tenant_id = $1 AND NOT branch_only AND status NOT IN ('draft', 'in_review')`
		checks := map[string][2]string{
			"opened": {`SELECT asset_id, severity, priority_class, day, opened FROM dash_asset_day WHERE tenant_id = $1 AND opened <> 0`,
				`SELECT ` + key + `, ` + day("COALESCE(first_detected_at, created_at)") + `, count(*)::int ` + base + ` GROUP BY 1, 2, 3, 4`},
			"fixed": {`SELECT asset_id, severity, priority_class, day, fixed FROM dash_asset_day WHERE tenant_id = $1 AND fixed <> 0`,
				`SELECT ` + key + `, ` + day("resolved_at") + `, count(*)::int ` + base + ` AND status = 'resolved' AND resolved_at IS NOT NULL GROUP BY 1, 2, 3, 4`},
			"dispositioned": {`SELECT asset_id, severity, priority_class, day, dispositioned FROM dash_asset_day WHERE tenant_id = $1 AND dispositioned <> 0`,
				`SELECT ` + key + `, ` + day("resolved_at") + `, count(*)::int ` + base + ` AND status IN ('false_positive', 'accepted', 'duplicate') AND resolved_at IS NOT NULL GROUP BY 1, 2, 3, 4`},
			"reopened": {`SELECT asset_id, severity, priority_class, day, reopened FROM dash_asset_day WHERE tenant_id = $1 AND reopened <> 0`,
				`SELECT ` + key + `, ` + day("last_reopened_at") + `, count(*)::int ` + base + ` AND last_reopened_at IS NOT NULL GROUP BY 1, 2, 3, 4`},
			"fixed within SLA": {`SELECT asset_id, severity, priority_class, day, fixed_within_sla FROM dash_asset_day WHERE tenant_id = $1 AND fixed_within_sla <> 0`,
				`SELECT ` + key + `, ` + day("resolved_at") + `, count(*)::int ` + base + ` AND status = 'resolved' AND resolved_at IS NOT NULL AND sla_deadline IS NOT NULL AND sla_status = 'on_track' GROUP BY 1, 2, 3, 4`},
		}
		for name, q := range checks {
			if d := symmetricDiff(ctx, t, db, q[0], q[1], tenant.String()); d != 0 {
				t.Errorf("F2 %s differs in %d rows", name, d)
			}
		}
		// Open count identity: every seeded date is inside the window, so the
		// net changes summed over all days equal today's open count.
		netByKey := `SELECT asset_id, severity, priority_class, sum(net_open_delta)::bigint FROM dash_asset_day
			WHERE tenant_id = $1 GROUP BY 1, 2, 3 HAVING sum(net_open_delta) <> 0`
		openByKey := `SELECT asset_id, severity, priority_class, sum(finding_count)::bigint FROM dash_asset_state
			WHERE tenant_id = $1 AND lens = 'open' GROUP BY 1, 2, 3`
		if d := symmetricDiff(ctx, t, db, netByKey, openByKey, tenant.String()); d != 0 {
			t.Errorf("sum of net_open_delta differs from the open count in %d groups", d)
		}
		var histTotal, fixedTotal int
		_ = db.QueryRowContext(ctx, `SELECT COALESCE(sum(h), 0) FROM dash_asset_day, unnest(fix_hours_hist) h WHERE tenant_id = $1`, tenant.String()).Scan(&histTotal)
		_ = db.QueryRowContext(ctx, `SELECT COALESCE(sum(fixed), 0) FROM dash_asset_day WHERE tenant_id = $1`, tenant.String()).Scan(&fixedTotal)
		if histTotal != fixedTotal || fixedTotal == 0 {
			t.Errorf("fix-time histogram holds %d findings, fixed %d", histTotal, fixedTotal)
		}
	})

	t.Run("F3 equals the top 10 per asset, kind and campaign", func(t *testing.T) {
		part := `PARTITION BY COALESCE(asset_id, '00000000-0000-0000-0000-000000000000'::uuid), source = 'pentest',
			CASE WHEN source = 'pentest' THEN COALESCE(pentest_campaign_id, '00000000-0000-0000-0000-000000000000'::uuid) END`
		base := `FROM findings WHERE tenant_id = $1 AND NOT branch_only AND ` + vulnerability.OpenStatusSQL("status") +
			` AND priority_class IN ('P0', 'P1', 'P2')`
		direct := `SELECT kind, id, rn FROM (
			SELECT 'fix_next' AS kind, id, row_number() OVER (` + part + ` ORDER BY priority_class, ` +
			severityRankSQLForFacts + `, created_at DESC, id) AS rn ` + base + `
			UNION ALL
			SELECT 'sla_due', id, row_number() OVER (` + part + ` ORDER BY sla_deadline, id) ` + base + ` AND sla_deadline IS NOT NULL
			UNION ALL
			SELECT 'oldest', id, row_number() OVER (` + part + ` ORDER BY COALESCE(first_detected_at, created_at), id) ` + base + `
		) r WHERE rn <= 10`
		facts := `SELECT kind::text, finding_id, rank::bigint FROM dash_asset_rank WHERE tenant_id = $1`
		if d := symmetricDiff(ctx, t, db, facts, direct, tenant.String()); d != 0 {
			t.Fatalf("F3 differs from the direct top-10 in %d rows", d)
		}
	})

	t.Run("tenant isolation", func(t *testing.T) {
		var n int
		for _, tbl := range []string{"dash_asset_state", "dash_asset_day", "dash_asset_rank"} {
			_ = db.QueryRowContext(ctx, `SELECT count(*) FROM `+tbl+` WHERE tenant_id = $1`, other.String()).Scan(&n)
			if n != 0 {
				t.Fatalf("rebuilding one tenant wrote %d %s rows for another", n, tbl)
			}
		}
		// Recomputing another tenant's asset id under this tenant reads
		// nothing of the other tenant.
		if _, err := repo.RecomputeAsset(ctx, tenant, otherAsset); err != nil {
			t.Fatal(err)
		}
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM dash_asset_state WHERE asset_id = $1`, otherAsset.String()).Scan(&n)
		if n != 0 {
			t.Fatalf("a foreign asset id produced %d fact rows", n)
		}
		if _, err := repo.RebuildTenant(ctx, other, 0); err != nil {
			t.Fatal(err)
		}
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), other.String()); d != 0 {
			t.Fatalf("other tenant's F1 differs in %d rows", d)
		}
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("rebuilding the other tenant changed this tenant's F1 (%d rows)", d)
		}
	})

	t.Run("idempotent and incremental", func(t *testing.T) {
		for _, a := range append(assets, DashboardNoAssetID) {
			n, err := repo.RecomputeAsset(ctx, tenant, a)
			if err != nil || n != 0 {
				t.Fatalf("recomputing an unchanged asset changed %d rows (%v)", n, err)
			}
		}
		// Change inputs on one asset, move a finding between assets, delete
		// one; recompute the touched assets only.
		if _, err := db.ExecContext(ctx, `UPDATE findings SET severity = 'critical', priority_class = 'P0', status = 'confirmed'
			WHERE tenant_id = $1 AND asset_id = $2 AND status = 'new'`, tenant.String(), assets[0].String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE findings SET asset_id = $3 WHERE id = (
			SELECT id FROM findings WHERE tenant_id = $1 AND asset_id = $2 AND status = 'resolved' LIMIT 1)`,
			tenant.String(), assets[1].String(), assets[2].String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM findings WHERE id = (
			SELECT id FROM findings WHERE tenant_id = $1 AND asset_id IS NULL LIMIT 1)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		for _, a := range append(assets, DashboardNoAssetID) {
			if _, err := repo.RecomputeAsset(ctx, tenant, a); err != nil {
				t.Fatal(err)
			}
		}
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("after incremental recompute F1 differs in %d rows", d)
		}
	})

	t.Run("rebuild removes facts of deleted assets and records the time", func(t *testing.T) {
		gone := seedOwnedAsset(ctx, t, db, tenant, nil)
		seedFactFinding(ctx, t, db, tenant, factFinding{asset: &gone, severity: "high", priority: "P1", status: "new",
			slaStatus: "on_track", source: "sast", detectedAgo: "1 day"})
		if _, err := repo.RecomputeAsset(ctx, tenant, gone); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM findings WHERE tenant_id = $1 AND asset_id = $2`, tenant.String(), gone.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM assets WHERE tenant_id = $1 AND id = $2`, tenant.String(), gone.String()); err != nil {
			t.Fatal(err)
		}
		// Leave stale facts behind as if the maintainer had not run yet.
		if _, err := db.ExecContext(ctx, `INSERT INTO dash_asset_state (tenant_id, asset_id, lens, severity, priority_class,
			sla_state, source, kev, reachable, age_band, pentest_campaign_id, finding_count)
			VALUES ($1, $2, 'open', 'high', 'P1', 'ok', 'sast', false, false, '0-30', '00000000-0000-0000-0000-000000000000', 1)
			ON CONFLICT DO NOTHING`, tenant.String(), gone.String()); err != nil {
			t.Fatal(err)
		}
		before := time.Now().Add(-time.Second)
		if _, err := repo.RebuildTenant(ctx, tenant, 0); err != nil {
			t.Fatal(err)
		}
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("after rebuild F1 differs in %d rows", d)
		}
		var at time.Time
		if err := db.QueryRowContext(ctx, `SELECT rebuilt_at FROM dash_fact_status WHERE tenant_id = $1`, tenant.String()).Scan(&at); err != nil || at.Before(before) {
			t.Fatalf("rebuilt_at %v (%v)", at, err)
		}
	})
}

// severityRankSQLForFacts is the list sort's severity rank (FindingFields).
const severityRankSQLForFacts = "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END"

// The SQL lens must stay the Go lens: a status added in Go without the
// migration helper would silently drop out of the facts.
func TestDashboardFactLens_MatchesGo_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	for _, st := range vulnerability.AllFindingStatuses() {
		want := ""
		switch {
		case vulnerability.IsOpenStatus(st):
			want = vulnerability.FindingLensOpen
		case containsFindingStatus(vulnerability.FixedStatuses(), st):
			want = vulnerability.FindingLensFixed
		case containsFindingStatus(vulnerability.DispositionedStatuses(), st):
			want = vulnerability.FindingLensDispositioned
		}
		var got sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT dash_finding_lens($1)`, string(st)).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got.String != want {
			t.Errorf("status %s: SQL lens %q, Go lens %q", st, got.String, want)
		}
	}
}

func containsFindingStatus(sts []vulnerability.FindingStatus, s vulnerability.FindingStatus) bool {
	for _, x := range sts {
		if x == s {
			return true
		}
	}
	return false
}

type dirtyRow struct {
	asset   string
	reasons int
}

func dirtyRows(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID) map[dirtyRow]int {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT asset_id, reasons FROM dash_dirty_assets WHERE tenant_id = $1`, tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[dirtyRow]int{}
	for rows.Next() {
		var r dirtyRow
		if err := rows.Scan(&r.asset, &r.reasons); err != nil {
			t.Fatal(err)
		}
		out[r]++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func clearDirty(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `DELETE FROM dash_dirty_assets WHERE tenant_id = $1`, tenant.String()); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardFacts_TriggersMarkDirty_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	a1 := seedOwnedAsset(ctx, t, db, tenant, nil)
	a2 := seedOwnedAsset(ctx, t, db, tenant, nil)
	none := DashboardNoAssetID.String()

	expect := func(t *testing.T, want map[dirtyRow]int) {
		t.Helper()
		got := dirtyRows(ctx, t, db, tenant)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("dirty rows: got %v, want %v", got, want)
		}
		clearDirty(ctx, t, db, tenant)
	}
	exec := func(t *testing.T, q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	clearDirty(ctx, t, db, tenant)

	var fid shared.ID
	t.Run("insert", func(t *testing.T) {
		fid = seedFactFinding(ctx, t, db, tenant, factFinding{asset: &a1, severity: "high", priority: "P1", status: "new",
			slaStatus: "on_track", source: "sast", detectedAgo: "1 day"})
		expect(t, map[dirtyRow]int{{a1.String(), 1}: 1})
	})
	t.Run("re-sighting marks nothing", func(t *testing.T) {
		exec(t, `UPDATE findings SET last_seen_at = now(), occurrence_count = occurrence_count + 1, metadata = '{"x": 1}'
			WHERE tenant_id = $1 AND id = $2`, tenant.String(), fid.String())
		exec(t, `UPDATE findings SET severity = 'high' WHERE tenant_id = $1 AND id = $2`, tenant.String(), fid.String())
		expect(t, map[dirtyRow]int{})
	})
	for _, set := range []string{"status = 'confirmed'", "severity = 'critical'", "priority_class = 'P0'",
		"sla_status = 'overdue'", "is_in_kev = true", "is_reachable = true", "epss_score = 0.5",
		"first_detected_at = now() - interval '50 days'", "sla_deadline = now()", "branch_only = true",
		"source = 'dast'", "resolved_at = now()", "last_reopened_at = now()"} {
		t.Run("update "+set, func(t *testing.T) {
			exec(t, `UPDATE findings SET `+set+` WHERE tenant_id = $1 AND id = $2`, tenant.String(), fid.String())
			expect(t, map[dirtyRow]int{{a1.String(), 1}: 1})
		})
	}
	t.Run("status change of many findings marks the asset once", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			seedFactFinding(ctx, t, db, tenant, factFinding{asset: &a2, severity: "low", priority: "P3", status: "new",
				slaStatus: "on_track", source: "sast", detectedAgo: "1 day"})
		}
		clearDirty(ctx, t, db, tenant)
		exec(t, `UPDATE findings SET status = 'in_progress' WHERE tenant_id = $1 AND asset_id = $2`, tenant.String(), a2.String())
		exec(t, `UPDATE findings SET status = 'confirmed' WHERE tenant_id = $1 AND asset_id = $2`, tenant.String(), a2.String())
		expect(t, map[dirtyRow]int{{a2.String(), 1}: 1})
	})
	t.Run("asset move marks both assets", func(t *testing.T) {
		exec(t, `UPDATE findings SET asset_id = $3 WHERE tenant_id = $1 AND id = $2`, tenant.String(), fid.String(), a2.String())
		expect(t, map[dirtyRow]int{{a1.String(), 1}: 1, {a2.String(), 1}: 1})
	})
	t.Run("delete", func(t *testing.T) {
		exec(t, `DELETE FROM findings WHERE tenant_id = $1 AND id = $2`, tenant.String(), fid.String())
		expect(t, map[dirtyRow]int{{a2.String(), 1}: 1})
	})
	t.Run("finding without an asset", func(t *testing.T) {
		seedFactFinding(ctx, t, db, tenant, factFinding{severity: "low", priority: "P3", status: "new",
			slaStatus: "on_track", source: "sast", detectedAgo: "1 day"})
		expect(t, map[dirtyRow]int{{none, 1}: 1})
	})
	t.Run("assets", func(t *testing.T) {
		a3 := seedOwnedAsset(ctx, t, db, tenant, nil)
		expect(t, map[dirtyRow]int{{a3.String(), 2}: 1})
		exec(t, `UPDATE assets SET risk_score = 42, last_seen = now() WHERE tenant_id = $1 AND id = $2`, tenant.String(), a3.String())
		expect(t, map[dirtyRow]int{})
		exec(t, `UPDATE assets SET criticality = 'critical' WHERE tenant_id = $1 AND id = $2`, tenant.String(), a3.String())
		expect(t, map[dirtyRow]int{{a3.String(), 2}: 1})
		exec(t, `UPDATE assets SET deleted_at = now() WHERE tenant_id = $1 AND id = $2`, tenant.String(), a3.String())
		expect(t, map[dirtyRow]int{{a3.String(), 2}: 1})
		exec(t, `DELETE FROM assets WHERE tenant_id = $1 AND id = $2`, tenant.String(), a3.String())
		expect(t, map[dirtyRow]int{{a3.String(), 2}: 1})
	})
	t.Run("asset group membership", func(t *testing.T) {
		gid := shared.NewID()
		exec(t, `INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'facts group')`, gid.String(), tenant.String())
		exec(t, `INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2), ($1, $3)`, gid.String(), a1.String(), a2.String())
		expect(t, map[dirtyRow]int{{a1.String(), 4}: 1, {a2.String(), 4}: 1})
		exec(t, `DELETE FROM asset_group_members WHERE asset_group_id = $1 AND asset_id = $2`, gid.String(), a1.String())
		expect(t, map[dirtyRow]int{{a1.String(), 4}: 1})
	})
	t.Run("asset ownership", func(t *testing.T) {
		uid := seedGroupsUser(ctx, t, db, "facts.example.com")
		exec(t, `INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`, a1.String(), uid.String())
		expect(t, map[dirtyRow]int{{a1.String(), 8}: 1})
		exec(t, `UPDATE asset_owners SET ownership_type = 'secondary' WHERE asset_id = $1 AND user_id = $2`, a1.String(), uid.String())
		expect(t, map[dirtyRow]int{{a1.String(), 8}: 1})
		exec(t, `DELETE FROM asset_owners WHERE asset_id = $1 AND user_id = $2`, a1.String(), uid.String())
		expect(t, map[dirtyRow]int{{a1.String(), 8}: 1})
	})
	t.Run("marks carry the writer's tenant only", func(t *testing.T) {
		oa := seedOwnedAsset(ctx, t, db, other, nil)
		seedFactFinding(ctx, t, db, other, factFinding{asset: &oa, severity: "low", priority: "P3", status: "new",
			slaStatus: "on_track", source: "sast", detectedAgo: "1 day"})
		expect(t, map[dirtyRow]int{})
		var n int
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1 AND asset_id = $2`, other.String(), oa.String()).Scan(&n)
		if n != 2 { // asset insert (2) and finding insert (1)
			t.Fatalf("other tenant's marks: %d rows", n)
		}
	})
	t.Run("aged findings", func(t *testing.T) {
		seedFactFinding(ctx, t, db, tenant, factFinding{asset: &a1, severity: "high", priority: "P1", status: "new",
			slaStatus: "on_track", source: "sast", detectedAgo: "31 days 1 hour"})
		seedFactFinding(ctx, t, db, tenant, factFinding{asset: &a2, severity: "high", priority: "P1", status: "new",
			slaStatus: "on_track", source: "sast", detectedAgo: "20 days"})
		seedFactFinding(ctx, t, db, tenant, factFinding{asset: &a2, severity: "high", priority: "P1", status: "resolved",
			slaStatus: "on_track", source: "sast", detectedAgo: "61 days 1 hour", resolvedAgo: "1 hour"})
		clearDirty(ctx, t, db, tenant)
		repo := NewDashboardFactsRepository(&DB{DB: db})
		now := time.Now()
		n, err := repo.MarkAgedAssets(ctx, tenant, now.Add(-24*time.Hour), now)
		if err != nil || n != 1 {
			t.Fatalf("marked %d (%v), want 1", n, err)
		}
		expect(t, map[dirtyRow]int{{a1.String(), 16}: 1})
	})
}

// The queue never loses a mark and never makes a writer wait: a row the
// maintainer holds is not relied on (the writer adds one), and a row a
// running writer holds is not claimed.
func TestDashboardDirtyQueue_ClaimRaces_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	clearDirty(ctx, t, db, tenant)
	insert := func(t *testing.T, ex interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	}) {
		t.Helper()
		id := shared.NewID()
		if _, err := ex.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint)
			VALUES ($1, $2, $3, 'sast', 'test', 'msg', 'low', $4)`, id.String(), tenant.String(), asset.String(), id.String()); err != nil {
			t.Fatal(err)
		}
	}
	claim := func(t *testing.T, tx *sql.Tx) int {
		t.Helper()
		rows, err := tx.QueryContext(ctx, `SELECT id FROM dash_dirty_assets WHERE tenant_id = $1 ORDER BY id FOR UPDATE SKIP LOCKED`, tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			n++
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return n
	}
	lockTimeout := func(t *testing.T, tx *sql.Tx) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '2s'`); err != nil {
			t.Fatal(err)
		}
	}

	insert(t, db)
	t.Run("writer during a claim adds its own row", func(t *testing.T) {
		m, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = m.Rollback() }()
		if n := claim(t, m); n != 1 {
			t.Fatalf("maintainer claimed %d rows, want 1", n)
		}
		w, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		lockTimeout(t, w)
		insert(t, w) // must not wait for the maintainer
		if err := w.Commit(); err != nil {
			t.Fatal(err)
		}
		if _, err := m.ExecContext(ctx, `DELETE FROM dash_dirty_assets WHERE tenant_id = $1 AND id IN (
			SELECT id FROM dash_dirty_assets WHERE tenant_id = $1 ORDER BY id LIMIT 1)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if err := m.Commit(); err != nil {
			t.Fatal(err)
		}
		if got := dirtyRows(ctx, t, db, tenant); got[dirtyRow{asset.String(), 1}] != 1 {
			t.Fatalf("the writer's mark was lost: %v", got)
		}
	})
	t.Run("a row held by a running writer is not claimed", func(t *testing.T) {
		w, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w.Rollback() }()
		insert(t, w) // reuses the committed row and holds it
		m, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = m.Rollback() }()
		lockTimeout(t, m)
		if n := claim(t, m); n != 0 {
			t.Fatalf("maintainer claimed %d rows held by a running writer", n)
		}
		_ = m.Rollback()
		if err := w.Commit(); err != nil {
			t.Fatal(err)
		}
		if got := dirtyRows(ctx, t, db, tenant); len(got) != 1 || got[dirtyRow{asset.String(), 1}] != 1 {
			t.Fatalf("queue after the writer committed: %v", got)
		}
	})
}

func TestDashboardFactTablesMigration_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "dash_facts", dir)
	v := testdb.MigrationVersion(t, dir, "dashboard_fact_tables")
	count := func() (tables, funcs, triggers int) {
		_ = db.QueryRow(`SELECT count(*) FROM pg_class WHERE relname LIKE 'dash\_%' AND relnamespace = 'public'::regnamespace`).Scan(&tables)
		_ = db.QueryRow(`SELECT count(*) FROM pg_proc WHERE proname LIKE 'dash\_%' AND pronamespace = 'public'::regnamespace`).Scan(&funcs)
		_ = db.QueryRow(`SELECT count(*) FROM pg_trigger WHERE tgname LIKE '%\_dash\_%' AND NOT tgisinternal`).Scan(&triggers)
		return
	}
	if tb, fn, tr := count(); tb == 0 || fn == 0 || tr != 14 {
		t.Fatalf("after up: %d relations, %d functions, %d triggers", tb, fn, tr)
	}
	tenant := shared.NewID()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'facts mig', $2)`, tenant.String(), "mig-"+tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO findings (tenant_id, source, tool_name, message, severity, fingerprint) VALUES ($1, 'sast', 't', 'm', 'low', 'fp')`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	testdb.Migrate(t, db, dir, v, v, true)
	if tb, fn, tr := count(); tb != 0 || fn != 0 || tr != 0 {
		t.Fatalf("after down: %d relations, %d functions, %d triggers left", tb, fn, tr)
	}
	// Writes keep working without the layer.
	if _, err := db.Exec(`UPDATE findings SET status = 'confirmed' WHERE tenant_id = $1`, tenant.String()); err != nil {
		t.Fatalf("write after down: %v", err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if _, tr := func() (int, int) { _, _, tr := count(); return 0, tr }(); tr != 14 {
		t.Fatalf("after up again: %d triggers", tr)
	}
}
