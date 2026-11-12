package postgres

// Time budget of the vulnerabilities list (docs/architecture/vulnerability-page.md,
// "Performance"): the default list of an organization with 200,000 findings
// over 15,000 CVEs and 4,000 assets, read by an administrator (the widest
// scope, the slowest case), stays under its budget, and its plan neither
// JIT-compiles (seconds of CPU for a sub-second query) nor spills a sort or
// a hash table to disk. The plan checks are deterministic; the time has a
// margin over what a loaded CI runner measures.
//
// The rows are seeded with triggers off (session_replication_role needs a
// superuser, as in the main test job); a run without one skips.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

const (
	cveListBudgetFindings = 200_000
	cveListBudgetCVEs     = 15_000
	cveListBudgetAssets   = 4_000
	// cveListBudget is the p95 target of the list (research 317 D6).
	cveListBudget = 1500 * time.Millisecond
)

func TestVulnerabilityListBudget_DB(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 200,000 findings")
	}
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database")
	}
	app, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	ctx := context.Background()
	if err := app.PingContext(ctx); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	admin := testdb.OpenAdmin(t)

	tenant := shared.NewID()
	user := shared.NewID()
	prefix := fmt.Sprintf("CVE-2097-%04d", rand.IntN(10000)) //nolint:gosec // a test id, not a secret
	seed := func(conn *sql.Conn) error {
		stmts := []string{
			`SET session_replication_role = replica`,
			`INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, 'vl-budget', 'vl-budget-' || $1::text)`,
			`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, is_crown_jewel)
			 SELECT md5($1::text || 'a' || g)::uuid, $1::uuid, 'vl-' || g || '.example.com', 'host',
			        CASE WHEN g % 5 = 0 THEN 'public' ELSE 'private' END, 'high', g % 50 = 0
			 FROM generate_series(1, ` + strconv.Itoa(cveListBudgetAssets) + `) g`,
			`INSERT INTO vulnerabilities (id, cve_id, external_id, title, severity, cvss_score, epss_score, fixed_versions)
			 SELECT md5($1::text || 'v' || g)::uuid, $2 || lpad(g::text, 5, '0'), $2 || lpad(g::text, 5, '0'), 'vl budget ' || g,
			        (ARRAY['critical','high','medium','low'])[1 + g % 4], (g % 100) / 10.0, (g % 1000) / 1000.0,
			        CASE WHEN g % 3 = 0 THEN '{1.2.3}'::text[] ELSE '{}' END
			 FROM generate_series(1, ` + strconv.Itoa(cveListBudgetCVEs) + `) g ON CONFLICT DO NOTHING`,
			`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, due_date)
			 SELECT $2 || lpad(g::text, 5, '0'), 'vl budget ' || $1::text, CURRENT_DATE - 30, CURRENT_DATE + 10
			 FROM generate_series(1, ` + strconv.Itoa(cveListBudgetCVEs) + `, 20) g ON CONFLICT DO NOTHING`,
			// Every finding on its own (CVE, asset) pair: the worst case for
			// the per-asset counts. One in six is resolved.
			`INSERT INTO findings (id, tenant_id, asset_id, cve_id, source, tool_name, message, severity, fingerprint,
			        status, priority_class, sla_status, sla_deadline, first_detected_at, last_seen_at, epss_score,
			        metadata, closure_reason, verification)
			 SELECT md5($1::text || 'f' || g)::uuid, $1::uuid,
			        md5($1::text || 'a' || (1 + abs(hashtext($1::text || g)) % ` + strconv.Itoa(cveListBudgetAssets) + `))::uuid,
			        $2 || lpad((1 + (g::bigint * 104729) % ` + strconv.Itoa(cveListBudgetCVEs) + `)::text, 5, '0'),
			        'va', 'vl-budget', 'vl budget', (ARRAY['critical','high','medium','low'])[1 + g % 4], 'vl' || g,
			        (ARRAY['new','confirmed','in_progress','resolved','new','new'])[1 + g % 6],
			        (ARRAY['P0','P1','P2','P3',NULL])[1 + g % 5], (ARRAY['on_track','overdue','warning'])[1 + g % 3],
			        NOW() + ((g % 40) - 10) * INTERVAL '1 day', NOW() - (g % 300) * INTERVAL '1 day',
			        NOW() - (g % 30) * INTERVAL '1 day', (g % 1000) / 1000.0,
			        CASE WHEN g % 4 = 0 THEN '{"fixed_versions":["9.9"]}'::jsonb ELSE '{}'::jsonb END,
			        CASE WHEN g % 6 = 3 THEN 'fixed' END, CASE WHEN g % 6 = 3 THEN 'covered_scan' END
			 FROM generate_series(1, ` + strconv.Itoa(cveListBudgetFindings) + `) g`,
			`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin)
			 SELECT md5($1::text || 'ra' || g)::uuid, $1::uuid, 'manual:vl' || g, 'manual', 'vl', 'manual' FROM generate_series(1, 300) g`,
			`INSERT INTO remediation_tasks (id, tenant_id, action_id, title, member_count, open_count)
			 SELECT md5($1::text || 'ra' || g)::uuid, $1::uuid, md5($1::text || 'ra' || g)::uuid, 'vl', 60, 60 FROM generate_series(1, 300) g`,
			`INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source)
			 SELECT $1::uuid, md5($1::text || 'ra' || (1 + g % 300))::uuid, md5($1::text || 'f' || g)::uuid, 'primary', 'manual'
			 FROM generate_series(1, ` + strconv.Itoa(cveListBudgetFindings) + `, 10) g`,
			`SET session_replication_role = origin`,
		}
		for _, q := range stmts {
			var args []any
			switch {
			case containsPlaceholder(q, 2):
				// $1 typed in every statement that has $2.
				args = []any{tenant.String(), prefix}
			case containsPlaceholder(q, 1):
				args = []any{tenant.String()}
			}
			if _, err := conn.ExecContext(ctx, q, args...); err != nil {
				return fmt.Errorf("%.60s: %w", q, err)
			}
		}
		return nil
	}
	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		_ = conn.Close()
		t.Skipf("cannot seed with triggers off (needs a superuser): %v", err)
	}
	t.Cleanup(func() {
		c, err := admin.Conn(ctx)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.ExecContext(ctx, `SET session_replication_role = replica`)
		for _, q := range []string{
			`DELETE FROM remediation_task_members WHERE tenant_id = $1`,
			`DELETE FROM remediation_tasks WHERE tenant_id = $1`,
			`DELETE FROM remediation_actions WHERE tenant_id = $1`,
			`DELETE FROM findings WHERE tenant_id = $1`,
			`DELETE FROM assets WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = c.ExecContext(ctx, q, tenant.String())
		}
		_, _ = c.ExecContext(ctx, `DELETE FROM kev_catalog WHERE cve_id LIKE $1 || '%'`, prefix)
		_, _ = c.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE cve_id LIKE $1 || '%'`, prefix)
		_, _ = c.ExecContext(ctx, `SET session_replication_role = origin`)
	})
	start := time.Now()
	err = seed(conn)
	_ = conn.Close()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := admin.ExecContext(ctx, `ANALYZE findings; ANALYZE assets; ANALYZE vulnerabilities; ANALYZE remediation_task_members`); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	t.Logf("seeded %d findings in %v", cveListBudgetFindings, time.Since(start).Round(time.Millisecond))

	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenant, UserID: user, IsAdmin: true,
		Scope: &shared.DataScope{TenantID: tenant, UserID: user, Unrestricted: true}})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := filterspec.ParseValues(map[string][]string{"state": {"open"}}, vulnerability.FindingFields, filterspec.Options{})
	if err != nil {
		t.Fatal(err)
	}
	where, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
	if err != nil {
		t.Fatal(err)
	}
	q := vulnerability.CVEListQuery{Where: where, TenantID: tenant, AssetScope: actor.AssetScopeSQL,
		Options: vulnerability.CVEListOptions{Sort: vulnerability.CVEListSort{Key: vulnerability.CVEListSortRisk}, Page: 1, PerPage: 25}}
	repo := NewFindingRepository(&DB{DB: app})
	var wantTotal int64
	if err := app.QueryRowContext(ctx, `SELECT COUNT(DISTINCT cve_id) FROM findings WHERE tenant_id = $1
		AND status IN ('new', 'confirmed', 'in_progress')`, tenant.String()).Scan(&wantTotal); err != nil {
		t.Fatal(err)
	}

	// The plan: no JIT, no sort or hash table on disk.
	checkCVEListPlan(t, app, q)

	budget := cveListBudget
	if raw := os.Getenv("VULN_LIST_BUDGET_MS"); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			budget = time.Duration(ms) * time.Millisecond
		}
	}
	runs := make([]time.Duration, 0, 5)
	for i := 0; i < 6; i++ {
		st := time.Now()
		out, err := repo.ListCVEExposures(ctx, q)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if out.Total != wantTotal || len(out.Data) != 25 {
			t.Fatalf("list total %d rows %d, want %d and 25", out.Total, len(out.Data), wantTotal)
		}
		if i > 0 { // the first run warms the cache
			runs = append(runs, time.Since(st))
		}
	}
	slices.Sort(runs)
	median := runs[len(runs)/2]
	t.Logf("list at %d findings / %d CVEs: runs %v, median %v (budget %v)", cveListBudgetFindings, cveListBudgetCVEs, runs, median, budget)
	if median > budget {
		t.Errorf("the vulnerabilities list took %v (median of %d runs) at %d findings, over its %v budget", median, len(runs), cveListBudgetFindings, budget)
	}
}

func containsPlaceholder(q string, n int) bool {
	p := "$" + strconv.Itoa(n)
	for i := 0; i+len(p) <= len(q); i++ {
		if q[i:i+len(p)] == p && (i+len(p) == len(q) || q[i+len(p)] < '0' || q[i+len(p)] > '9') {
			return true
		}
	}
	return false
}

// checkCVEListPlan runs the list statement under EXPLAIN ANALYZE with the
// list's own settings and fails on JIT or a disk spill.
func checkCVEListPlan(t *testing.T, db *sql.DB, q vulnerability.CVEListQuery) {
	t.Helper()
	ctx := context.Background()
	query, args, _, err := cveListStatement(q)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, cveListSettings); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+query, args...).Scan(&raw); err != nil {
		t.Fatalf("explain: %v", err)
	}
	var plans []map[string]any
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
		t.Fatalf("explain json: %v", err)
	}
	if _, jit := plans[0]["JIT"]; jit {
		t.Errorf("the list plan is JIT-compiled (cveListSettings must turn JIT off)")
	}
	var walk func(n map[string]any)
	walk = func(n map[string]any) {
		if v, ok := n["Sort Space Type"].(string); ok && v == "Disk" {
			t.Errorf("a %v node sorts on disk", n["Node Type"])
		}
		if v, ok := n["Disk Usage"].(float64); ok && v > 0 {
			t.Errorf("a %v node spills %v kB to disk", n["Node Type"], v)
		}
		if kids, ok := n["Plans"].([]any); ok {
			for _, k := range kids {
				if m, ok := k.(map[string]any); ok {
					walk(m)
				}
			}
		}
	}
	if root, ok := plans[0]["Plan"].(map[string]any); ok {
		walk(root)
	}
}
