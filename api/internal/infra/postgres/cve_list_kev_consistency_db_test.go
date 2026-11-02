package postgres

// One KEV definition (vulnerability.KEVFindingSQL): the findings stats'
// kev_open, the vulnerabilities list's open_kev_findings (what the MCP
// tools finding_stats and list_active_cves return) and the findings filter
// is_in_kev the dashboard metric intel.kev_open counts all give the same
// number over the same compiled WHERE. The list has a row for every CVE
// named on an open finding, in the catalog or not, and never one of another
// tenant or outside the reader's data scope.

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

func TestCVEListKEVConsistency_DB(t *testing.T) {
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

	tenantA, tenantB := shared.NewID(), shared.NewID()
	reader := shared.NewID()
	a1, a2, b1 := shared.NewID(), shared.NewID(), shared.NewID()
	n := rand.IntN(10000) //nolint:gosec // a test id, not a secret
	cve := func(i int) string { return fmt.Sprintf("CVE-2096-%04d%d", n, i) }
	x1, x2, x3, x4, x5 := cve(1), cve(2), cve(3), cve(4), cve(5)

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
		for _, tid := range []shared.ID{tenantA, tenantB} {
			for _, q := range []string{
				`DELETE FROM user_accessible_assets WHERE tenant_id = $1`,
				`DELETE FROM finding_remediation_keys WHERE tenant_id = $1`,
				`DELETE FROM findings WHERE tenant_id = $1`,
				`DELETE FROM assets WHERE tenant_id = $1`,
				`DELETE FROM tenants WHERE id = $1`,
			} {
				_, _ = c.ExecContext(ctx, q, tid.String())
			}
		}
		_, _ = c.ExecContext(ctx, `DELETE FROM kev_catalog WHERE cve_id = ANY($1)`, "{"+x1+","+x2+","+x4+"}")
		_, _ = c.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, "{"+x1+","+x4+"}")
		_, _ = c.ExecContext(ctx, `SET session_replication_role = origin`)
	})

	type fx struct {
		tenant, asset shared.ID
		cve           string // "" = no CVE
		status        string
		kev           bool
		source        string
	}
	findings := []fx{
		{tenantA, a1, x1, "new", true, "sca"},            // open KEV, in catalog
		{tenantA, a2, x1, "false_positive", true, "sca"}, // the same CVE triaged on another asset: not open
		{tenantA, a2, x2, "confirmed", true, "dast"},     // open KEV, not in the catalog
		{tenantA, a1, x3, "new", false, "dast"},          // not KEV, not in the catalog
		{tenantA, a1, x4, "in_progress", false, "sca"},   // the catalog's own KEV date is not a source
		{tenantA, a1, "", "new", false, "sast"},          // no CVE
		{tenantB, b1, x1, "new", true, "sca"},            // another tenant
		{tenantB, b1, x5, "new", false, "sca"},           // another tenant's CVE
	}
	stmts := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, 'kev-a', 'kev-a-' || $1::text), ($2::uuid, 'kev-b', 'kev-b-' || $2::text)`,
			[]any{tenantA.String(), tenantB.String()}},
		{`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES
			($1, $4, 'kev-a1.example.com', 'host', 'public', 'high'),
			($2, $4, 'kev-a2.example.com', 'host', 'private', 'high'),
			($3, $5, 'kev-b1.example.com', 'host', 'public', 'high')`,
			[]any{a1.String(), a2.String(), b1.String(), tenantA.String(), tenantB.String()}},
		{`INSERT INTO vulnerabilities (id, cve_id, external_id, title, severity, cvss_score, cisa_kev_date_added) VALUES
			($1, $2, $2, 'kev consistency catalog title', 'critical', 9.8, NULL),
			($3, $4, $4, 'kev consistency other', 'high', 7.5, CURRENT_DATE)`,
			[]any{shared.NewID().String(), x1, shared.NewID().String(), x4}},
		{`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, due_date) VALUES
			($1, 'kev consistency', CURRENT_DATE - 30, CURRENT_DATE + 10),
			($2, 'kev consistency', CURRENT_DATE - 30, CURRENT_DATE + 10)`,
			[]any{x1, x2}},
		// The reader's data scope: asset a1 only.
		{`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
			[]any{reader.String(), tenantA.String(), a1.String()}},
	}
	for i, f := range findings {
		var c any
		if f.cve != "" {
			c = f.cve
		}
		stmts = append(stmts, struct {
			q    string
			args []any
		}{`INSERT INTO findings (id, tenant_id, asset_id, cve_id, source, tool_name, message, severity, fingerprint, status, is_in_kev, closure_reason)
			VALUES ($1, $2, $3, $4, $5, 'kev-test', 'kev consistency', 'critical', $6, $7::text, $8,
				CASE WHEN $7::text = 'false_positive' THEN 'detection_error' END)`,
			[]any{shared.NewID().String(), f.tenant.String(), f.asset.String(), c, f.source,
				fmt.Sprintf("kev-%d-%d", n, i), f.status, f.kev}})
	}
	for _, s := range stmts {
		if _, err := conn.ExecContext(ctx, s.q, s.args...); err != nil {
			_ = conn.Close()
			t.Fatalf("seed %.50s: %v", s.q, err)
		}
	}
	// One fix source: x2's finding says a fix is available (scanner flag);
	// x1's open finding is in a remediation group (its key); x3 has none.
	for _, q := range []struct {
		q    string
		args []any
	}{
		{`UPDATE findings SET remediation = '{"fix_available": true}'::jsonb WHERE tenant_id = $1 AND cve_id = $2`, []any{tenantA.String(), x2}},
		{`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title, algorithm_version)
			SELECT id, tenant_id, 'sol:sca:kevtest', 'Upgrade kevpkg to 9.9', 3 FROM findings
			WHERE tenant_id = $1 AND cve_id = $2 AND status = 'new'`, []any{tenantA.String(), x1}},
	} {
		if _, err := conn.ExecContext(ctx, q.q, q.args...); err != nil {
			_ = conn.Close()
			t.Fatalf("seed fix: %v", err)
		}
	}
	_, _ = conn.ExecContext(ctx, `SET session_replication_role = origin`)
	_ = conn.Close()

	repo := NewFindingRepository(&DB{DB: app})
	compile := func(t *testing.T, actor filterspec.Actor, q map[string][]string) *filterspec.Where {
		t.Helper()
		spec, err := filterspec.ParseValues(q, vulnerability.FindingFields, filterspec.Options{})
		if err != nil {
			t.Fatal(err)
		}
		w, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	list := func(t *testing.T, actor filterspec.Actor, kevOnly bool) *vulnerability.CVEList {
		t.Helper()
		opts := vulnerability.CVEListOptions{Sort: vulnerability.CVEListSort{Key: vulnerability.CVEListSortRisk}, Page: 1, PerPage: 100}
		if kevOnly {
			kev := true
			opts.KEV = &kev
		}
		out, err := repo.ListCVEExposures(ctx, vulnerability.CVEListQuery{
			Where: compile(t, actor, map[string][]string{"state": {"open"}}), TenantID: tenantA,
			AssetScope: actor.AssetScopeSQL, Options: opts,
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		return out
	}
	// The three KEV numbers must be one.
	check := func(t *testing.T, actor filterspec.Actor, wantKEV int64, wantCVEs, wantKEVCVEs []string) {
		t.Helper()
		stats, err := repo.GetStatsWhere(ctx, compile(t, actor, nil))
		if err != nil {
			t.Fatalf("stats: %v", err)
		}
		dash, err := repo.CountWhere(ctx, compile(t, actor, map[string][]string{"state": {"open"}, "is_in_kev": {"true"}}))
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		kevList := list(t, actor, true)
		var sum int64
		var kevCVEs []string
		for _, r := range kevList.Data {
			sum += r.OpenKEVFindings
			kevCVEs = append(kevCVEs, r.CVEID)
		}
		if stats.KevOpen != wantKEV || dash != wantKEV || sum != wantKEV || kevList.Summary.OpenKEVFindings != wantKEV {
			t.Fatalf("kev: stats %d, dashboard filter %d, list rows %d, list summary %d; want all %d",
				stats.KevOpen, dash, sum, kevList.Summary.OpenKEVFindings, wantKEV)
		}
		slices.Sort(kevCVEs)
		if !slices.Equal(kevCVEs, wantKEVCVEs) {
			t.Fatalf("kev_only CVEs %v, want %v", kevCVEs, wantKEVCVEs)
		}
		all := list(t, actor, false)
		var got []string
		for _, r := range all.Data {
			got = append(got, r.CVEID)
		}
		slices.Sort(got)
		if !slices.Equal(got, wantCVEs) || all.Total != int64(len(wantCVEs)) {
			t.Fatalf("CVEs %v (total %d), want %v", got, all.Total, wantCVEs)
		}
	}

	t.Run("full data view", func(t *testing.T) {
		actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenantA, UserID: reader, IsAdmin: false,
			Scope: &shared.DataScope{TenantID: tenantA, UserID: reader, Unrestricted: true}})
		if err != nil {
			t.Fatal(err)
		}
		// Every CVE on an open finding of tenant A, none of tenant B (x5).
		check(t, actor, 2, sortedStrings(x1, x2, x3, x4), sortedStrings(x1, x2))
		for _, r := range list(t, actor, false).Data {
			switch r.CVEID {
			case x1:
				if !r.InCatalog || r.Title != "kev consistency catalog title" || !r.KEV || r.OpenFindings != 1 {
					t.Errorf("x1 row %+v: want in catalog with its title, KEV, one open finding", r)
				}
				if !r.HasFix || len(r.Remediations) != 1 || r.Remediations[0] != "Upgrade kevpkg to 9.9" {
					t.Errorf("x1 row: has_fix %v remediations %v, want the remediation group's fix", r.HasFix, r.Remediations)
				}
			case x2:
				if r.InCatalog || r.Title != "" || !r.KEV {
					t.Errorf("x2 row %+v: want not in catalog, KEV from the KEV catalog", r)
				}
				if !r.HasFix {
					t.Errorf("x2 row: the scanner's fix flag must give has_fix")
				}
			case x3:
				if r.HasFix || len(r.Remediations) != 0 {
					t.Errorf("x3 row: no fix known, got has_fix %v %v", r.HasFix, r.Remediations)
				}
			case x4:
				if r.KEV {
					t.Errorf("x4 row: the vulnerability catalog's own KEV date must not make it known exploited")
				}
			}
		}
	})
	t.Run("own scope rows", func(t *testing.T) {
		actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenantA, UserID: reader, IsAdmin: false,
			Scope: &shared.DataScope{TenantID: tenantA, UserID: reader}})
		if err != nil {
			t.Fatal(err)
		}
		// Asset a1 only: x2 (on a2) is out of scope.
		check(t, actor, 1, sortedStrings(x1, x3, x4), sortedStrings(x1))
	})
	t.Run("empty scope", func(t *testing.T) {
		nobody := shared.NewID()
		actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenantA, UserID: nobody, IsAdmin: false,
			Scope: &shared.DataScope{TenantID: tenantA, UserID: nobody}})
		if err != nil {
			t.Fatal(err)
		}
		check(t, actor, 0, nil, nil)
	})
}

func sortedStrings(s ...string) []string {
	out := append([]string(nil), s...)
	slices.Sort(out)
	return out
}
