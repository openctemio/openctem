package postgres

import (
	"context"
	"database/sql"
	"sort"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// coverageFixture is a tenant with one host asset scanned by nuclei under one
// scan profile, and a second, uncovered asset.
type coverageFixture struct {
	db                         *sql.DB
	tenant, sensor             shared.ID
	host, otherHost, repoAsset shared.ID
	profile, otherProfile      shared.ID
	scan, otherScan            shared.ID
}

func newCoverageFixture(t *testing.T) *coverageFixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping coverage auto-resolve DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	f := &coverageFixture{
		db: db, tenant: shared.NewID(), sensor: shared.NewID(),
		host: shared.NewID(), otherHost: shared.NewID(), repoAsset: shared.NewID(),
		profile: shared.NewID(), otherProfile: shared.NewID(), scan: shared.NewID(), otherScan: shared.NewID(),
	}
	f.exec(t, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, f.tenant, "cov-"+f.tenant.String())
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DELETE FROM ingest_reports WHERE tenant_id = $1", f.tenant.String())
		_, _ = db.ExecContext(context.Background(), "DELETE FROM tenants WHERE id = $1", f.tenant.String())
	})
	f.exec(t, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, 'cov-sensor', $3, 'p', 'active')`, f.sensor, f.tenant, "h-"+f.sensor.String())
	for _, a := range []shared.ID{f.host, f.otherHost, f.repoAsset} {
		f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`, a, f.tenant, "h-"+a.String())
	}
	for _, p := range []shared.ID{f.profile, f.otherProfile} {
		f.exec(t, `INSERT INTO scan_profiles (id, tenant_id, name) VALUES ($1, $2, $3)`, p, f.tenant, "p-"+p.String())
	}
	f.exec(t, `INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets, profile_id)
		VALUES ($1, $2, 'cov-scan', 'single', 'nuclei', ARRAY['h'], $3)`, f.scan, f.tenant, f.profile)
	f.exec(t, `INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets, profile_id)
		VALUES ($1, $2, 'cov-scan-2', 'single', 'nuclei', ARRAY['h'], $3)`, f.otherScan, f.tenant, f.otherProfile)
	return f
}

func (f *coverageFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	for i, a := range args {
		if id, ok := a.(shared.ID); ok {
			args[i] = id.String()
		}
	}
	if _, err := f.db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, q)
	}
}

// run records a scan command of the given scan with one completed nuclei
// report that touched the given assets, and returns command and report ids.
func (f *coverageFixture) run(t *testing.T, scanID shared.ID, status string, touched ...shared.ID) (shared.ID, string) {
	t.Helper()
	cmd, report := shared.NewID(), shared.NewID().String()
	f.exec(t, `INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, result)
		VALUES ($1, $2, $3, 'scan', $4, jsonb_build_object('scan_id', $5::text, 'scanner', 'nuclei'), '{"exit_code":0}')`,
		cmd, f.tenant, f.sensor, status, scanID)
	ids := make([]string, len(touched))
	for i, a := range touched {
		ids[i] = a.String()
	}
	f.exec(t, `INSERT INTO ingest_reports (id, tenant_id, sensor_id, report_id, command_id, state, media_type,
			header_digest, header, tool_name, segment_outcomes, touched_asset_ids, expires_at, committed_at)
		VALUES ($1, $2, $3, $4, $5, 'completed', 'application/vnd.ctis+json', 'd', '{"tool":{"name":"nuclei"}}',
			'nuclei', '{"0":{"accepted_findings":1}}', $6::uuid[], NOW() + interval '1 hour', NOW())`,
		shared.NewID(), f.tenant, f.sensor, report, cmd, pq.Array(ids))
	return cmd, report
}

// finding inserts an open finding of the tool on the asset, last seen by the
// given scan id (a report id, or anything for a v1 sighting).
func (f *coverageFixture) finding(t *testing.T, asset shared.ID, tool, scanID string, branch *shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	var b any
	if branch != nil {
		b = branch.String()
	}
	f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, scan_id, branch_id)
		VALUES ($1, $2, $3, 'dast', $4, 'm', 'high', $5, 'new', $6, $7)`,
		id, f.tenant, asset, tool, "fp-"+id.String(), scanID, b)
	return id
}

func (f *coverageFixture) status(t *testing.T, id shared.ID) string {
	t.Helper()
	var s string
	if err := f.db.QueryRowContext(context.Background(), `SELECT status FROM findings WHERE id = $1`, id.String()).Scan(&s); err != nil {
		t.Fatalf("status: %v", err)
	}
	return s
}

func idStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	sort.Strings(out)
	return out
}

// TestCoverageAutoResolve_NonRepositoryFindings is the regression for
// non-repository findings never being closed by a later scan: the only
// auto-resolve SQL joins repository_branches, so a host finding that a
// completed, full nuclei run of the same profile no longer reports stayed open
// forever. Only that finding is a candidate; everything else is left alone.
func TestCoverageAutoResolve_NonRepositoryFindings(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	// Yesterday's run of the profile saw four findings.
	_, earlier := f.run(t, f.scan, "completed", f.host)
	gone := f.finding(t, f.host, "nuclei", earlier, nil)           // not reported today: closes
	stillThere := f.finding(t, f.host, "nuclei", earlier, nil)     // reported today (below)
	uncovered := f.finding(t, f.otherHost, "nuclei", earlier, nil) // today's run never reached its asset
	otherTool := f.finding(t, f.host, "trivy", earlier, nil)       // another tool
	// A different profile's run saw this one: a narrower profile proves nothing.
	_, otherProfileReport := f.run(t, f.otherScan, "completed", f.host)
	otherProfile := f.finding(t, f.host, "nuclei", otherProfileReport, nil)
	// Last seen through v1 ingest: no run to compare against.
	v1Sighting := f.finding(t, f.host, "nuclei", "legacy-v1-scan", nil)
	// A repository finding (branch set) keeps the default-branch path.
	f.exec(t, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, f.repoAsset)
	branch := shared.NewID()
	f.exec(t, `INSERT INTO repository_branches (id, repository_id, name, is_default) VALUES ($1, $2, 'main', true)`, branch, f.repoAsset)
	onBranch := f.finding(t, f.host, "nuclei", earlier, &branch)

	// Today's run: completed, reached the host, reported only stillThere.
	cmd, today := f.run(t, f.scan, "completed", f.host)
	f.exec(t, `UPDATE findings SET scan_id = $1 WHERE id = $2`, today, stillThere)

	cov, err := repo.CommandCoverage(ctx, f.tenant, cmd)
	if err != nil {
		t.Fatalf("CommandCoverage: %v", err)
	}
	if cov.CommandType != "scan" || cov.CommandStatus != "completed" || cov.ProfileID != f.profile.String() ||
		len(cov.Reports) != 1 || cov.Reports[0].State != protov2.StateCompleted || cov.Reports[0].ToolName != "nuclei" ||
		len(cov.Reports[0].TouchedAssetIDs) != 1 || cov.Reports[0].TouchedAssetIDs[0] != f.host ||
		cov.Reports[0].SensorID != f.sensor || cov.Reports[0].SegmentOutcomes["0"].AcceptedFindings != 1 {
		t.Fatalf("coverage = %+v", cov)
	}

	q := ingestreport.CoverageQuery{AssetIDs: []shared.ID{f.host}, ToolName: "nuclei", ProfileID: f.profile.String(), SeenScanIDs: []string{today}}
	stale, open, err := repo.CoverageStaleFindings(ctx, f.tenant, q)
	if err != nil {
		t.Fatalf("CoverageStaleFindings: %v", err)
	}
	if got, want := idStrings(stale), idStrings([]shared.ID{gone}); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("stale = %v, want only %v", got, want)
	}
	// Open nuclei, non-repository findings on the host: gone, stillThere,
	// otherProfile, v1Sighting.
	if open != 4 {
		t.Fatalf("open = %d, want 4", open)
	}

	// Someone triaged the finding between read and resolve: left alone.
	f.exec(t, `UPDATE findings SET status = 'accepted' WHERE id = $1`, gone)
	if resolved, err := repo.ResolveCoverageStale(ctx, f.tenant, stale); err != nil || len(resolved) != 0 {
		t.Fatalf("resolve after triage = %v, %v; want nothing", resolved, err)
	}
	f.exec(t, `UPDATE findings SET status = 'new' WHERE id = $1`, gone)

	resolved, err := repo.ResolveCoverageStale(ctx, f.tenant, stale)
	if err != nil || len(resolved) != 1 || resolved[0] != gone {
		t.Fatalf("resolve = %v, %v", resolved, err)
	}
	if s := f.status(t, gone); s != "resolved" {
		t.Fatalf("gone finding status = %s", s)
	}
	for name, id := range map[string]shared.ID{
		"still reported": stillThere, "uncovered asset": uncovered, "other tool": otherTool,
		"other profile": otherProfile, "v1 sighting": v1Sighting, "repository branch": onBranch,
	} {
		if s := f.status(t, id); s != "new" {
			t.Errorf("%s finding was changed to %s", name, s)
		}
	}

	// Another tenant cannot read the command.
	if _, err := repo.CommandCoverage(ctx, shared.NewID(), cmd); err == nil {
		t.Fatal("command coverage leaked across tenants")
	}
}
