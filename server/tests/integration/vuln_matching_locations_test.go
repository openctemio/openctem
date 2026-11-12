package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	vm "github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// Locations of version-match findings (docs/architecture/vulnerability-matching.md,
// "Locations"): the web origins of one host that run the same version are one
// finding with one location per origin, each with its own state.

// serviceAsset creates a service asset (a web origin) named name, created at.
func serviceAsset(t *testing.T, e *matchEnv, tenantID shared.ID, name string, at time.Time) shared.ID {
	t.Helper()
	id := shared.NewID()
	_, err := e.pdb.ExecContext(context.Background(), `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, criticality, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'service', 'http', 'medium', 'active', $4, $4)`, id.String(), tenantID.String(), name, at)
	require.NoError(t, err)
	return id
}

// observeOn links the test product at version to assetID on port.
func (e *matchEnv) observeOn(tenantID, assetID shared.ID, version string, port int) {
	e.t.Helper()
	ctx := context.Background()
	p, ok := software.Parse(software.Observation{CPE: "cpe:2.3:a:" + e.vendor + ":" + e.product + ":" + version, Port: port,
		Transport: "tcp", Location: "", Source: software.SourceService})
	require.True(e.t, ok)
	refs, err := e.sw.Resolve(ctx, tenantID, []software.Identity{p.Identity})
	require.NoError(e.t, err)
	ref := refs[p.Identity]
	vid, err := e.sw.EnsureVersion(ctx, tenantID, ref, p.Version)
	require.NoError(e.t, err)
	_, err = e.sw.UpsertLinks(ctx, tenantID, []software.Link{{
		AssetID: assetID, ProductID: ref.ID, VersionID: vid, Location: "", Port: port, Transport: "tcp",
		Source: software.SourceService, Evidence: "Server: widget/" + version + " admin@example.com", Confidence: software.ConfidenceCPE,
		Version: p.Version, Segments: p.Segments, Class: software.ClassProbe,
	}})
	require.NoError(e.t, err)
	e.svc.SoftwareChanged(tenantID, []shared.ID{assetID})
}

type locRow struct {
	FindingID, AssetID, State, Evidence string
	Port                                int
}

func (e *matchEnv) locations(tenantID shared.ID) []locRow {
	e.t.Helper()
	rows, err := e.pdb.QueryContext(context.Background(), `SELECT finding_id, asset_id, state, port, evidence FROM finding_locations
		WHERE tenant_id = $1 ORDER BY port`, tenantID.String())
	require.NoError(e.t, err)
	defer rows.Close()
	var out []locRow
	for rows.Next() {
		var r locRow
		require.NoError(e.t, rows.Scan(&r.FindingID, &r.AssetID, &r.State, &r.Port, &r.Evidence))
		out = append(out, r)
	}
	require.NoError(e.t, rows.Err())
	return out
}

type vmFinding struct{ ID, AssetID, Status string }

func (e *matchEnv) vmFindings(tenantID shared.ID) []vmFinding {
	e.t.Helper()
	rows, err := e.pdb.QueryContext(context.Background(), `SELECT id, asset_id, status FROM findings WHERE tenant_id = $1 AND tool_name = 'version-match'
		AND cve_id = $2 ORDER BY created_at, id`, tenantID.String(), e.cveID)
	require.NoError(e.t, err)
	defer rows.Close()
	var out []vmFinding
	for rows.Next() {
		var r vmFinding
		require.NoError(e.t, rows.Scan(&r.ID, &r.AssetID, &r.Status))
		out = append(out, r)
	}
	require.NoError(e.t, rows.Err())
	return out
}

func (e *matchEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.pdb.QueryRowContext(context.Background(), q, args...).Scan(&n))
	return n
}

func TestVulnMatchingLocations_OriginsOfOneHostAreOneFinding(t *testing.T) {
	e := newMatchEnv(t)
	tenant := e.tenant("vm-loc", true)
	other := e.tenant("vm-loc-other", true)
	host := "loc-" + uuid.NewString()[:8] + ".example.com"
	old := time.Now().Add(-48 * time.Hour)
	http80 := serviceAsset(t, e, tenant, "http://"+host, old)
	https443 := serviceAsset(t, e, tenant, "https://"+host, old.Add(time.Hour))
	// Another organization with the same host name: its own finding.
	otherHTTPS := serviceAsset(t, e, other, "https://"+host, old)

	e.observeOn(tenant, http80, "1.4.2", 80)
	e.observeOn(tenant, https443, "1.4.2", 443)
	e.observeOn(other, otherHTTPS, "1.4.2", 443)
	e.run()

	got := e.vmFindings(tenant)
	require.Len(t, got, 1, "one finding per host, product, version and CVE")
	assert.Equal(t, http80.String(), got[0].AssetID, "the finding stays on the oldest service")
	locs := e.locations(tenant)
	require.Len(t, locs, 2)
	for _, l := range locs {
		assert.Equal(t, got[0].ID, l.FindingID)
		assert.Equal(t, "affected", l.State)
		assert.NotContains(t, l.Evidence, "admin@", "evidence keeps no e-mail address")
	}
	assert.Equal(t, 80, locs[0].Port)
	assert.Equal(t, 443, locs[1].Port)

	// Tenant isolation: the other organization has its own finding and
	// location, and no location of one names the other's finding or asset.
	og := e.vmFindings(other)
	require.Len(t, og, 1)
	ol := e.locations(other)
	require.Len(t, ol, 1)
	assert.Equal(t, og[0].ID, ol[0].FindingID)
	assert.Zero(t, e.count(`SELECT count(*) FROM finding_locations l JOIN findings f ON f.id = l.finding_id
		WHERE l.tenant_id <> f.tenant_id`))

	// A second pass changes nothing.
	e.run()
	assert.Len(t, e.vmFindings(tenant), 1)
	assert.Len(t, e.locations(tenant), 2)
	added := e.count(`SELECT count(*) FROM finding_activities WHERE tenant_id = $1 AND activity_type = 'location_changed'`, tenant.String())
	assert.Equal(t, 1, added, "the second service is on the timeline once")

	// https is upgraded out of range: that location is fixed, the finding
	// stays open (http still runs the vulnerable version).
	e.observeOn(tenant, https443, "2.0.1", 443)
	e.run()
	got = e.vmFindings(tenant)
	require.Len(t, got, 1)
	assert.Equal(t, "new", got[0].Status)
	locs = e.locations(tenant)
	assert.Equal(t, "affected", locs[0].State)
	assert.Equal(t, "fixed", locs[1].State)

	// http too: every location is fixed, the finding closes as fixed.
	e.observeOn(tenant, http80, "2.0.1", 80)
	e.run()
	got = e.vmFindings(tenant)
	assert.Equal(t, "resolved", got[0].Status)
	locs = e.locations(tenant)
	assert.Equal(t, "fixed", locs[0].State)
	assert.Equal(t, "fixed", locs[1].State)

	// https goes back to the vulnerable version: that location is affected
	// again and the finding reopens.
	e.observeOn(tenant, https443, "1.4.2", 443)
	e.run()
	got = e.vmFindings(tenant)
	require.Len(t, got, 1)
	assert.Equal(t, "confirmed", got[0].Status)
	locs = e.locations(tenant)
	assert.Equal(t, "fixed", locs[0].State)
	assert.Equal(t, "affected", locs[1].State)

	// Every move is on the timeline and audited.
	moves := e.count(`SELECT count(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2 AND activity_type = 'location_changed'`,
		tenant.String(), got[0].ID)
	assert.Equal(t, 4, moves, "added, https fixed, http fixed, https affected again")
	assert.Equal(t, 4, e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2 AND action = 'finding.location_changed'`,
		tenant.String(), got[0].ID))
	// The other organization saw none of it.
	assert.Equal(t, "new", e.vmFindings(other)[0].Status)
	assert.Zero(t, e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.location_changed'`, other.String()))
}

func TestVulnMatchingLocations_DifferentVersionsAreDifferentFindings(t *testing.T) {
	e := newMatchEnv(t)
	tenant := e.tenant("vm-loc-ver", true)
	host := "ver-" + uuid.NewString()[:8] + ".example.com"
	old := time.Now().Add(-48 * time.Hour)
	a := serviceAsset(t, e, tenant, "http://"+host, old)
	b := serviceAsset(t, e, tenant, "https://"+host, old.Add(time.Hour))
	e.observeOn(tenant, a, "1.4.2", 80)
	e.observeOn(tenant, b, "1.5.0", 443)
	e.run()
	got := e.vmFindings(tenant)
	require.Len(t, got, 2, "another version on another service is another backend")
	assert.Len(t, e.locations(tenant), 2)
}

// Services that users see differently are never grouped: a person who can
// see one service keeps its finding, and nobody sees a service they could
// not see before.
func TestVulnMatchingLocations_ScopeDiffersKeepsFindingsApart(t *testing.T) {
	e := newMatchEnv(t)
	tenant := e.tenant("vm-loc-scope", true)
	host := "scope-" + uuid.NewString()[:8] + ".example.com"
	old := time.Now().Add(-48 * time.Hour)
	a := serviceAsset(t, e, tenant, "http://"+host, old)
	b := serviceAsset(t, e, tenant, "https://"+host, old.Add(time.Hour))
	user := createTestUser(t, e.pdb.DB, "loc-"+uuid.NewString()[:8]+"@example.com", "Scoped")
	_, err := e.pdb.ExecContext(context.Background(), `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
		user.String(), tenant.String(), b.String())
	require.NoError(t, err)
	e.observeOn(tenant, a, "1.4.2", 80)
	e.observeOn(tenant, b, "1.4.2", 443)
	e.run()
	got := e.vmFindings(tenant)
	require.Len(t, got, 2)
	assets := []string{got[0].AssetID, got[1].AssetID}
	assert.ElementsMatch(t, []string{a.String(), b.String()}, assets)
}

// A new service of a host joins the open finding of that host.
func TestVulnMatchingLocations_NewServiceJoinsOpenFinding(t *testing.T) {
	e := newMatchEnv(t)
	tenant := e.tenant("vm-loc-join", true)
	host := "join-" + uuid.NewString()[:8] + ".example.com"
	old := time.Now().Add(-48 * time.Hour)
	a := serviceAsset(t, e, tenant, "http://"+host, old)
	e.observeOn(tenant, a, "1.4.2", 80)
	e.run()
	require.Len(t, e.vmFindings(tenant), 1)

	c := serviceAsset(t, e, tenant, "http://"+host+":8080", old.Add(2*time.Hour))
	e.observeOn(tenant, c, "1.4.2", 8080)
	e.run()
	got := e.vmFindings(tenant)
	require.Len(t, got, 1)
	locs := e.locations(tenant)
	require.Len(t, locs, 2)
	assert.Equal(t, got[0].ID, locs[1].FindingID)
	assert.Equal(t, 8080, locs[1].Port)
}

// One service not seen lately and the other no longer covered by the
// advisory: the second location is not affected, the first stays affected
// (not seen is not fixed), and the finding is only marked stale.
func TestVulnMatchingLocations_AdvisoryAndNotSeenPerLocation(t *testing.T) {
	e := newMatchEnv(t)
	tenant := e.tenant("vm-loc-adv", true)
	host := "adv-" + uuid.NewString()[:8] + ".example.com"
	old := time.Now().Add(-48 * time.Hour)
	a := serviceAsset(t, e, tenant, "http://"+host, old)
	b := serviceAsset(t, e, tenant, "https://"+host, old.Add(time.Hour))
	e.observeOn(tenant, a, "1.4.2", 80)
	e.observeOn(tenant, b, "1.4.2", 443)
	e.run()
	require.Len(t, e.vmFindings(tenant), 1)

	_, err := e.pdb.ExecContext(context.Background(), `UPDATE asset_software SET last_seen_at = now() - interval '31 days' WHERE tenant_id = $1 AND asset_id = $2`,
		tenant.String(), a.String())
	require.NoError(t, err)
	e.feed(vm.Range{End: "1.0"})
	require.NoError(t, postgres.NewSoftwareMatchRepository(e.pdb).QueueTenants(context.Background(), []shared.ID{tenant}))
	e.run()

	got := e.vmFindings(tenant)
	require.Len(t, got, 1)
	assert.NotEqual(t, "false_positive", got[0].Status, "a location not seen is still affected")
	locs := e.locations(tenant)
	assert.Equal(t, "affected", locs[0].State)
	assert.Equal(t, "not_affected", locs[1].State)
	var observation string
	require.NoError(t, e.pdb.QueryRowContext(context.Background(), `SELECT observation_state FROM findings WHERE id = $1`, got[0].ID).Scan(&observation))
	assert.Equal(t, "stale", observation)
}

// After the location merge folds per-service findings, the matcher's next
// passes keep the survivor and its locations: nothing is created again and
// the fold's services keep their state.
func TestVulnMatchingLocations_MergedDuplicatesStayMerged(t *testing.T) {
	e := newMatchEnv(t)
	tenant := e.tenant("vm-loc-merged", true)
	host := "merged-" + uuid.NewString()[:8] + ".example.com"
	old := time.Now().Add(-48 * time.Hour)
	a := serviceAsset(t, e, tenant, "http://"+host, old)
	b := serviceAsset(t, e, tenant, "https://"+host, old.Add(time.Hour))
	// Seen differently at first: two findings, as before locations.
	user := createTestUser(t, e.pdb.DB, "merged-"+uuid.NewString()[:8]+"@example.com", "Scoped")
	_, err := e.pdb.ExecContext(context.Background(), `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
		user.String(), tenant.String(), b.String())
	require.NoError(t, err)
	e.observeOn(tenant, a, "1.4.2", 80)
	e.observeOn(tenant, b, "1.4.2", 443)
	e.run()
	require.Len(t, e.vmFindings(tenant), 2)
	_, err = e.pdb.ExecContext(context.Background(), `DELETE FROM user_accessible_assets WHERE tenant_id = $1 AND asset_id = $2`, tenant.String(), b.String())
	require.NoError(t, err)

	rep, err := postgres.NewLocationMergeRepository(e.pdb).PlanLocationMerges(context.Background(), tenant, true, shared.NewID().String())
	require.NoError(t, err)
	require.Equal(t, 1, rep.Merged)

	for range 2 {
		e.svc.SoftwareChanged(tenant, []shared.ID{a, b})
		e.run()
	}
	got := e.vmFindings(tenant)
	require.Len(t, got, 2)
	assert.Equal(t, "new", got[0].Status)
	assert.Equal(t, "duplicate", got[1].Status)
	locs := e.locations(tenant)
	require.Len(t, locs, 2)
	for _, l := range locs {
		assert.Equal(t, got[0].ID, l.FindingID)
		assert.Equal(t, "affected", l.State)
	}
}
