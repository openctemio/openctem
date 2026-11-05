package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The version-match location merge (cmd/vulnmatch-locations): findings
// stored once per web origin of a host fold into the oldest, with one
// location per origin; -down puts everything back.

type locMergeFixture struct {
	t       *testing.T
	db      *sql.DB
	repo    *postgres.LocationMergeRepository
	tenant  shared.ID
	user    shared.ID
	intg    string
	product string
	version string
	cve     string
	host    string
}

func newLocMergeFixture(t *testing.T, name string) *locMergeFixture {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	f := &locMergeFixture{t: t, db: db, repo: postgres.NewLocationMergeRepository(&postgres.DB{DB: db}),
		tenant: createTestTenant(t, db, name), product: uuid.NewString(), version: uuid.NewString(),
		cve: testCVEID(), host: name + "-" + uuid.NewString()[:8] + ".example.com"}
	f.user = createTestUser(t, db, name+"-"+uuid.NewString()[:8]+"@example.com", "Merge")
	f.intg = uuid.NewString()
	_, err := db.ExecContext(context.Background(), `INSERT INTO integrations (id, tenant_id, name, category, provider, status, base_url)
		VALUES ($1, $2, 'j', 'ticketing', 'jira', 'connected', 'https://acme.atlassian.net')`, f.intg, f.tenant.String())
	require.NoError(t, err)
	return f
}

func (f *locMergeFixture) service(name string, at time.Time) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	_, err := f.db.ExecContext(context.Background(), `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, criticality, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'service', 'http', 'medium', 'active', $4, $4)`, id.String(), f.tenant.String(), name, at)
	require.NoError(f.t, err)
	return id
}

// finding stores a version-match finding the way the matcher did before
// locations: on one service, keyed on (asset, CVE, port).
func (f *locMergeFixture) finding(asset shared.ID, port int, status string, created time.Time, sla time.Time) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	closure, verification, resolution := "", "", ""
	if status == "resolved" {
		closure, verification, resolution = "fixed", "source_reported", "auto_fixed"
	}
	_, err := f.db.ExecContext(context.Background(), `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, last_seen_tool, message, title,
			severity, status, fingerprint, cve_id, network_port, network_transport, created_at, updated_at, first_detected_at,
			last_seen_at, sla_deadline, closure_reason, verification, resolution, metadata)
		VALUES ($1, $2, $3, 'va', 'version-match', 'version-match', 'widget may be affected', 'CVE in widget', 'high', $4, $5, $6,
			$7, 'tcp', $8, $8, $8, $8, $9, NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''),
			jsonb_build_object('version_match', jsonb_build_object('product_id', $13::text, 'version_id', $14::text,
				'version', '1.4.2', 'location', '', 'evidence', 'Server: widget/1.4.2')))`,
		id.String(), f.tenant.String(), asset.String(), status, "vm:"+id.String(), f.cve, port, created, sla,
		closure, verification, resolution, f.product, f.version)
	require.NoError(f.t, err)
	return id
}

func (f *locMergeFixture) scalar(q string, args ...any) string {
	f.t.Helper()
	var s sql.NullString
	require.NoError(f.t, f.db.QueryRowContext(context.Background(), q, args...).Scan(&s))
	return s.String
}

func (f *locMergeFixture) n(q string, args ...any) int {
	f.t.Helper()
	var n int
	require.NoError(f.t, f.db.QueryRowContext(context.Background(), q, args...).Scan(&n))
	return n
}

func TestLocationMerge_FoldsOriginsAndDownRestores(t *testing.T) {
	ctx := context.Background()
	f := newLocMergeFixture(t, "locmerge")
	other := newLocMergeFixture(t, "locmerge-other")
	old := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)
	sla := old.Add(30 * 24 * time.Hour)

	http80 := f.service("http://"+f.host, old)
	https443 := f.service("https://"+f.host, old)
	http8080 := f.service("http://"+f.host+":8080", old)
	survivor := f.finding(http80, 80, "new", old, sla)
	loserTLS := f.finding(https443, 443, "confirmed", old.Add(time.Hour), sla.Add(-24*time.Hour))
	loserAlt := f.finding(http8080, 8080, "resolved", old.Add(2*time.Hour), sla)
	// The same shapes in another organization: never touched.
	oHTTP := other.service("http://"+other.host, old)
	oHTTPS := other.service("https://"+other.host, old)
	oSurvivor := other.finding(oHTTP, 80, "new", old, sla)
	oLoser := other.finding(oHTTPS, 443, "new", old.Add(time.Hour), sla)

	// The loser's comment, ticket, timeline and work item.
	_, err := f.db.ExecContext(context.Background(), `INSERT INTO finding_comments (tenant_id, finding_id, author_id, content) VALUES ($1, $2, $3, 'on https')`,
		f.tenant.String(), loserTLS.String(), f.user.String())
	require.NoError(t, err)
	_, err = f.db.ExecContext(context.Background(), `INSERT INTO ticket_links (tenant_id, integration_id, finding_id, external_key, url, source)
		VALUES ($1, $2, $3, 'SEC-7', 'https://acme.atlassian.net/browse/SEC-7', 'platform')`, f.tenant.String(), f.intg, loserTLS.String())
	require.NoError(t, err)
	_, err = f.db.ExecContext(context.Background(), `UPDATE findings SET work_item_uris = ARRAY['https://acme.atlassian.net/browse/SEC-7'] WHERE id = $1`, loserTLS.String())
	require.NoError(t, err)
	_, err = f.db.ExecContext(context.Background(), `INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
		VALUES ($1, $2, 'comment_added', 'user', '{}', 'test', 'history of https')`, f.tenant.String(), loserTLS.String())
	require.NoError(t, err)

	// Dry run: reports, writes nothing.
	rep, err := f.repo.PlanLocationMerges(ctx, f.tenant, false, "")
	require.NoError(t, err)
	require.Len(t, rep.Groups, 1)
	g := rep.Groups[0]
	assert.Empty(t, g.Skipped)
	assert.Equal(t, survivor.String(), g.Survivor.FindingID)
	assert.Len(t, g.Losers, 2)
	assert.Equal(t, 2, rep.Merged)
	assert.Zero(t, f.n(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'duplicate'`, f.tenant.String()))
	assert.Zero(t, f.n(`SELECT count(*) FROM finding_locations WHERE tenant_id = $1`, f.tenant.String()))

	run := shared.NewID().String()
	rep, err = f.repo.PlanLocationMerges(ctx, f.tenant, true, run)
	require.NoError(t, err)
	assert.Equal(t, 2, rep.Merged)

	// The survivor keeps its status and asset, and takes the earlier SLA
	// deadline of an affected service, the loser's comment, ticket, work
	// item and history.
	assert.Equal(t, "new", f.scalar(`SELECT status FROM findings WHERE id = $1`, survivor.String()))
	assert.Equal(t, http80.String(), f.scalar(`SELECT asset_id FROM findings WHERE id = $1`, survivor.String()))
	var gotSLA time.Time
	require.NoError(t, f.db.QueryRowContext(context.Background(), `SELECT sla_deadline FROM findings WHERE id = $1`, survivor.String()).Scan(&gotSLA))
	assert.True(t, gotSLA.Equal(sla.Add(-24*time.Hour)), "the earlier deadline of an affected service is kept")
	assert.Equal(t, 1, f.n(`SELECT count(*) FROM finding_comments WHERE finding_id = $1`, survivor.String()))
	assert.Equal(t, 1, f.n(`SELECT count(*) FROM ticket_links WHERE finding_id = $1`, survivor.String()))
	assert.Equal(t, 1, f.n(`SELECT count(*) FROM findings WHERE id = $1 AND 'https://acme.atlassian.net/browse/SEC-7' = ANY(work_item_uris)`, survivor.String()))
	assert.Equal(t, 1, f.n(`SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND message = 'history of https'`, survivor.String()))
	for _, l := range []shared.ID{loserTLS, loserAlt} {
		assert.Equal(t, "duplicate", f.scalar(`SELECT status FROM findings WHERE id = $1`, l.String()))
		assert.Equal(t, survivor.String(), f.scalar(`SELECT duplicate_of FROM findings WHERE id = $1`, l.String()))
	}
	// One location per service, with the state its finding stood for.
	states := map[string]string{}
	func() {
		rows, err := f.db.QueryContext(context.Background(), `SELECT asset_id, state FROM finding_locations WHERE tenant_id = $1 AND finding_id = $2`,
			f.tenant.String(), survivor.String())
		require.NoError(t, err)
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a, s string
			require.NoError(t, rows.Scan(&a, &s))
			states[a] = s
		}
		require.NoError(t, rows.Err())
	}()
	assert.Equal(t, map[string]string{http80.String(): "affected", https443.String(): "affected", http8080.String(): "fixed"}, states)
	// Audited per fold; on the timeline.
	assert.Equal(t, 2, f.n(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.duplicate_marked'`, f.tenant.String()))
	assert.Equal(t, 2, f.n(`SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'location_changed'`, survivor.String()))
	// The former keys are not aliases of the survivor (no data scope change).
	assert.Zero(t, f.n(`SELECT count(*) FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint IN ($2, $3)`,
		survivor.String(), "vm:"+loserTLS.String(), "vm:"+loserAlt.String()))

	// Tenant isolation: the other organization is untouched.
	assert.Equal(t, "new", other.scalar(`SELECT status FROM findings WHERE id = $1`, oLoser.String()))
	assert.Zero(t, other.n(`SELECT count(*) FROM finding_locations WHERE tenant_id = $1`, other.tenant.String()))
	assert.Zero(t, other.n(`SELECT count(*) FROM finding_location_merges WHERE tenant_id = $1`, other.tenant.String()))
	_ = oSurvivor

	// Idempotent: a second run finds nothing to fold.
	rep, err = f.repo.PlanLocationMerges(ctx, f.tenant, true, shared.NewID().String())
	require.NoError(t, err)
	assert.Zero(t, rep.Merged)
	assert.Empty(t, rep.Groups)

	// A revert of another tenant reverts nothing here.
	orep, err := other.repo.RevertLocationMerges(ctx, other.tenant, "", true)
	require.NoError(t, err)
	assert.Zero(t, orep.Reverted)

	// -down dry run writes nothing; -down restores everything.
	drep, err := f.repo.RevertLocationMerges(ctx, f.tenant, run, false)
	require.NoError(t, err)
	assert.Len(t, drep.Entries, 2)
	assert.Equal(t, "duplicate", f.scalar(`SELECT status FROM findings WHERE id = $1`, loserTLS.String()))
	drep, err = f.repo.RevertLocationMerges(ctx, f.tenant, run, true)
	require.NoError(t, err)
	assert.Equal(t, 2, drep.Reverted)
	assert.Equal(t, "confirmed", f.scalar(`SELECT status FROM findings WHERE id = $1`, loserTLS.String()))
	assert.Equal(t, "resolved", f.scalar(`SELECT status FROM findings WHERE id = $1`, loserAlt.String()))
	assert.Equal(t, "vm:"+loserTLS.String(), f.scalar(`SELECT fingerprint FROM findings WHERE id = $1`, loserTLS.String()))
	assert.Empty(t, f.scalar(`SELECT duplicate_of FROM findings WHERE id = $1`, loserTLS.String()))
	assert.Equal(t, 1, f.n(`SELECT count(*) FROM finding_comments WHERE finding_id = $1`, loserTLS.String()))
	assert.Equal(t, 1, f.n(`SELECT count(*) FROM ticket_links WHERE finding_id = $1`, loserTLS.String()))
	assert.Equal(t, 1, f.n(`SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND message = 'history of https'`, loserTLS.String()))
	assert.Zero(t, f.n(`SELECT count(*) FROM finding_comments WHERE finding_id = $1`, survivor.String()))
	require.NoError(t, f.db.QueryRowContext(context.Background(), `SELECT sla_deadline FROM findings WHERE id = $1`, survivor.String()).Scan(&gotSLA))
	assert.True(t, gotSLA.Equal(sla), "the survivor's own deadline is back")
	assert.Zero(t, f.n(`SELECT count(*) FROM findings WHERE id = $1 AND 'https://acme.atlassian.net/browse/SEC-7' = ANY(work_item_uris)`, survivor.String()))
	assert.Zero(t, f.n(`SELECT count(*) FROM finding_locations WHERE tenant_id = $1`, f.tenant.String()), "built locations are removed")
	assert.Zero(t, f.n(`SELECT count(*) FROM finding_location_merges WHERE tenant_id = $1 AND reverted_at IS NULL`, f.tenant.String()))
	assert.Equal(t, 2, f.n(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.location_changed'
		AND metadata->>'reason' = 'location_merge_reverted'`, f.tenant.String()))

	// Reverting again does nothing; the groups can be folded again.
	drep, err = f.repo.RevertLocationMerges(ctx, f.tenant, "", true)
	require.NoError(t, err)
	assert.Zero(t, drep.Reverted)
	rep, err = f.repo.PlanLocationMerges(ctx, f.tenant, false, "")
	require.NoError(t, err)
	assert.Equal(t, 2, rep.Merged)
}

// A matcher-fixed survivor with a service still affected reopens; a person's
// decision, a scope difference or another assignee leaves the group alone.
func TestLocationMerge_SkipsAndReopen(t *testing.T) {
	ctx := context.Background()
	old := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)
	sla := old.Add(30 * 24 * time.Hour)

	t.Run("matcher-fixed survivor reopens", func(t *testing.T) {
		f := newLocMergeFixture(t, "locreopen")
		s := f.finding(f.service("http://"+f.host, old), 80, "resolved", old, sla)
		f.finding(f.service("https://"+f.host, old), 443, "new", old.Add(time.Hour), sla)
		run := shared.NewID().String()
		rep, err := f.repo.PlanLocationMerges(ctx, f.tenant, true, run)
		require.NoError(t, err)
		require.Len(t, rep.Groups, 1)
		assert.True(t, rep.Groups[0].Reopen)
		assert.Equal(t, "confirmed", f.scalar(`SELECT status FROM findings WHERE id = $1`, s.String()))
		_, err = f.repo.RevertLocationMerges(ctx, f.tenant, run, true)
		require.NoError(t, err)
		assert.Equal(t, "resolved", f.scalar(`SELECT status FROM findings WHERE id = $1`, s.String()), "-down restores the closed survivor")
	})
	t.Run("accepted loser is a person decision", func(t *testing.T) {
		f := newLocMergeFixture(t, "locaccepted")
		f.finding(f.service("http://"+f.host, old), 80, "new", old, sla)
		f.finding(f.service("https://"+f.host, old), 443, "accepted", old.Add(time.Hour), sla)
		rep, err := f.repo.PlanLocationMerges(ctx, f.tenant, true, shared.NewID().String())
		require.NoError(t, err)
		require.Len(t, rep.Groups, 1)
		assert.Equal(t, postgres.MergeSkipPersonDecision, rep.Groups[0].Skipped)
		assert.Zero(t, f.n(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'duplicate'`, f.tenant.String()))
	})
	t.Run("scope differs", func(t *testing.T) {
		f := newLocMergeFixture(t, "locscope")
		f.finding(f.service("http://"+f.host, old), 80, "new", old, sla)
		b := f.service("https://"+f.host, old)
		f.finding(b, 443, "new", old.Add(time.Hour), sla)
		_, err := f.db.ExecContext(context.Background(), `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
			f.user.String(), f.tenant.String(), b.String())
		require.NoError(t, err)
		rep, err := f.repo.PlanLocationMerges(ctx, f.tenant, true, shared.NewID().String())
		require.NoError(t, err)
		require.Len(t, rep.Groups, 1)
		assert.Equal(t, postgres.MergeSkipScopeDiffers, rep.Groups[0].Skipped)
	})
	t.Run("assignee differs", func(t *testing.T) {
		f := newLocMergeFixture(t, "locassignee")
		f.finding(f.service("http://"+f.host, old), 80, "new", old, sla)
		l := f.finding(f.service("https://"+f.host, old), 443, "new", old.Add(time.Hour), sla)
		_, err := f.db.ExecContext(context.Background(), `UPDATE findings SET assigned_to = $2 WHERE id = $1`, l.String(), f.user.String())
		require.NoError(t, err)
		rep, err := f.repo.PlanLocationMerges(ctx, f.tenant, true, shared.NewID().String())
		require.NoError(t, err)
		require.Len(t, rep.Groups, 1)
		assert.Equal(t, postgres.MergeSkipAssigneeDiffers, rep.Groups[0].Skipped)
	})
	t.Run("different versions never group", func(t *testing.T) {
		f := newLocMergeFixture(t, "locversions")
		f.finding(f.service("http://"+f.host, old), 80, "new", old, sla)
		l := f.finding(f.service("https://"+f.host, old), 443, "new", old.Add(time.Hour), sla)
		_, err := f.db.ExecContext(context.Background(), `UPDATE findings SET metadata = jsonb_set(metadata, '{version_match,version_id}', to_jsonb($2::text)) WHERE id = $1`,
			l.String(), uuid.NewString())
		require.NoError(t, err)
		rep, err := f.repo.PlanLocationMerges(ctx, f.tenant, false, "")
		require.NoError(t, err)
		assert.Empty(t, rep.Groups)
	})
}
