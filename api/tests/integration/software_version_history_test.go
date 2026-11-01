package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Version history end to end through the matcher (research 376): one weak
// sighting of a new version never closes or proposes to close a finding,
// several consecutive ones do, and a version that comes back cancels the
// proposal it caused.

type reviewClosing struct{}

func (reviewClosing) GetClosureSettings(context.Context, string) (*tenant.ClosureSettings, error) {
	return &tenant.ClosureSettings{Mode: tenant.ClosingModeReview}, nil
}

func (e *matchEnv) proposals(tenantID shared.ID) (pending, canceled int, evidence map[string]any) {
	e.t.Helper()
	rows, err := e.pdb.Query(`SELECT p.state, p.evidence FROM finding_closure_proposals p
		JOIN findings f ON f.tenant_id = p.tenant_id AND f.id = p.finding_id
		WHERE p.tenant_id = $1 AND f.cve_id = $2 AND p.method = 'source_reported'`, tenantID.String(), e.cveID)
	require.NoError(e.t, err)
	defer rows.Close()
	for rows.Next() {
		var state string
		var raw []byte
		require.NoError(e.t, rows.Scan(&state, &raw))
		switch state {
		case "pending":
			pending++
			require.NoError(e.t, json.Unmarshal(raw, &evidence))
		case "canceled":
			canceled++
		}
	}
	require.NoError(e.t, rows.Err())
	return pending, canceled, evidence
}

// The production case: the affected version seen for days, the fixed one
// seen once by technology detection (banner class, confidence 65). The
// finding stays open with no proposal; three readings over more than 12
// hours close it.
func TestVersionHistory_WeakSightingDoesNotClose(t *testing.T) {
	e := newMatchEnv(t)
	org := e.tenant("vh-weak", true)
	now := time.Now().UTC()
	asset := e.observeAt(org, shared.ID{}, "1.4.2", software.ClassBanner, 65, now.Add(-96*time.Hour))
	e.observeAt(org, asset, "1.4.2", software.ClassBanner, 65, now.Add(-60*time.Hour))
	e.run()
	require.Len(t, e.findings(org), 1)

	e.observeAt(org, asset, "2.0.1", software.ClassBanner, 65, now.Add(-40*time.Hour))
	e.run()
	got := e.findings(org)
	require.Len(t, got, 1)
	assert.Equal(t, "new", got[0].Status, "one weak sighting must not close the finding")

	e.observeAt(org, asset, "2.0.1", software.ClassBanner, 65, now.Add(-30*time.Hour))
	e.run()
	assert.Equal(t, "new", e.findings(org)[0].Status, "two readings are not enough")

	e.observeAt(org, asset, "2.0.1", software.ClassBanner, 65, now.Add(-20*time.Hour))
	e.run()
	got = e.findings(org)
	assert.Equal(t, "resolved", got[0].Status, "three readings over 20 hours establish the new version")
	assert.Equal(t, "fixed/source_reported", got[0].Method)
}

// Flapping (load balancer, stale cache): readings alternate; the finding
// stays open and no proposal is made.
func TestVersionHistory_FlappingProposesNothing(t *testing.T) {
	e := newMatchEnv(t)
	e.svc.SetClosureSettings(reviewClosing{})
	org := e.tenant("vh-flap", true)
	now := time.Now().UTC()
	asset := e.observeAt(org, shared.ID{}, "1.4.2", software.ClassBanner, 65, now.Add(-120*time.Hour))
	e.run()
	for i := 0; i < 8; i++ {
		v := "2.0.1"
		if i%2 == 1 {
			v = "1.4.2"
		}
		e.observeAt(org, asset, v, software.ClassBanner, 65, now.Add(time.Duration(-100+i*12)*time.Hour))
		e.run()
	}
	got := e.findings(org)
	require.Len(t, got, 1)
	assert.Equal(t, "new", got[0].Status)
	pending, _, _ := e.proposals(org)
	assert.Zero(t, pending)
}

// Review mode: a strong reading of the fixed version proposes the close
// with the change as evidence; the affected version established again
// (rollback) cancels the proposal.
func TestVersionHistory_ProposalEvidenceAndCancelOnRollback(t *testing.T) {
	e := newMatchEnv(t)
	e.svc.SetClosureSettings(reviewClosing{})
	org := e.tenant("vh-review", true)
	now := time.Now().UTC()
	asset := e.observeAt(org, shared.ID{}, "1.4.2", software.ClassBanner, 65, now.Add(-48*time.Hour))
	e.run()
	e.observeAt(org, asset, "2.0.1", software.ClassProbe, 90, now.Add(-24*time.Hour))
	e.run()
	pending, _, ev := e.proposals(org)
	require.Equal(t, 1, pending)
	assert.Equal(t, "version_changed", ev["kind"])
	assert.Equal(t, "1.4.2", ev["from_version"])
	assert.Equal(t, "2.0.1", ev["to_version"])
	assert.Equal(t, "probe", ev["to_evidence_class"])
	assert.EqualValues(t, 90, ev["to_confidence"])
	assert.Equal(t, "service", ev["to_source"])
	assert.NotContains(t, ev, "evidence", "no source text in the proposal")
	assert.Equal(t, "new", e.findings(org)[0].Status)

	e.observeAt(org, asset, "1.4.2", software.ClassProbe, 90, now.Add(-1*time.Hour))
	e.run()
	pending, canceled, _ := e.proposals(org)
	assert.Zero(t, pending, "the version came back: the proposal is canceled")
	assert.Equal(t, 1, canceled)
	assert.Equal(t, "new", e.findings(org)[0].Status)
}

// An older scan arriving after a newer one only adds history: it never
// closes the finding.
func TestVersionHistory_OutOfOrderDoesNotClose(t *testing.T) {
	e := newMatchEnv(t)
	org := e.tenant("vh-order", true)
	now := time.Now().UTC()
	asset := e.observeAt(org, shared.ID{}, "1.4.2", software.ClassBanner, 65, now.Add(-time.Hour))
	e.run()
	e.observeAt(org, asset, "2.0.1", software.ClassProbe, 95, now.Add(-72*time.Hour))
	e.run()
	assert.Equal(t, "new", e.findings(org)[0].Status)
}

// Every history read and write is the tenant's own: another tenant's
// LinkStates on the same keys sees nothing, and its proposal cancel touches
// nothing.
func TestVersionHistory_TenantIsolation(t *testing.T) {
	e := newMatchEnv(t)
	e.svc.SetClosureSettings(reviewClosing{})
	a := e.tenant("vh-iso-a", true)
	b := e.tenant("vh-iso-b", true)
	now := time.Now().UTC()
	asset := e.observeAt(a, shared.ID{}, "1.4.2", software.ClassBanner, 65, now.Add(-48*time.Hour))
	e.run()
	e.observeAt(a, asset, "2.0.1", software.ClassProbe, 90, now.Add(-24*time.Hour))
	e.run()
	pending, _, _ := e.proposals(a)
	require.Equal(t, 1, pending)

	store := postgres.NewSoftwareMatchRepository(e.pdb)
	ctx := context.Background()
	var fid, pid, vid string
	require.NoError(t, e.pdb.QueryRow(`SELECT f.id, s.product_id, s.software_version_id FROM findings f
		JOIN asset_software s ON s.tenant_id = f.tenant_id AND s.asset_id = f.asset_id
		JOIN software_versions v ON v.id = s.software_version_id AND v.raw = '1.4.2'
		WHERE f.tenant_id = $1 AND f.cve_id = $2`, a.String(), e.cveID).Scan(&fid, &pid, &vid))
	key := softwarematch.LinkKey{AssetID: asset, ProductID: shared.MustIDFromString(pid), VersionID: shared.MustIDFromString(vid), Location: "tcp/443"}
	states, err := store.LinkStates(ctx, b, []softwarematch.LinkKey{key}, now.Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, softwarematch.LinkGone, states[key].State)
	assert.Nil(t, states[key].Now, "no other tenant's version leaks")
	statesA, err := store.LinkStates(ctx, a, []softwarematch.LinkKey{key}, now.Add(-30*24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, softwarematch.LinkUpgraded, statesA[key].State)
	assert.Equal(t, "2.0.1", statesA[key].Now.Version)

	n, err := store.CancelVersionProposals(ctx, b, []shared.ID{shared.MustIDFromString(fid)})
	require.NoError(t, err)
	assert.Zero(t, n)
	pending, _, _ = e.proposals(a)
	assert.Equal(t, 1, pending)
}

// The asset's software list shows established versions only; a candidate
// waits in the history.
func TestVersionHistory_ListShowsEstablished(t *testing.T) {
	e := newMatchEnv(t)
	org := e.tenant("vh-list", true)
	now := time.Now().UTC()
	asset := e.observeAt(org, shared.ID{}, "1.4.2", software.ClassBanner, 65, now.Add(-48*time.Hour))
	e.observeAt(org, asset, "2.0.1", software.ClassBanner, 65, now.Add(-24*time.Hour))
	links, err := e.sw.ListAssetLinks(context.Background(), org, asset)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, "1.4.2", links[0].Version)
	assert.Equal(t, software.ClassBanner, links[0].Class)
	var state string
	var sightings int
	require.NoError(t, e.pdb.QueryRow(`SELECT s.version_state, s.sightings FROM asset_software s
		JOIN software_versions v ON v.id = s.software_version_id WHERE s.tenant_id = $1 AND s.asset_id = $2 AND v.raw = '2.0.1'`,
		org.String(), asset.String()).Scan(&state, &sightings))
	assert.Equal(t, "candidate", state)
	assert.Equal(t, 1, sightings)
}
