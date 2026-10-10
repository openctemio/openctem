package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// A soft-deleted asset (owner decision O3) is invisible to every read path a
// person or a worker uses: search, the graph, tag facets, ingest correlation,
// groups, scope rules, bulk actions, and the exposure lists and counts. The
// same reads of another tenant are unaffected.
func TestAssetSoftDelete_InvisibleToSearchGraphGroupsIngestAndExposures(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	pdb := &DB{DB: db}
	repo := NewAssetRepository(pdb)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	victim := seedOwnedAsset(ctx, t, db, tenant, nil)
	keep := seedOwnedAsset(ctx, t, db, tenant, nil)
	foreign := seedOwnedAsset(ctx, t, db, other, nil)
	suffix := victim.String()[:8]
	searchTerm := "sdreads-" + suffix
	victimName := searchTerm + "-victim.example.com"
	ip := "10.250." + "0.9"
	exec(`UPDATE assets SET name = $2, tags = ARRAY['sd-only-'||$3, 'sd-shared'], external_id = 'ext-'||$3,
	        properties = jsonb_build_object('ip', $4::text), risk_score = 90 WHERE id = $1`,
		victim.String(), victimName, suffix, ip)
	exec(`UPDATE assets SET name = $2, tags = ARRAY['sd-shared'], risk_score = 10 WHERE id = $1`,
		keep.String(), searchTerm+"-keep.example.com")
	exec(`UPDATE assets SET name = $2, tags = ARRAY['sd-only-'||$3], external_id = 'ext-'||$3,
	        properties = jsonb_build_object('ip', $4::text) WHERE id = $1`,
		foreign.String(), victimName, suffix, ip)

	group := shared.NewID()
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'sd-reads')`, group.String(), tenant.String())
	exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2), ($1, $3)`, group.String(), victim.String(), keep.String())
	for _, a := range []struct {
		tenant, asset shared.ID
		fp            string
	}{{tenant, victim, "sd-v-" + suffix}, {tenant, keep, "sd-k-" + suffix}, {other, foreign, "sd-f-" + suffix}} {
		exec(`INSERT INTO exposure_events (tenant_id, asset_id, event_type, severity, state, title, fingerprint, source)
		      VALUES ($1, $2, 'port_open', 'critical', 'active', 'open port', $3, 'test')`,
			a.tenant.String(), a.asset.String(), a.fp)
	}

	if err := repo.Delete(ctx, tenant, victim, nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	tid := tenant.String()

	// Search.
	res, err := repo.List(ctx, asset.Filter{TenantID: &tid}.WithSearch(searchTerm), asset.ListOptions{}, pagination.New(1, 50))
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Data) != 1 || res.Data[0].ID() != keep {
		t.Errorf("search returned %d (total %d), want only the live asset", len(res.Data), res.Total)
	}

	// Graph nodes (attack paths, exposure chains).
	nodes, err := repo.ListAllNodes(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.ID == victim.String() {
			t.Error("graph lists the deleted asset as a node")
		}
	}

	// Tag facets.
	tags, err := repo.ListDistinctTags(ctx, tenant, asset.AccessScope{}, "sd-", nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range tags {
		if tag == "sd-only-"+suffix {
			t.Error("tag facets list a tag only the deleted asset had")
		}
	}

	// Ingest correlation never resolves to the deleted row, in this tenant;
	// the other tenant's asset with the same identity still resolves.
	if a, err := repo.FindByIP(ctx, tenant, ip); err != nil || a != nil {
		t.Errorf("FindByIP = %v, %v; want nothing", a, err)
	}
	if byIPs, err := repo.FindByIPs(ctx, tenant, []string{ip}); err != nil || len(byIPs[ip]) != 0 {
		t.Errorf("FindByIPs = %v, %v; want nothing", byIPs, err)
	}
	if a, err := repo.FindByExternalID(ctx, tenant, "ext-"+suffix); err != nil || a != nil {
		t.Errorf("FindByExternalID = %v, %v; want nothing", a, err)
	}
	if byName, err := repo.GetByNames(ctx, tenant, []string{victimName}); err != nil || len(byName) != 0 {
		t.Errorf("GetByNames = %v, %v; want nothing", byName, err)
	}
	if a, err := repo.FindByIP(ctx, other, ip); err != nil || a == nil || a.ID() != foreign {
		t.Errorf("other tenant FindByIP = %v, %v; want its own asset", a, err)
	}

	// Averages and bulk actions ignore it.
	if avg, err := repo.GetAverageRiskScore(ctx, tenant); err != nil || avg != 10 {
		t.Errorf("average risk = %v, %v; want 10 (the live asset only)", avg, err)
	}
	if n, err := repo.BulkUpdateStatus(ctx, tenant, []shared.ID{victim, keep}, asset.StatusArchived); err != nil || n != 1 {
		t.Errorf("BulkUpdateStatus = %d, %v; want only the live asset updated", n, err)
	}

	// Groups.
	groups := NewAssetGroupRepository(pdb)
	members, err := groups.GetGroupAssets(ctx, group, pagination.New(1, 50), nil)
	if err != nil {
		t.Fatal(err)
	}
	if members.Total != 1 || len(members.Data) != 1 || members.Data[0].ID != keep {
		t.Errorf("group members = %d (total %d), want only the live asset", len(members.Data), members.Total)
	}
	if err := groups.RecalculateCounts(ctx, group); err != nil {
		t.Fatal(err)
	}
	if n := countRows(ctx, t, db, `SELECT asset_count FROM asset_groups WHERE id = $1`, group.String()); n != 1 {
		t.Errorf("group asset_count = %d, want 1", n)
	}

	// Scope rules never match it.
	ac := NewAccessControlRepository(pdb)
	matched, err := ac.FindAssetsByTagMatch(ctx, tenant, []string{"sd-only-" + suffix}, accesscontrol.MatchLogicAny)
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 0 {
		t.Errorf("tag scope rule matched %v, want nothing", matched)
	}

	// Exposures: not listed and not counted; the other tenant's still are.
	exposures := NewExposureRepository(pdb)
	list, err := exposures.List(ctx, exposure.Filter{TenantID: &tid}, exposure.ListOptions{}, pagination.New(1, 50))
	if err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 {
		t.Errorf("exposure list total = %d, want 1", list.Total)
	}
	byState, err := exposures.CountByState(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if byState[exposure.StateActive] != 1 {
		t.Errorf("active exposures = %d, want 1 (the deleted asset's are history)", byState[exposure.StateActive])
	}
	bySeverity, err := exposures.CountBySeverity(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if bySeverity[exposure.SeverityCritical] != 1 {
		t.Errorf("critical exposures = %d, want 1", bySeverity[exposure.SeverityCritical])
	}
	if os, err := exposures.CountByState(ctx, other); err != nil || os[exposure.StateActive] != 1 {
		t.Errorf("other tenant active exposures = %v, %v; want 1", os, err)
	}

	// EASM overview counts.
	summary, err := NewEASMSummaryRepository(pdb).Summary(ctx, tenant, nil, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if summary.OpenBySeverity["critical"] != 1 {
		t.Errorf("EASM open critical = %d, want 1", summary.OpenBySeverity["critical"])
	}
	for _, r := range summary.TopRisks {
		if r.AssetID != nil && *r.AssetID == victim.String() {
			t.Error("EASM top risks list the deleted asset")
		}
	}
}
