package integration

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/bountyprogram"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/programtarget"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Program targets go through the standard asset ingest (RFC-065 §16.8):
// typed assets in the program's tenant only, recorded as the program's
// targets (so a mobile app with no entry is still a program asset), with
// the feed's source; an identical re-import changes nothing and writes no
// timeline event; another tenant's assets and programs are never touched.
func TestProgramTargets_IngestedThroughTheStandardPath(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant, other := seedLifecycleTenant(ctx, t, db), seedLifecycleTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(pg), postgres.NewFindingRepository(pg),
		postgres.NewVulnerabilityRepository(pg), postgres.NewComponentRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewBranchRepository(pg), postgres.NewTenantRepository(pg),
		postgres.NewAuditRepository(pg), logger.NewNop())
	assetSvc := assetapp.NewAssetService(postgres.NewAssetRepository(pg), logger.NewNop())
	assetSvc.SetAttributeSources(postgres.NewAssetAttributeSourceRepository(pg), postgres.NewTenantRepository(pg))
	svc.SetAttributeReconciler(assetSvc)
	programs := postgres.NewBountyProgramRepository(pg)
	g := programtarget.New(svc, programs)

	suffix := strings.ReplaceAll(tenant.String(), "-", "")[:10]
	items, err := bp.ParseScope("In scope:\nwww.t" + suffix + ".example\napi.t" + suffix + ".example:8443/tcp\nhttps://shop.t" + suffix + ".example/api/\n")
	if err != nil {
		t.Fatal(err)
	}
	app := bp.ClassifyTyped("com.t"+suffix+".app", "android_app")
	app.InScope = true
	items = append(items, app)
	now := time.Now().UTC()
	p := &bp.Program{ID: shared.NewID(), TenantID: tenant, Name: "PT " + suffix, Platform: "acme", Handle: "pt",
		Visibility: bp.VisibilityPublic, Status: bp.StatusPendingAttestation, ScopeSource: bp.ScopeSourcePublicFeed,
		ScopeItems: items, TermsSHA256: strings.Repeat("cd", 32), CreatedAt: now.Add(-time.Hour), UpdatedAt: now}
	if err := programs.Import(ctx, bp.ImportWrite{Program: p}); err != nil {
		t.Fatal(err)
	}
	// The organization already has www (exposure unknown): the program's
	// statement that it is public changes it once.
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`,
		shared.NewID().String(), tenant.String(), "www.t"+suffix+".example"); err != nil {
		t.Fatal(err)
	}
	src := bountyprogram.TargetSource{Name: bountyprogram.TargetSourceFeed, Feed: true, Run: "programfeed:7", ObservedAt: now.Add(-time.Minute)}
	if err := g.IngestProgramTargets(ctx, tenant, p.ID, src, bp.TargetAssets(items)); err != nil {
		t.Fatal(err)
	}

	types := assetTypesByName(t, db, tenant)
	for name, typ := range map[string]string{
		"www.t" + suffix + ".example":              "domain",
		"api.t" + suffix + ".example":              "domain",
		"com.t" + suffix + ".app":                  "application/mobile_app",
		"https://shop.t" + suffix + ".example/api": "application/website", // the standard path classifies a site URL
	} {
		if types[name] != typ {
			t.Errorf("%s: type %q, want %q (have %v)", name, types[name], typ, types)
		}
	}
	service := false
	for name, typ := range types {
		if strings.HasPrefix(typ, "service") && strings.Contains(name, "api.t"+suffix+".example") && strings.Contains(name, "8443") {
			service = true
		}
	}
	if !service {
		t.Errorf("no service asset for the port-limited target: %v", types)
	}
	if n := ptCount(t, db, `SELECT count(*) FROM assets WHERE tenant_id = $1`, other); n != 0 {
		t.Fatalf("another tenant got %d assets", n)
	}
	targets := ptCount(t, db, `SELECT count(*) FROM bounty_program_target_assets WHERE tenant_id = $1 AND program_id = $2`, tenant, p.ID)
	if targets != len(types) {
		t.Fatalf("program targets = %d, assets = %d", targets, len(types))
	}
	// The mobile app is a program asset (link, system tags) without any
	// scope entry; its source is the feed.
	if n := ptCount(t, db, `SELECT count(*) FROM asset_program_links l JOIN assets a ON a.tenant_id = l.tenant_id AND a.id = l.asset_id
		WHERE l.tenant_id = $1 AND l.program_id = $2 AND a.name = $3 AND 'bug-bounty' = ANY(a.system_tags)`, tenant, p.ID, "com.t"+suffix+".app"); n != 1 {
		t.Fatalf("mobile app link = %d", n)
	}
	if n := ptCount(t, db, `SELECT count(*) FROM exposure_events WHERE tenant_id = $1`, tenant); n != 0 {
		t.Fatalf("a listed service opened %d exposures", n)
	}

	// The feed is the source of what it stated (exposure), with its run.
	if n := ptCount(t, db, `SELECT count(*) FROM asset_attribute_sources WHERE tenant_id = $1 AND source_kind = 'feed'
		AND source_name = 'programfeed' AND source_run = 'programfeed:7'`, tenant); n == 0 {
		t.Fatal("no attribute recorded with the feed source")
	}
	// An identical re-import (same feed record, same observation time),
	// and the same data seen again later: no new asset, no timeline event,
	// and the replay leaves the recorded observation untouched.
	events := ptCount(t, db, `SELECT count(*) FROM asset_change_events WHERE tenant_id = $1`, tenant)
	observed := func() string {
		var at string
		if err := db.QueryRow(`SELECT max(observed_at)::text FROM asset_attribute_sources WHERE tenant_id = $1 AND source_kind = 'feed'`,
			tenant.String()).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	before := observed()
	assets := ptCount(t, db, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tenant)
	if err := g.IngestProgramTargets(ctx, tenant, p.ID, src, bp.TargetAssets(items)); err != nil {
		t.Fatal(err)
	}
	if after := observed(); after != before {
		t.Fatalf("a replay rewrote the observation: %s -> %s", before, after)
	}
	later := src
	later.Run, later.ObservedAt = "programfeed:8", now
	if err := g.IngestProgramTargets(ctx, tenant, p.ID, later, bp.TargetAssets(items)); err != nil {
		t.Fatal(err)
	}
	if e := ptCount(t, db, `SELECT count(*) FROM asset_change_events WHERE tenant_id = $1`, tenant); e != events {
		t.Fatalf("re-import wrote %d timeline events", e-events)
	}
	if a := ptCount(t, db, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tenant); a != assets {
		t.Fatalf("re-import made %d assets", a-assets)
	}

	// Cross-tenant: another tenant cannot record targets on this program,
	// and an id of another tenant's asset is never recorded.
	foreign := shared.NewID()
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'x.foreign.example', 'domain')`,
		foreign.String(), other.String()); err != nil {
		t.Fatal(err)
	}
	if err := programs.ReplaceTargetAssets(ctx, other, p.ID, map[shared.ID]string{foreign: "x"}); !errors.Is(err, bp.ErrNotFound) {
		t.Fatalf("another tenant wrote program targets: %v", err)
	}
	if err := programs.ReplaceTargetAssets(ctx, tenant, p.ID, map[shared.ID]string{foreign: "x"}); err != nil {
		t.Fatal(err)
	}
	if n := ptCount(t, db, `SELECT count(*) FROM bounty_program_target_assets WHERE asset_id = $1`, foreign); n != 0 {
		t.Fatal("another tenant's asset recorded as a program target")
	}
	// An ended program (no assets) keeps no targets; the assets stay.
	if err := g.IngestProgramTargets(ctx, tenant, p.ID, src, nil); err != nil {
		t.Fatal(err)
	}
	if n := ptCount(t, db, `SELECT count(*) FROM asset_program_links WHERE tenant_id = $1 AND program_id = $2`, tenant, p.ID); n != 0 {
		t.Fatalf("links left: %d", n)
	}
}

func assetTypesByName(t *testing.T, db *sql.DB, tenant shared.ID) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT name, asset_type || COALESCE(NULLIF('/' || sub_type, '/'), '') FROM assets WHERE tenant_id = $1`, tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var n, typ string
		if err := rows.Scan(&n, &typ); err != nil {
			t.Fatal(err)
		}
		out[n] = typ
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func ptCount(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	for i, a := range args {
		if id, ok := a.(shared.ID); ok {
			args[i] = id.String()
		}
	}
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
	return n
}
