package main

// A campaign resolve is a "mark fixed" on a migrated database: the
// composition-root adapter sends the campaign's open findings through the
// finding bulk path with the legal steps, so findings nobody has picked up
// yet (new, confirmed) reach fix_applied, a finding already claimed is
// skipped, the asset owner's claim is the only one accepted, and every
// finding not updated comes back with a reason.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestCampaignResolve_MarksFixedThroughLegalSteps(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}

	tenant, owner, stranger, asset := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant.String(), "cmf-"+tenant.String())
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant.String())
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM users WHERE id = ANY($1::uuid[])`, "{"+owner.String()+","+stranger.String()+"}")
	})
	for _, u := range []shared.ID{owner, stranger} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'cmf')`, u.String(), u.String()+"@cmf.test")
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), tenant.String())
	}
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'cmf-asset', 'domain', 'public', 'high')`,
		asset.String(), tenant.String())
	exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'owner_ref')`,
		asset.String(), owner.String())
	ids := map[string]shared.ID{}
	for _, st := range []string{"new", "confirmed", "fix_applied"} {
		id := shared.NewID()
		ids[st] = id
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 'cmf-tool', 'cmf finding', 'high', $1::text, $4)`,
			id.String(), tenant.String(), asset.String(), st)
	}

	db := &postgres.DB{DB: sqlDB}
	log := logger.NewNop()
	findingRepo := postgres.NewFindingRepository(db)
	accessRepo := postgres.NewAccessControlRepository(db)
	vuln := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), findingRepo, log)
	vuln.SetAccessControlRepository(accessRepo)
	actions := finding.NewFindingActionsService(findingRepo, accessRepo, nil, postgres.NewAssetRepository(db), nil, sqlDB, log)
	vuln.SetFixApplierCheck(actions.FixAppliers)
	queued := 0
	vuln.SetProofOfFixQueuer(func(_ context.Context, _ shared.ID, ids []shared.ID) int { queued += len(ids); return len(ids) })

	resolver := campaignFindingResolver{vuln: vuln}
	filter := vulnerability.NewFindingFilter().WithTenantID(tenant).
		WithFindingIDs([]string{ids["new"].String(), ids["confirmed"].String(), ids["fix_applied"].String()})
	claim := func(actor shared.ID) *exposure.CampaignResolveResult {
		t.Helper()
		res, err := resolver.ResolveOpenByFilter(ctx, tenant.String(), filter, exposure.CampaignResolveInput{
			Resolution: "patched", ActorID: actor.String(), HasFixApplyPermission: true,
		})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		return res
	}
	status := func(id shared.ID) string {
		var s string
		if err := sqlDB.QueryRowContext(ctx, `SELECT status FROM findings WHERE id = $1 AND tenant_id = $2`, id.String(), tenant.String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Not the stranger's findings: nothing moves, each one has a reason.
	res := claim(stranger)
	if res.Updated != 0 || res.Failed != 2 || res.Skipped != 1 || len(res.Rows) != 3 {
		t.Errorf("stranger = %+v, want 0 updated, 2 refused, 1 skipped with reasons", res)
	}
	for _, r := range res.Rows {
		if r.Reason == "" {
			t.Errorf("row without a reason: %+v", r)
		}
	}
	if status(ids["new"]) != "new" {
		t.Fatal("a stranger's claim moved a finding")
	}

	// The asset owner: new and confirmed reach fix_applied; the claimed one
	// is skipped; one proof-of-fix re-check per finding claimed.
	res = claim(owner)
	if res.Updated != 2 || res.Skipped != 1 || res.Failed != 0 || res.ValidationsQueued != 2 || queued != 2 {
		t.Errorf("owner = %+v (queued %d), want 2 updated, 1 skipped, 2 re-checks", res, queued)
	}
	for _, st := range []string{"new", "confirmed", "fix_applied"} {
		if got := status(ids[st]); got != "fix_applied" {
			t.Errorf("%s finding is %s, want fix_applied", st, got)
		}
	}
}
