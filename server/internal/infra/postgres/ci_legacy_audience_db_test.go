package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The legacy audience of a trust configuration is read with it, survives an
// edit that keeps the audience and ends with one that changes it. A
// pipeline's move to the new audience is recorded once, per tenant.
func TestCILegacyAudience_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	now := time.Now().UTC()
	c := &cirun.TrustConfig{ID: shared.NewID(), TenantID: tenant, Name: "gh", Provider: cirun.ProviderGitHub,
		Issuer: cirun.GitHubIssuer, Audience: cirun.DefaultAudience(tenant), DefaultBranch: "main", Enabled: true,
		Rules: cirun.Rules{Owners: []string{"acme"}}, CreatedAt: now}
	if err := repo.CreateTrustConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE ci_trust_configs SET legacy_audience = 'https://openctem.example.com',
		legacy_audience_until = now() + interval '90 days' WHERE id = $1`, c.ID.String()); err != nil {
		t.Fatal(err)
	}
	read := func() cirun.TrustConfig {
		t.Helper()
		cs, err := repo.EnabledTrustConfigs(ctx, tenant, cirun.GitHubIssuer)
		if err != nil || len(cs) != 1 {
			t.Fatalf("configs: %v %v", cs, err)
		}
		return cs[0]
	}
	got := read()
	if got.LegacyAudience != "https://openctem.example.com" || got.LegacyAudienceUntil == nil || !got.LegacyAccepted(got.LegacyAudience, now) {
		t.Fatalf("legacy audience not read: %+v", got)
	}
	got.Name = "renamed"
	if err := repo.UpdateTrustConfig(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if again := read(); again.LegacyAudience == "" {
		t.Fatal("an edit that keeps the audience dropped the legacy audience")
	}
	got.Audience = cirun.DefaultAudience(tenant) + ":v2"
	if err := repo.UpdateTrustConfig(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if again := read(); again.LegacyAudience != "" || again.LegacyAudienceUntil != nil {
		t.Fatalf("a changed audience kept the legacy one: %+v", again)
	}

	asset := seedTestAsset(ctx, t, db, tenant)
	key := cirun.PipelineKey{Provider: cirun.ProviderGitHub, Issuer: cirun.GitHubIssuer, ExternalRepoID: "4242", WorkflowPath: ".github/workflows/scan.yml"}
	if exists, _, err := repo.PipelineAudienceState(ctx, tenant, key); err != nil || exists {
		t.Fatalf("unknown pipeline: %v %v", exists, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO ci_pipelines (id, tenant_id, provider, issuer, external_repo_id,
		workflow_path, repository_asset_id) VALUES ($1, $2, 'github', $3, '4242', '.github/workflows/scan.yml', $4)`,
		shared.NewID().String(), tenant.String(), cirun.GitHubIssuer, asset.String()); err != nil {
		t.Fatal(err)
	}
	if exists, upgraded, err := repo.PipelineAudienceState(ctx, tenant, key); err != nil || !exists || upgraded {
		t.Fatalf("existing pipeline: %v %v %v", exists, upgraded, err)
	}
	// Another tenant cannot mark or see this tenant's pipeline.
	if err := repo.MarkPipelineAudienceUpgraded(ctx, other, key, now); err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := repo.PipelineAudienceState(ctx, other, key); exists {
		t.Fatal("another tenant sees the pipeline")
	}
	if _, upgraded, _ := repo.PipelineAudienceState(ctx, tenant, key); upgraded {
		t.Fatal("another tenant's mark moved this tenant's pipeline")
	}
	if err := repo.MarkPipelineAudienceUpgraded(ctx, tenant, key, now); err != nil {
		t.Fatal(err)
	}
	if _, upgraded, _ := repo.PipelineAudienceState(ctx, tenant, key); !upgraded {
		t.Fatal("the move to the new audience was not recorded")
	}
}
