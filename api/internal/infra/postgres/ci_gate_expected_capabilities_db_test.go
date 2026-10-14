package postgres

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run must report every capability its repository is expected to have;
// what it reported comes from its tools through the tool catalog.
func TestCIRunMissingExpectedCapabilities(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()

	newRun := func(tenantID, assetID shared.ID) *cirun.Run {
		t.Helper()
		_, hash, _ := cirun.NewToken()
		exp := now.Add(10 * time.Minute)
		run := &cirun.Run{ID: shared.NewID(), TenantID: tenantID, RepositoryAssetID: assetID, Provider: cirun.ProviderGitHub,
			Issuer: cirun.GitHubIssuer, Repository: "github.com/acme/api", Ref: "refs/pull/7/merge", Branch: "feature",
			CommitSHA: "abcdef1234567", Status: cirun.StatusRunning, TokenHash: hash, TokenExpiresAt: &exp, CreatedAt: now, UpdatedAt: now}
		if err := repo.CreateRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		return run
	}
	missing := func(run *cirun.Run) []string {
		t.Helper()
		got, err := repo.MissingExpectedCapabilities(ctx, run.TenantID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	run := newRun(tenant, asset)
	// No expectation: nothing is required.
	if got := missing(run); len(got) != 0 {
		t.Fatalf("no expectation, missing = %v", got)
	}

	// Expected sast and secrets; the run reported only a secrets scanner.
	if err := repo.UpsertExpectation(ctx, &cirun.Expectation{TenantID: tenant, RepositoryAssetID: asset,
		Capabilities: []cirun.Capability{cirun.CapabilitySAST, cirun.CapabilitySecrets}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordRunTools(ctx, tenant, run.ID, []cirun.ToolLabel{{Name: "betterleaks"}}); err != nil {
		t.Fatal(err)
	}
	if got := missing(run); !slices.Equal(got, []string{"sast"}) {
		t.Fatalf("missing = %v, want [sast]", got)
	}
	// Once a SAST tool reports (any case of its name), nothing is missing.
	if err := repo.RecordRunTools(ctx, tenant, run.ID, []cirun.ToolLabel{{Name: "Semgrep"}}); err != nil {
		t.Fatal(err)
	}
	if got := missing(run); len(got) != 0 {
		t.Fatalf("after semgrep, missing = %v", got)
	}

	// An empty expectation means every capability, in display order.
	if err := repo.UpsertExpectation(ctx, &cirun.Expectation{TenantID: tenant, RepositoryAssetID: asset,
		CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if got := missing(newRun(tenant, asset)); !slices.Equal(got, []string{"sast", "sca", "secrets", "iac"}) {
		t.Fatalf("every capability expected, missing = %v", got)
	}

	// Cross-tenant: another tenant's run on its own repository is not held to
	// this tenant's expectation, and this tenant's run id under the other
	// tenant answers nothing.
	otherAsset := seedTestAsset(ctx, t, db, other)
	if got := missing(newRun(other, otherAsset)); len(got) != 0 {
		t.Fatalf("other tenant's run, missing = %v", got)
	}
	got, err := repo.MissingExpectedCapabilities(ctx, other, run.ID)
	if err != nil || len(got) != 0 {
		t.Fatalf("run id under another tenant: %v %v", got, err)
	}

	// A tenant's own tool counts only for that tenant.
	if _, err := db.ExecContext(ctx, `INSERT INTO tools (id, tenant_id, name, display_name, capabilities)
		VALUES ($1, $2, 'acme-sast', 'acme-sast', ARRAY['sast'])`, shared.NewID().String(), other.String()); err != nil {
		t.Skipf("tools table shape: %v", err)
	}
	r2 := newRun(tenant, asset)
	if err := repo.RecordRunTools(ctx, tenant, r2.ID, []cirun.ToolLabel{{Name: "acme-sast"}}); err != nil {
		t.Fatal(err)
	}
	if got := missing(r2); !slices.Contains(got, "sast") {
		t.Fatalf("another tenant's tool covered sast: missing = %v", got)
	}
}
