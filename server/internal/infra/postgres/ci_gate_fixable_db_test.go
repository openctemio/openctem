package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fixable_only round-trips on a policy, and a run's findings carry whether a
// fixed version exists (findings.remediation fix_available).
func TestCIGateFixableOnly(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()

	p := &cirun.GatePolicy{ID: shared.NewID(), TenantID: tenant, ScopeType: cirun.ScopeTenant, Enabled: true,
		Mode: cirun.ModeEnforce, FailOnSeverity: "high", FixableOnly: true, AllowRepoPolicy: true, CreatedAt: now}
	if err := repo.CreateGatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetGatePolicy(ctx, tenant, p.ID)
	if err != nil || !got.FixableOnly {
		t.Fatalf("created: %+v %v", got, err)
	}
	got.FixableOnly = false
	if err := repo.UpdateGatePolicy(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := repo.GetGatePolicy(ctx, tenant, p.ID); again.FixableOnly {
		t.Fatal("update did not store fixable_only")
	}

	_, hash, _ := cirun.NewToken()
	exp := now.Add(10 * time.Minute)
	run := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: asset, Provider: cirun.ProviderGitHub,
		Issuer: cirun.GitHubIssuer, Repository: "github.com/acme/api", Ref: "refs/heads/main", Branch: "main",
		CommitSHA: "abcdef1234567", Status: cirun.StatusRunning, TokenHash: hash, TokenExpiresAt: &exp, CreatedAt: now, UpdatedAt: now}
	if err := repo.CreateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	for fp, remediation := range map[string]any{"fp-fix": `{"fix_available": true}`, "fp-nofix": `{"fix_available": false}`, "fp-none": nil} {
		if _, err := db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity,
				fingerprint, status, remediation) VALUES ($1, $2, $3, 'sca', 'trivy', 'm', 'high', $4, 'new', $5::jsonb)`,
			shared.NewID().String(), tenant.String(), asset.String(), fp, remediation); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.RecordRunReport(ctx, tenant, run.ID, []string{"fp-fix", "fp-nofix", "fp-none"}); err != nil {
		t.Fatal(err)
	}
	findings, err := repo.RunFindings(ctx, tenant, run.ID, asset)
	if err != nil {
		t.Fatal(err)
	}
	fix := map[string]bool{}
	for _, f := range findings {
		fix[f.Fingerprint] = f.FixAvailable
	}
	if len(fix) != 3 || !fix["fp-fix"] || fix["fp-nofix"] || fix["fp-none"] {
		t.Fatalf("fix available: %v", fix)
	}
}
