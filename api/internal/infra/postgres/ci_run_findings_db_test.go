package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The CI gate honors a suppression only while its rule applies: approved, not
// expired, in the run's tenant. A link row left behind by a rule that expired
// (the expiry job reopens the finding but keeps the row) or was never approved
// must not let the finding pass the gate. Requires DATABASE_URL.
func TestCIRunFindingsHonorActiveSuppressionsOnly(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()

	exp := now.Add(10 * time.Minute)
	_, hash, err := cirun.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	run := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: asset, Provider: cirun.ProviderGitHub,
		Issuer: cirun.GitHubIssuer, Repository: "github.com/acme/api", Ref: "refs/heads/feature", Branch: "feature",
		CommitSHA: "abcdef1234567", Status: cirun.StatusRunning, TokenHash: hash, TokenExpiresAt: &exp,
		CreatedAt: now, UpdatedAt: now}
	if err := repo.CreateRun(ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}

	finding := func(fp string) string {
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
				severity, fingerprint, status) VALUES ($1, $2, $3, 'sast', 'semgrep', 'm', 'high', $4, 'new')`,
			id, tenant.String(), asset.String(), fp); err != nil {
			t.Fatalf("seed finding %s: %v", fp, err)
		}
		return id
	}
	rule := func(tid shared.ID, status string, expires *time.Time) string {
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO suppression_rules (id, tenant_id, rule_id, name, status, expires_at)
				VALUES ($1, $2, 'r1', 'rule', $3, COALESCE($4::timestamptz, NOW() + interval '30 days'))`, id, tid.String(), status, expires); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
		return id
	}
	link := func(findingID, ruleID string) {
		if _, err := db.ExecContext(ctx, `INSERT INTO finding_suppressions (finding_id, suppression_rule_id) VALUES ($1, $2)`,
			findingID, ruleID); err != nil {
			t.Fatalf("link suppression: %v", err)
		}
	}

	past := now.Add(-time.Hour)
	future := now.Add(24 * time.Hour)
	cases := map[string]struct {
		ruleTenant shared.ID
		status     string
		expires    *time.Time
		honored    bool
	}{
		"fp-approved":          {tenant, "approved", nil, true},
		"fp-approved-future":   {tenant, "approved", &future, true},
		"fp-approved-past":     {tenant, "approved", &past, false}, // expiry job has not run yet
		"fp-expired":           {tenant, "expired", &past, false},  // expiry job ran, link row kept
		"fp-pending":           {tenant, "pending", nil, false},
		"fp-rejected":          {tenant, "rejected", nil, false},
		"fp-other-tenant-rule": {other, "approved", nil, false},
	}
	fps := []string{"fp-unsuppressed"}
	finding("fp-unsuppressed")
	for fp, c := range cases {
		link(finding(fp), rule(c.ruleTenant, c.status, c.expires))
		fps = append(fps, fp)
	}
	if err := repo.ReserveRunReport(ctx, tenant, run.ID); err != nil {
		t.Fatalf("reserve run report: %v", err)
	}
	if err := repo.RecordRunReport(ctx, tenant, run.ID, fps); err != nil {
		t.Fatalf("record run report: %v", err)
	}

	got, err := repo.RunFindings(ctx, tenant, run.ID, asset)
	if err != nil {
		t.Fatalf("run findings: %v", err)
	}
	if len(got) != len(fps) {
		t.Fatalf("run findings: got %d, want %d", len(got), len(fps))
	}
	for _, f := range got {
		want := cases[f.Fingerprint].honored // false for fp-unsuppressed
		if f.Suppressed != want {
			t.Errorf("%s: suppressed = %v, want %v", f.Fingerprint, f.Suppressed, want)
		}
	}

	// Cross-tenant: the other tenant reads none of the run's findings.
	if rows, err := repo.RunFindings(ctx, other, run.ID, asset); err != nil || len(rows) != 0 {
		t.Fatalf("cross-tenant run findings: %d %v", len(rows), err)
	}
}
