package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const testPastedJWKS = `{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`

// A trust configuration stores its key source and pasted keys as given, per
// tenant, and the last verifying kid follows the exchanges.
func TestCITrustSigningKeysRepository_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	now := time.Now().UTC().Truncate(time.Second)
	c := &cirun.TrustConfig{ID: shared.NewID(), TenantID: tenant, Name: "self-managed", Provider: cirun.ProviderGitLab,
		Issuer: "https://gitlab.example.com", Audience: cirun.DefaultAudience(tenant), DefaultBranch: "main", Enabled: true,
		Rules: cirun.Rules{Owners: []string{"acme"}}, CreatedAt: now,
		KeySource: cirun.KeySourcePasted, SigningKeys: testPastedJWKS, SigningKeysUpdatedAt: &now}
	if err := repo.CreateTrustConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetTrustConfig(ctx, tenant, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeySource != cirun.KeySourcePasted || got.SigningKeys != testPastedJWKS ||
		got.SigningKeysUpdatedAt == nil || !got.SigningKeysUpdatedAt.Equal(now) || got.LastKeyID != "" {
		t.Fatalf("stored = %q %q %v %q", got.KeySource, got.SigningKeys, got.SigningKeysUpdatedAt, got.LastKeyID)
	}
	if _, err := repo.GetTrustConfig(ctx, other, c.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}

	// The last verifying key is recorded, kept on an exchange without a
	// kid, and a new kid is written at once (no once-a-minute wait).
	if err := repo.TouchTrustConfig(ctx, tenant, c.ID, now, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := repo.TouchTrustConfig(ctx, tenant, c.ID, now.Add(2*time.Minute), ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetTrustConfig(ctx, tenant, c.ID); got.LastKeyID != "k1" {
		t.Fatalf("last key = %q, want k1", got.LastKeyID)
	}
	if err := repo.TouchTrustConfig(ctx, tenant, c.ID, now.Add(2*time.Minute+time.Second), "k2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetTrustConfig(ctx, tenant, c.ID); got.LastKeyID != "k2" {
		t.Fatalf("rotated key not recorded: %q", got.LastKeyID)
	}
	// Another tenant's touch never writes this row.
	if err := repo.TouchTrustConfig(ctx, other, c.ID, now.Add(time.Hour), "evil"); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetTrustConfig(ctx, tenant, c.ID); got.LastKeyID != "k2" {
		t.Fatalf("cross-tenant touch wrote %q", got.LastKeyID)
	}

	// Back to fetch: the keys are cleared by the update.
	c.KeySource, c.SigningKeys, c.SigningKeysUpdatedAt = cirun.KeySourceFetch, "", nil
	if err := repo.UpdateTrustConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetTrustConfig(ctx, tenant, c.ID); got.KeySource != cirun.KeySourceFetch || got.SigningKeys != "" {
		t.Fatalf("after update = %q %q", got.KeySource, got.SigningKeys)
	}

	// The database refuses pasted mode without keys and an unknown source.
	if _, err := db.ExecContext(ctx, `UPDATE ci_trust_configs SET key_source = 'pasted', signing_keys = NULL WHERE id = $1`, c.ID.String()); err == nil {
		t.Fatal("pasted mode without keys stored")
	}
	if _, err := db.ExecContext(ctx, `UPDATE ci_trust_configs SET key_source = 'sensor' WHERE id = $1`, c.ID.String()); err == nil {
		t.Fatal("unknown key source stored")
	}
	// Existing rows (inserted without the new columns) fetch.
	legacy := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO ci_trust_configs (id, tenant_id, name, provider, issuer, audience)
		VALUES ($1, $2, 'gh', 'github', $3, 'aud')`, legacy.String(), tenant.String(), cirun.GitHubIssuer); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetTrustConfig(ctx, tenant, legacy); got.KeySource != cirun.KeySourceFetch || got.SigningKeys != "" {
		t.Fatalf("legacy row = %q %q", got.KeySource, got.SigningKeys)
	}
}
