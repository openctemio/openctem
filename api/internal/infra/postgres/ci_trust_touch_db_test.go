package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The trust configuration row is shared by every pipeline, so a burst of
// token exchanges writes it at most once a minute.
func TestTouchTrustConfig_WritesAtMostOncePerMinute_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := newIngestJobTestTenant(t, db)
	repo := NewCIRunRepository(&DB{DB: db})
	trust := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO ci_trust_configs (id, tenant_id, name, provider, issuer, audience)
		VALUES ($1, $2, 'gh', 'github', $3, 'aud')`, trust.String(), tenant.String(), cirun.GitHubIssuer); err != nil {
		t.Fatal(err)
	}
	lastUsed := func() time.Time {
		var at time.Time
		if err := db.QueryRowContext(ctx, `SELECT last_used_at FROM ci_trust_configs WHERE id = $1`, trust.String()).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	t0 := time.Now().UTC().Truncate(time.Second)
	if err := repo.TouchTrustConfig(ctx, tenant, trust, t0); err != nil {
		t.Fatal(err)
	}
	if got := lastUsed(); !got.Equal(t0) {
		t.Fatalf("first touch wrote %v, want %v", got, t0)
	}
	if err := repo.TouchTrustConfig(ctx, tenant, trust, t0.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := lastUsed(); !got.Equal(t0) {
		t.Fatalf("a touch within a minute rewrote the row: %v", got)
	}
	if err := repo.TouchTrustConfig(ctx, tenant, trust, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := lastUsed(); !got.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("a touch after a minute did not write: %v", got)
	}
	// Another tenant's touch never changes this row.
	if err := repo.TouchTrustConfig(ctx, newIngestJobTestTenant(t, db), trust, t0.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := lastUsed(); !got.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("cross-tenant touch wrote: %v", got)
	}
}
