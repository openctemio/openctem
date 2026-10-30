package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Revoking a person's API keys after a credential change reaches their keys
// in every organization and nobody else's: another user's keys and keys with
// no owner stay active.
func TestAPIKeyRepository_RevokeByUserAcrossTenants(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'revoke-by-user', $2)`, id.String(), "rbu-"+id.String()[24:])
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	user := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'rbu')`, id.String(), "rbu-"+id.String()[24:]+"@it.test")
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id.String()) })
		return id
	}
	a, b := tenant(), tenant()
	victim, other := user(), user()
	key := func(tn, owner shared.ID, name, status string) {
		var o any
		if !owner.IsZero() {
			o = owner.String()
		}
		exec(`INSERT INTO api_keys (tenant_id, user_id, name, key_hash, key_prefix, status) VALUES ($1, $2, $3, $5, 'ctem_x', $4)`,
			tn.String(), o, name, status, shared.NewID().String())
	}
	key(a, victim, "v-a", "active")
	key(b, victim, "v-b", "active")
	key(a, victim, "v-old", "revoked")
	key(a, other, "o-a", "active")
	key(a, shared.ID{}, "service", "active")

	repo := NewAPIKeyRepository(&DB{DB: db})
	now := time.Now()
	if n, err := repo.CountActiveByUser(ctx, victim, now); err != nil || n != 2 {
		t.Fatalf("count before: %d %v, want 2", n, err)
	}
	if n, err := repo.RevokeByUser(ctx, victim, victim, now); err != nil || n != 2 {
		t.Fatalf("RevokeByUser: %d %v, want 2 (both tenants)", n, err)
	}
	if n, _ := repo.CountActiveByUser(ctx, victim, now); n != 0 {
		t.Fatalf("victim still has %d active keys", n)
	}
	if n, _ := repo.CountActiveByUser(ctx, other, now); n != 1 {
		t.Fatalf("another user's key was revoked (active=%d)", n)
	}
	var active int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM api_keys WHERE name = 'service' AND tenant_id = $1 AND status = 'active'`, a.String()).Scan(&active); err != nil || active != 1 {
		t.Fatalf("an ownerless key was revoked: %d %v", active, err)
	}
}
