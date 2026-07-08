package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestAgentKeyExpiry_RoundTrip exercises the new key_expires_at column against
// the real agents schema: Create persists it, GetByAPIKeyHash (the auth read
// path, scanAgent) reads it back, and Update rewrites it. A missing scan target
// or a placeholder-numbering slip in either scanner would surface here rather
// than in the auth path at runtime. Skipped unless DATABASE_URL is set.
func TestAgentKeyExpiry_RoundTrip(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	// Seed a tenant (agents.tenant_id is NOT NULL REFERENCES tenants). Deleting
	// it CASCADE-removes the agent, so the test leaves no residue.
	tenantID := shared.NewID()
	slug := "keyexp-" + tenantID.String()[:8]
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "key-expiry-test", slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	}()

	repo := NewAgentRepository(&DB{DB: db})

	a, err := agent.NewAgent(tenantID, "expiry-agent", agent.AgentTypeRunner, "", nil, nil, agent.ExecutionModeStandalone)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	// Truncate to microseconds — Postgres TIMESTAMPTZ resolution — so the
	// equality assertions below aren't defeated by sub-microsecond drift.
	exp := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
	a.SetAPIKeyWithExpiry("hash-keyexp-1", "rda_keyexp1", &exp)

	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	got, err := repo.GetByAPIKeyHash(ctx, "hash-keyexp-1")
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if got.KeyExpiresAt == nil {
		t.Fatal("expected KeyExpiresAt to round-trip, got nil")
	}
	if !got.KeyExpiresAt.Equal(exp) {
		t.Errorf("KeyExpiresAt mismatch: got %v, want %v", got.KeyExpiresAt.UTC(), exp.UTC())
	}

	// Update to a new expiry and confirm it persists.
	newExp := time.Now().Add(48 * time.Hour).Truncate(time.Microsecond)
	got.SetAPIKeyWithExpiry("hash-keyexp-2", "rda_keyexp2", &newExp)
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update agent: %v", err)
	}
	got2, err := repo.GetByAPIKeyHash(ctx, "hash-keyexp-2")
	if err != nil {
		t.Fatalf("get by new hash: %v", err)
	}
	if got2.KeyExpiresAt == nil || !got2.KeyExpiresAt.Equal(newExp) {
		t.Errorf("updated KeyExpiresAt mismatch: got %v, want %v", got2.KeyExpiresAt, newExp.UTC())
	}

	// A never-expiring key (nil) must also round-trip as nil.
	got2.SetAPIKey("hash-keyexp-3", "rda_keyexp3")
	if err := repo.Update(ctx, got2); err != nil {
		t.Fatalf("update agent (nil expiry): %v", err)
	}
	got3, err := repo.GetByAPIKeyHash(ctx, "hash-keyexp-3")
	if err != nil {
		t.Fatalf("get by nil-expiry hash: %v", err)
	}
	if got3.KeyExpiresAt != nil {
		t.Errorf("expected nil KeyExpiresAt after SetAPIKey, got %v", got3.KeyExpiresAt)
	}
}
