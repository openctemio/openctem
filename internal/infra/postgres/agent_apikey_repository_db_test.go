package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	agentdom "github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestAgentAPIKeyRepository_RoundTrip exercises the agent_api_keys repo against
// the real schema: create → get-by-hash → record-usage → revoke, plus the
// overlap invariant that two active keys for one agent coexist. Skipped unless
// DATABASE_URL is set.
func TestAgentAPIKeyRepository_RoundTrip(t *testing.T) {
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

	// Seed tenant + agent (agent_api_keys.agent_id REFERENCES agents; deleting
	// the tenant CASCADEs both away).
	tenantID := shared.NewID()
	slug := "aak-" + tenantID.String()[:8]
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "agent-apikey-test", slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	agentRepo := NewAgentRepository(&DB{DB: db})
	a, err := agentdom.NewAgent(tenantID, "aak-agent", agentdom.AgentTypeRunner, "", nil, nil, agentdom.ExecutionModeStandalone)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	a.SetAPIKey("inline-hash", "rda_inline12")
	if err := agentRepo.Create(ctx, a); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	repo := NewAgentAPIKeyRepository(&DB{DB: db})

	// Create key N.
	kN, _ := agentdom.NewAPIKey(a.ID, "keyN", agentdom.RunnerScopes())
	kN.SetKeyHash("hash-N", "rda_N0000000")
	expN := time.Now().Add(1 * time.Hour).Truncate(time.Microsecond)
	kN.SetExpiration(expN)
	if err := repo.Create(ctx, kN); err != nil {
		t.Fatalf("create key N: %v", err)
	}

	got, err := repo.GetByHash(ctx, "hash-N")
	if err != nil {
		t.Fatalf("get by hash N: %v", err)
	}
	if got.AgentID != a.ID || !got.IsValid() {
		t.Fatalf("round-trip mismatch: agent=%v valid=%v", got.AgentID, got.IsValid())
	}
	if len(got.Scopes) != len(agentdom.RunnerScopes()) {
		t.Errorf("scopes not round-tripped: %v", got.Scopes)
	}

	// RecordUsage bumps count.
	if err := repo.RecordUsage(ctx, kN.ID, "203.0.113.7"); err != nil {
		t.Fatalf("record usage: %v", err)
	}
	if got, _ = repo.GetByHash(ctx, "hash-N"); got.UseCount != 1 {
		t.Errorf("expected use_count 1, got %d", got.UseCount)
	}

	// Overlap: issue key N+1 while N is still active → two active keys coexist.
	kN1, _ := agentdom.NewAPIKey(a.ID, "keyN+1", agentdom.RunnerScopes())
	kN1.SetKeyHash("hash-N1", "rda_N1000000")
	if err := repo.Create(ctx, kN1); err != nil {
		t.Fatalf("create key N+1: %v", err)
	}
	count, err := repo.CountActiveByAgentID(ctx, a.ID)
	if err != nil {
		t.Fatalf("count active: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 active keys during overlap, got %d", count)
	}

	// Revoke N → GetByHash(N) no longer resolves (active-only), N+1 still works.
	if err := repo.Revoke(ctx, kN.ID, "rotated out"); err != nil {
		t.Fatalf("revoke N: %v", err)
	}
	if _, err := repo.GetByHash(ctx, "hash-N"); err == nil {
		t.Error("expected revoked key to no longer resolve via GetByHash")
	}
	if _, err := repo.GetByHash(ctx, "hash-N1"); err != nil {
		t.Errorf("expected N+1 to still resolve, got %v", err)
	}
}
