package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// An agent row with health='online' and last_seen_at IS NULL is undead: it
// claims to be online, has never once heartbeated, and nothing could ever
// change that.
//
// Both stale sweeps carried `AND last_seen_at IS NOT NULL`, so neither could
// ever select such a row. Meanwhile every dispatch query asked only for
// health='online' and ordered by `total_scans ASC` — so a never-started agent,
// with zero scans to its name, outranked every genuinely running one and won
// each selection. It then advertised its tools, which is how a tenant gets
// "scanner not found: nuclei" from an agent that does not exist.
//
// The app cannot produce this state — UpdateLastSeen is the only writer of
// health='online' and it sets last_seen_at in the same statement — but a
// fixture, a restore or a manual UPDATE can, and two such rows sat undead on
// the live database from 2026-04-24, taking every dispatch with them.
//
// These tests pin both halves: the sweeps now reap it, and dispatch now
// ignores it even before a sweep runs.

func openAgentDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping undead-agent tests")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

// seedAgent inserts an agent. lastSeen nil means it has never heartbeated —
// the undead case. totalScans drives the dispatch ordering.
func seedAgent(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID,
	health string, lastSeen *time.Time, tool string, totalScans int) shared.ID {
	t.Helper()

	id := shared.NewID()
	var seenArg any
	if lastSeen != nil {
		seenArg = *lastSeen
	}

	_, err := db.ExecContext(ctx,
		`INSERT INTO agents (id, tenant_id, name, type, status, health,
		                     api_key_hash, api_key_prefix, tools, execution_mode,
		                     max_concurrent_jobs, current_jobs, total_scans, last_seen_at)
		 VALUES ($1, $2, $3, 'agent', 'active', $4, $5, $6, ARRAY[$7], 'daemon', 5, 0, $8, $9)`,
		id.String(), tenantID.String(), "undead probe "+id.String(),
		health, "hash-"+id.String(), id.String()[:8], tool, totalScans, seenArg)
	if err != nil {
		t.Fatalf("seed agent (health=%s, lastSeen=%v): %v", health, lastSeen, err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM agents WHERE id = $1`, id.String())
	})
	return id
}

func agentHealth(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) string {
	t.Helper()
	var h string
	if err := db.QueryRowContext(ctx, `SELECT health FROM agents WHERE id = $1`, id.String()).Scan(&h); err != nil {
		t.Fatalf("read agent health: %v", err)
	}
	return h
}

// The regression that matters for the sweep: never-heartbeated, so the old
// `last_seen_at IS NOT NULL` predicate excluded it permanently.
func TestMarkStaleAsOffline_ReapsNeverHeartbeatedAgent(t *testing.T) {
	db := openAgentDB(t)
	ctx := context.Background()
	repo := &AgentRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	undead := seedAgent(ctx, t, db, tenantID, "online", nil, "nuclei", 0)

	if _, err := repo.MarkStaleAsOffline(ctx, 5*time.Minute); err != nil {
		t.Fatalf("MarkStaleAsOffline: %v", err)
	}

	if got := agentHealth(ctx, t, db, undead); got != "offline" {
		t.Errorf("never-heartbeated agent health = %q, want %q — the sweep still cannot reach it", got, "offline")
	}
}

func TestMarkStaleAgentsOffline_ReapsNeverHeartbeatedAgent(t *testing.T) {
	db := openAgentDB(t)
	ctx := context.Background()
	repo := &AgentRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	undead := seedAgent(ctx, t, db, tenantID, "online", nil, "nuclei", 0)

	ids, err := repo.MarkStaleAgentsOffline(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("MarkStaleAgentsOffline: %v", err)
	}

	var reported bool
	for _, id := range ids {
		if id.String() == undead.String() {
			reported = true
		}
	}
	if !reported {
		t.Errorf("undead agent not in the reaped set — the health monitor cannot audit-log what it never selects")
	}
	if got := agentHealth(ctx, t, db, undead); got != "offline" {
		t.Errorf("never-heartbeated agent health = %q, want %q", got, "offline")
	}
}

// A recently-heartbeating agent must survive both sweeps — the fix widens the
// predicate, and widening a reaper is exactly how you take down a live fleet.
func TestMarkStaleSweeps_LeaveLiveAgentAlone(t *testing.T) {
	db := openAgentDB(t)
	ctx := context.Background()
	repo := &AgentRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	now := time.Now()
	live := seedAgent(ctx, t, db, tenantID, "online", &now, "nuclei", 7)

	if _, err := repo.MarkStaleAsOffline(ctx, 5*time.Minute); err != nil {
		t.Fatalf("MarkStaleAsOffline: %v", err)
	}
	if _, err := repo.MarkStaleAgentsOffline(ctx, 5*time.Minute); err != nil {
		t.Fatalf("MarkStaleAgentsOffline: %v", err)
	}

	if got := agentHealth(ctx, t, db, live); got != "online" {
		t.Errorf("live agent health = %q, want %q — the widened sweep is reaping healthy agents", got, "online")
	}
}

// The dispatch half. Ordering is `total_scans ASC`, so the undead agent (0
// scans) sorts ahead of the live one (7) and used to win. Selection must skip
// it without waiting for a sweep.
func TestFindAvailableWithTool_SkipsNeverHeartbeatedAgent(t *testing.T) {
	db := openAgentDB(t)
	ctx := context.Background()
	repo := &AgentRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	now := time.Now()
	undead := seedAgent(ctx, t, db, tenantID, "online", nil, "nuclei", 0)
	live := seedAgent(ctx, t, db, tenantID, "online", &now, "nuclei", 7)

	got, err := repo.FindAvailableWithTool(ctx, tenantID, "nuclei")
	if err != nil {
		t.Fatalf("FindAvailableWithTool: %v", err)
	}
	if got == nil {
		t.Fatal("no agent selected, want the live one")
	}
	if got.ID.String() == undead.String() {
		t.Fatalf("dispatch picked the never-heartbeated agent — it sorts first on total_scans ASC")
	}
	if got.ID.String() != live.String() {
		t.Errorf("dispatch picked %s, want the live agent %s", got.ID, live)
	}
}

// Tool availability drives what a tenant is allowed to launch. An undead agent
// advertising nuclei makes the platform offer a scanner nothing can run.
func TestGetAvailableToolsForTenant_IgnoresNeverHeartbeatedAgent(t *testing.T) {
	db := openAgentDB(t)
	ctx := context.Background()
	repo := &AgentRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	seedAgent(ctx, t, db, tenantID, "online", nil, "nuclei", 0)

	tools, err := repo.GetAvailableToolsForTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetAvailableToolsForTenant: %v", err)
	}
	for _, tool := range tools {
		if tool == "nuclei" {
			t.Fatalf("nuclei advertised as available, but its only agent has never heartbeated")
		}
	}
}
