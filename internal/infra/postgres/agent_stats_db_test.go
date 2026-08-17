package postgres

import (
	"context"
	"testing"
	"time"
)

// GetTenantAgentStats errored on EVERY call for EVERY tenant. Its CTE projected
// six columns:
//
//	WITH tenant_agents AS (
//	  SELECT id, status, health, type, execution_mode, current_jobs
//	  FROM agents WHERE ...
//	)
//
// and the outer query filtered `... AND last_seen_at IS NOT NULL` — a column the
// CTE does not carry, so Postgres answers "column last_seen_at does not exist"
// and GET /api/v1/agents/stats is a 500.
//
// It shipped in api#386 and in v0.5.0. The unit tests around agent stats all use
// a mock repository, which is why it compiled, linted and unit-tested clean and
// still failed on every real execution — the exact shape the SQL schema-drift
// gate (#364) exists to catch, and did.
//
// This test drives the real query against a real database so a regression here
// fails a test instead of a production request.
func TestGetTenantAgentStats_RunsAndCountsOnlineActive(t *testing.T) {
	db := openAgentDB(t)
	ctx := context.Background()
	repo := NewAgentRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	now := time.Now()

	// online + active, heartbeated -> counts toward OnlineActive.
	seedAgent(ctx, t, db, tenantID, "online", &now, "nuclei", 3)
	seedAgent(ctx, t, db, tenantID, "online", &now, "nuclei", 3)
	// online + active but never heartbeated -> last_seen_at IS NULL, so it is
	// online but NOT online-active under the query's own predicate.
	seedAgent(ctx, t, db, tenantID, "online", nil, "nuclei", 0)
	// offline -> not online-active.
	seedAgent(ctx, t, db, tenantID, "offline", &now, "nuclei", 0)

	stats, err := repo.GetTenantAgentStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantAgentStats errored — the CTE does not project a column "+
			"the outer query filters on, so this endpoint 500s for every tenant: %v", err)
	}

	if stats.Total != 4 {
		t.Errorf("Total = %d, want 4", stats.Total)
	}
	// Two online agents have a heartbeat; the third is online but never seen, so
	// the query's `AND last_seen_at IS NOT NULL` excludes it.
	if stats.OnlineActive != 2 {
		t.Errorf("OnlineActive = %d, want 2 (the never-heartbeated online agent is "+
			"excluded by the query's own last_seen_at predicate)", stats.OnlineActive)
	}
	if stats.ByHealth["online"] != 3 {
		t.Errorf("ByHealth[online] = %d, want 3", stats.ByHealth["online"])
	}
	if stats.ByStatus["active"] != 4 {
		t.Errorf("ByStatus[active] = %d, want 4 (seedAgent creates active agents)", stats.ByStatus["active"])
	}
}
