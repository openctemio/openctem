package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// The platform-job side of the command lifecycle had two reapers that could
// never reap and one that reaped silently.
//
//   - recover_stuck_platform_jobs required `platform_agent_id IS NOT NULL`.
//     Nothing sets that column: get_next_platform_job is the only writer and it
//     has no Go caller. In practice a platform job is claimed by an ordinary
//     tenant agent through GET /api/v1/agent/commands — GetPendingForAgent and
//     ClaimForAgent do not filter on is_platform_job, and platform jobs are
//     created with agent_id NULL — so ClaimForAgent sets agent_id instead. The
//     function matched nothing, and the controller logged "recovered stuck
//     platform jobs: 0" forever, reading as healthy.
//
//   - It also ignored the caller's max-retries setting: the Go wrapper bound
//     only the threshold and the SQL hardcoded `dispatch_attempts < 3`.
//
//   - ExpireOldPlatformJobs was a raw UPDATE that flipped queued jobs to
//     'expired' and told nobody. Platform jobs carry pipeline_run_id + step_key
//     and have expires_at NULL, so FindExpired never saw them; this was the only
//     thing that reaped them, and the owning run was never notified.
//
// These tests pin all three, plus the boundaries, so the reapers cannot go
// quietly inert again.

func openPlatformJobDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping platform job lifecycle tests")
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

// platformJobSeed describes a row to plant in `commands`.
type platformJobSeed struct {
	isPlatformJob bool
	status        string
	// ackedMinutesAgo sets acknowledged_at; 0 leaves it NULL.
	ackedMinutesAgo int
	// queuedMinutesAgo sets queued_at; 0 leaves it NULL.
	queuedMinutesAgo int
	// withTenantAgent sets agent_id (the column ClaimForAgent actually writes).
	withTenantAgent bool
	// withPlatformAgent sets platform_agent_id (what get_next_platform_job would
	// write, if it had a caller).
	withPlatformAgent bool
	dispatchAttempts  int
}

// seedJobAgent creates a throwaway agent. commands.agent_id and
// commands.platform_agent_id are both foreign keys, so a random shared.NewID()
// fails the insert.
func seedJobAgent(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID) shared.ID {
	t.Helper()

	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO agents (id, tenant_id, name, type, status, api_key_hash, api_key_prefix)
		 VALUES ($1, $2, $3, 'agent', 'active', $4, $5)`,
		id.String(), tenantID.String(), "job probe "+id.String(),
		"hash-"+id.String(), id.String()[:8])
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM agents WHERE id = $1`, id.String())
	})
	return id
}

func seedPlatformJob(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, s platformJobSeed) shared.ID {
	t.Helper()

	id := shared.NewID()

	var agentID, platformAgentID any
	if s.withTenantAgent {
		agentID = seedJobAgent(ctx, t, db, tenantID).String()
	}
	if s.withPlatformAgent {
		platformAgentID = seedJobAgent(ctx, t, db, tenantID).String()
	}

	// A pipeline payload: this is what makes silent expiry damaging, because the
	// run is waiting on step_key and nothing else will tell it.
	payload := `{"pipeline_run_id":"` + shared.NewID().String() + `","step_key":"probe-step"}`

	_, err := db.ExecContext(ctx, `
		INSERT INTO commands (
			id, tenant_id, agent_id, platform_agent_id, type, priority, payload, status,
			is_platform_job, dispatch_attempts,
			acknowledged_at, queued_at
		) VALUES (
			$1, $2, $3, $4, 'scan', 'normal', $5::jsonb, $6,
			$7, $8,
			CASE WHEN $9::INTEGER = 0 THEN NULL ELSE NOW() - ($9 || ' minutes')::INTERVAL END,
			CASE WHEN $10::INTEGER = 0 THEN NULL ELSE NOW() - ($10 || ' minutes')::INTERVAL END
		)`,
		id.String(), tenantID.String(), agentID, platformAgentID, payload, s.status,
		s.isPlatformJob, s.dispatchAttempts,
		s.ackedMinutesAgo, s.queuedMinutesAgo)
	if err != nil {
		t.Fatalf("seed platform job: %v", err)
	}

	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE id = $1`, id.String())
	})
	return id
}

// commandState reads back the columns the reapers write.
func commandState(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (status string, attempts int, agentSet, platformAgentSet bool) {
	t.Helper()

	var agentID, platformAgentID sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT status, dispatch_attempts, agent_id, platform_agent_id FROM commands WHERE id = $1`,
		id.String()).Scan(&status, &attempts, &agentID, &platformAgentID)
	if err != nil {
		t.Fatalf("read command state: %v", err)
	}
	return status, attempts, agentID.Valid, platformAgentID.Valid
}

// =============================================================================
// RecoverStuckJobs
// =============================================================================

// The state that actually occurs in production: a platform job claimed by a
// *tenant* agent (agent_id set, platform_agent_id NULL) whose agent then died.
//
// Before the fix nothing could reach this row. recover_stuck_platform_jobs
// skipped it (platform_agent_id IS NULL), recover_stuck_tenant_commands skips it
// by design (is_platform_job = FALSE, migration 000172), ExpireOldPlatformJobs
// only looked at 'pending', and fail_exhausted_commands needs
// dispatch_attempts >= max — which only the recovery functions ever increment.
// The job sat in 'acknowledged' forever and its pipeline run waited on it.
func TestRecoverStuckJobs_RecoversJobClaimedByTenantAgent(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:   true,
		status:          "acknowledged",
		ackedMinutesAgo: 120,
		withTenantAgent: true,
	})

	if _, err := repo.RecoverStuckJobs(ctx, 30, 3); err != nil {
		t.Fatalf("RecoverStuckJobs: %v", err)
	}

	status, attempts, agentSet, _ := commandState(ctx, t, db, id)
	if status != "pending" {
		t.Errorf("status = %q, want \"pending\": a platform job claimed by a tenant agent that "+
			"went offline is unreachable by every other reaper, so if recovery skips it the job "+
			"is stuck forever and its pipeline run never ends", status)
	}
	if agentSet {
		t.Error("agent_id still set after recovery: the job is back in the queue but still " +
			"looks claimed, so no other agent will take it")
	}
	if attempts != 1 {
		t.Errorf("dispatch_attempts = %d, want 1: without an increment there is no stopping "+
			"condition and fail_exhausted_commands can never take over", attempts)
	}
}

// The state the original query was written for must keep working.
func TestRecoverStuckJobs_RecoversJobClaimedByPlatformAgent(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:     true,
		status:            "acknowledged",
		ackedMinutesAgo:   120,
		withPlatformAgent: true,
	})

	if _, err := repo.RecoverStuckJobs(ctx, 30, 3); err != nil {
		t.Fatalf("RecoverStuckJobs: %v", err)
	}

	status, _, _, platformAgentSet := commandState(ctx, t, db, id)
	if status != "pending" {
		t.Errorf("status = %q, want \"pending\"", status)
	}
	if platformAgentSet {
		t.Error("platform_agent_id still set after recovery")
	}
}

// maxRetries was accepted by the Go wrapper and dropped: only $1 was bound and
// the SQL hardcoded `dispatch_attempts < 3`. Latent only while the configured
// value happens to be 3.
func TestRecoverStuckJobs_HonoursMaxRetries(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	// platform_agent_id deliberately, so this case isolates the maxRetries bug
	// from the "can never match" one: the old query reached this row fine and
	// still recovered it, because `dispatch_attempts < 3` was hardcoded.
	//
	// 1 attempt already used. With maxRetries=1 the job is exhausted and must be
	// left for fail_exhausted_commands.
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:     true,
		status:            "acknowledged",
		ackedMinutesAgo:   120,
		withPlatformAgent: true,
		dispatchAttempts:  1,
	})

	if _, err := repo.RecoverStuckJobs(ctx, 30, 1); err != nil {
		t.Fatalf("RecoverStuckJobs: %v", err)
	}

	status, attempts, _, _ := commandState(ctx, t, db, id)
	if status != "acknowledged" || attempts != 1 {
		t.Errorf("status = %q attempts = %d, want \"acknowledged\"/1: the job has already used "+
			"its single allowed attempt, so recovering it ignores the caller's maxRetries and "+
			"retries forever", status, attempts)
	}
}

// A job under the stuck threshold is simply still running. Recovering it would
// yank work away from a healthy agent.
func TestRecoverStuckJobs_IgnoresFreshlyAcknowledgedJob(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:   true,
		status:          "acknowledged",
		ackedMinutesAgo: 5,
		withTenantAgent: true,
	})

	if _, err := repo.RecoverStuckJobs(ctx, 30, 3); err != nil {
		t.Fatalf("RecoverStuckJobs: %v", err)
	}

	status, _, _, _ := commandState(ctx, t, db, id)
	if status != "acknowledged" {
		t.Errorf("status = %q, want \"acknowledged\": the agent has had 5 of its 30 minutes and "+
			"is probably still working", status)
	}
}

// Tenant commands belong to recover_stuck_tenant_commands, which increments and
// caps attempts on its own terms. Reaping them here would double-count.
func TestRecoverStuckJobs_IgnoresTenantCommands(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:   false,
		status:          "acknowledged",
		ackedMinutesAgo: 120,
		withTenantAgent: true,
	})

	if _, err := repo.RecoverStuckJobs(ctx, 30, 3); err != nil {
		t.Fatalf("RecoverStuckJobs: %v", err)
	}

	status, attempts, _, _ := commandState(ctx, t, db, id)
	if status != "acknowledged" || attempts != 0 {
		t.Errorf("status = %q attempts = %d: a non-platform command must be left to "+
			"recover_stuck_tenant_commands, or both functions count the same retry", status, attempts)
	}
}

// =============================================================================
// FindQueueExpiredPlatformJobs
// =============================================================================

// The rows the old raw UPDATE reaped silently must now be handed back to the
// caller, which expires them *and* fails the pipeline step.
func TestFindQueueExpiredPlatformJobs_ReturnsOverdueQueuedJob(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:    true,
		status:           "pending",
		queuedMinutesAgo: 120,
	})

	jobs, err := repo.FindQueueExpiredPlatformJobs(ctx, 60)
	if err != nil {
		t.Fatalf("FindQueueExpiredPlatformJobs: %v", err)
	}

	found := false
	for _, j := range jobs {
		if j.ID == id {
			found = true
			if len(j.Payload) == 0 {
				t.Error("payload not loaded: without pipeline_run_id/step_key the caller cannot " +
					"notify the run, which is the entire reason this returns rows instead of expiring them")
			}
		}
	}
	if !found {
		t.Error("a platform job queued for 120 minutes past a 60 minute limit was not returned; " +
			"unexpired it occupies the queue forever, and unreturned nothing can tell its run why")
	}
}

// A job inside its queue budget is just waiting its turn.
func TestFindQueueExpiredPlatformJobs_IgnoresJobWithinBudget(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:    true,
		status:           "pending",
		queuedMinutesAgo: 10,
	})

	jobs, err := repo.FindQueueExpiredPlatformJobs(ctx, 60)
	if err != nil {
		t.Fatalf("FindQueueExpiredPlatformJobs: %v", err)
	}
	for _, j := range jobs {
		if j.ID == id {
			t.Error("a job queued 10 minutes ago against a 60 minute limit was reported expired; " +
				"expiring it would fail a pipeline run that was about to succeed")
		}
	}
}

// An acknowledged job is being worked on, not queued. It belongs to
// RecoverStuckJobs; expiring it here would kill live work.
func TestFindQueueExpiredPlatformJobs_IgnoresAcknowledgedJob(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:    true,
		status:           "acknowledged",
		ackedMinutesAgo:  120,
		queuedMinutesAgo: 120,
		withTenantAgent:  true,
	})

	jobs, err := repo.FindQueueExpiredPlatformJobs(ctx, 60)
	if err != nil {
		t.Fatalf("FindQueueExpiredPlatformJobs: %v", err)
	}
	for _, j := range jobs {
		if j.ID == id {
			t.Error("an acknowledged job was reported as queue-expired: it is claimed and " +
				"possibly running, and RecoverStuckJobs owns it")
		}
	}
}

// Non-platform commands expire on expires_at via FindExpired.
func TestFindQueueExpiredPlatformJobs_IgnoresTenantCommands(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	id := seedPlatformJob(ctx, t, db, tenantID, platformJobSeed{
		isPlatformJob:    false,
		status:           "pending",
		queuedMinutesAgo: 120,
	})

	jobs, err := repo.FindQueueExpiredPlatformJobs(ctx, 60)
	if err != nil {
		t.Fatalf("FindQueueExpiredPlatformJobs: %v", err)
	}
	for _, j := range jobs {
		if j.ID == id {
			t.Error("a non-platform command was reported as queue-expired; it has no queue " +
				"budget and expires on expires_at through FindExpired")
		}
	}
}
