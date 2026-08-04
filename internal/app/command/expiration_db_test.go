package command

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/internal/infra/postgres"
	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ExpirationChecker has run on a 60s tick in every deployment and had never
// expired a single command. Both consumers of commands.expires_at require
// `expires_at IS NOT NULL`:
//
//	FindExpired:        WHERE status IN ('pending','acknowledged')
//	                    AND expires_at IS NOT NULL AND expires_at < NOW()
//	GetPendingForAgent: AND (expires_at IS NULL OR expires_at > NOW())
//
// and nothing ever wrote the column: the only setter was
// command.Service.Create's `if input.ExpiresIn > 0`, and no caller passes
// ExpiresIn. All six creation sites (scan/trigger x2, pipeline/run,
// validation/dispatcher, scancoverage/dispatcher, command/service) went through
// commanddom.NewCommand, which left ExpiresAt nil. On the live database:
// 21 commands, 0 with an expiry, 0 ever expired.
//
// So a command nobody answers was never expired and
// pipeline.OnStepFailed(..., "COMMAND_EXPIRED") had never fired — the owning run
// hung until ScanTimeoutController reported a generic timeout instead.
//
// These tests go through the real postgres repository so they fail if the
// default stops being written, or is written somewhere FindExpired cannot see.

func openCommandDB(t *testing.T) *postgres.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping command expiry DB tests")
	}

	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := sqlDB.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return &postgres.DB{DB: sqlDB}
}

// seedExpiryTenant creates a throwaway tenant; commands.tenant_id is a foreign
// key, so a random shared.NewID() fails the insert.
func seedExpiryTenant(ctx context.Context, t *testing.T, db *postgres.DB) shared.ID {
	t.Helper()

	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		id.String(), "command expiry test", "test-"+id.String())
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

func pipelinePayload(t *testing.T, runID, stepKey string) json.RawMessage {
	t.Helper()

	raw, err := json.Marshal(map[string]string{
		"pipeline_run_id": runID,
		"step_key":        stepKey,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

// TestCommandCreation_PersistsDefaultExpiry is the direct regression: a command
// built the way production builds them must reach the database with a non-NULL
// expires_at. Before the fix the column was NULL for every row.
func TestCommandCreation_PersistsDefaultExpiry(t *testing.T) {
	ctx := context.Background()
	db := openCommandDB(t)
	repo := postgres.NewCommandRepository(db)
	tenantID := seedExpiryTenant(ctx, t, db)

	svc := NewService(repo, logger.NewNop())

	created, err := svc.Create(ctx, CreateInput{
		TenantID: tenantID.String(),
		Type:     string(commanddom.CommandTypeScan),
		Payload:  pipelinePayload(t, shared.NewID().String(), "default-expiry-step"),
	})
	if err != nil {
		t.Fatalf("create command: %v", err)
	}

	// Read the persisted row back, not the in-memory entity.
	var expiresAt sql.NullTime
	if err := db.QueryRowContext(ctx,
		`SELECT expires_at FROM commands WHERE id = $1`, created.ID.String(),
	).Scan(&expiresAt); err != nil {
		t.Fatalf("read back command: %v", err)
	}

	if !expiresAt.Valid {
		t.Fatal("commands.expires_at is NULL for a command created through the " +
			"production path: FindExpired requires `expires_at IS NOT NULL`, so " +
			"ExpirationChecker can never see this row and the owning pipeline run " +
			"will never receive COMMAND_EXPIRED")
	}

	ttl := time.Until(expiresAt.Time)
	// Generous window: this asserts the default is the intended backstop
	// magnitude, not a stopwatch.
	if ttl < commanddom.DefaultCommandTTL-time.Hour || ttl > commanddom.DefaultCommandTTL+time.Hour {
		t.Fatalf("expires_at is %v away, want ~%v (DefaultCommandTTL); a shorter "+
			"default would expire healthy in-flight work before the timeouts that "+
			"should catch it first", ttl, commanddom.DefaultCommandTTL)
	}
}

// TestCommandCreation_ExplicitExpiresInWins pins that the default is a fallback:
// an explicit ExpiresIn must still take effect.
func TestCommandCreation_ExplicitExpiresInWins(t *testing.T) {
	ctx := context.Background()
	db := openCommandDB(t)
	repo := postgres.NewCommandRepository(db)
	tenantID := seedExpiryTenant(ctx, t, db)

	svc := NewService(repo, logger.NewNop())

	created, err := svc.Create(ctx, CreateInput{
		TenantID:  tenantID.String(),
		Type:      string(commanddom.CommandTypeScan),
		Payload:   pipelinePayload(t, shared.NewID().String(), "explicit-expiry-step"),
		ExpiresIn: 300,
	})
	if err != nil {
		t.Fatalf("create command: %v", err)
	}

	var expiresAt sql.NullTime
	if err := db.QueryRowContext(ctx,
		`SELECT expires_at FROM commands WHERE id = $1`, created.ID.String(),
	).Scan(&expiresAt); err != nil {
		t.Fatalf("read back command: %v", err)
	}
	if !expiresAt.Valid {
		t.Fatal("expires_at is NULL despite an explicit ExpiresIn")
	}

	if ttl := time.Until(expiresAt.Time); ttl > time.Hour {
		t.Fatalf("expires_at is %v away: the 5 minute ExpiresIn was overwritten by "+
			"the %v default", ttl, commanddom.DefaultCommandTTL)
	}
}

// TestExpirationChecker_ExpiresCommandAndFailsStep drives the real checker over
// the real repository: create through the production path, move the row's clock
// past its own deadline, and assert the checker both marks it expired and tells
// the owning run with COMMAND_EXPIRED.
//
// The clock shift is relative (`expires_at = expires_at - interval`), never an
// absolute timestamp: `NULL - interval` is NULL, so this test cannot pass by
// injecting the value the code under test was supposed to write.
func TestExpirationChecker_ExpiresCommandAndFailsStep(t *testing.T) {
	ctx := context.Background()
	db := openCommandDB(t)
	repo := postgres.NewCommandRepository(db)
	tenantID := seedExpiryTenant(ctx, t, db)

	runID := shared.NewID().String()
	const stepKey = "expiry-backstop-step"

	svc := NewService(repo, logger.NewNop())
	created, err := svc.Create(ctx, CreateInput{
		TenantID: tenantID.String(),
		Type:     string(commanddom.CommandTypeScan),
		Payload:  pipelinePayload(t, runID, stepKey),
	})
	if err != nil {
		t.Fatalf("create command: %v", err)
	}

	shiftSeconds := int64((commanddom.DefaultCommandTTL + time.Hour).Seconds())
	res, err := db.ExecContext(ctx,
		`UPDATE commands SET expires_at = expires_at - ($2 || ' seconds')::INTERVAL WHERE id = $1`,
		created.ID.String(), shiftSeconds)
	if err != nil {
		t.Fatalf("shift expiry: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("shift expiry updated %d rows, want 1", n)
	}

	failer := &stubStepFailer{}
	checker := NewExpirationChecker(repo, nil, ExpirationCheckerConfig{}, logger.NewNop())
	checker.pipelineService = failer

	checker.checkAndExpire()

	var status string
	if err := db.QueryRowContext(ctx,
		`SELECT status FROM commands WHERE id = $1`, created.ID.String(),
	).Scan(&status); err != nil {
		t.Fatalf("read back status: %v", err)
	}
	if status != string(commanddom.CommandStatusExpired) {
		t.Fatalf("command status = %q, want %q: FindExpired did not match a command "+
			"that is past its own expires_at", status, commanddom.CommandStatusExpired)
	}

	var got *recordedStepFailure
	for i := range failer.calls {
		if failer.calls[i].runID == runID {
			got = &failer.calls[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("pipeline run %s was not notified: the command expired silently and "+
			"the run is left waiting on a step that is already dead", runID)
	}
	if got.stepKey != stepKey {
		t.Errorf("step key = %q, want %q", got.stepKey, stepKey)
	}
	if got.code != expiryReasonCommand.code {
		t.Errorf("error code = %q, want %q", got.code, expiryReasonCommand.code)
	}
}
