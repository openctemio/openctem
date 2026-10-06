package integration

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestRecoverStuckTenantCommands tests the recover_stuck_tenant_commands function.
// This function recovers commands that were assigned to sensors that went offline.
//
// Run with: go test -v ./tests/integration -run TestRecoverStuckTenantCommands
func TestRecoverStuckTenantCommands(t *testing.T) {
	db := setupCommandTestDB(t)
	defer db.Close()
	defer lockGlobalSweep(context.Background(), t, db)()

	tenantID := createTestTenantForCommand(t, db)
	sensorID := createTestSensor(t, db, tenantID, "online")
	offlineSensorID := createTestSensor(t, db, tenantID, "offline")

	t.Run("RecoverCommandsFromOfflineSensor", func(t *testing.T) {
		// A command the offline sensor acknowledged 30 min ago but never finished.
		cmdID := createTestAckStuckCommand(t, db, tenantID, offlineSensorID, 0)

		// Run recovery function
		var recovered int
		err := db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if err != nil {
			t.Fatalf("Failed to run recover_stuck_tenant_commands: %v", err)
		}

		if recovered != 1 {
			t.Errorf("Expected 1 recovered command, got %d", recovered)
		}

		// Verify command was unassigned
		var sensorIDNullable sql.NullString
		var dispatchAttempts int
		err = db.QueryRow("SELECT sensor_id, dispatch_attempts FROM commands WHERE id = $1", cmdID.String()).
			Scan(&sensorIDNullable, &dispatchAttempts)
		if err != nil {
			t.Fatalf("Failed to query command: %v", err)
		}

		if sensorIDNullable.Valid {
			t.Errorf("Expected sensor_id to be NULL, got %s", sensorIDNullable.String)
		}
		if dispatchAttempts != 1 {
			t.Errorf("Expected dispatch_attempts to be 1, got %d", dispatchAttempts)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Run("DontRecoverCommandsFromOnlineSensor_WhenRecent", func(t *testing.T) {
		// Acknowledged just now (not stuck) — recovery must leave it assigned.
		cmdID := createTestAckRecentCommand(t, db, tenantID, sensorID, 0)

		// Run recovery function with 10 minute threshold
		var recovered int
		err := db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if err != nil {
			t.Fatalf("Failed to run recover_stuck_tenant_commands: %v", err)
		}

		if recovered != 0 {
			t.Errorf("Expected 0 recovered commands for recent online sensor command, got %d", recovered)
		}

		// Verify command still assigned
		var assignedSensorID sql.NullString
		err = db.QueryRow("SELECT sensor_id FROM commands WHERE id = $1", cmdID.String()).Scan(&assignedSensorID)
		if err != nil {
			t.Fatalf("Failed to query command: %v", err)
		}

		if !assignedSensorID.Valid || assignedSensorID.String != sensorID.String() {
			t.Errorf("Expected sensor_id to remain %s, got %v", sensorID, assignedSensorID)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Run("RespectMaxRetries", func(t *testing.T) {
		// Stuck+acknowledged but already at max dispatch_attempts — recovery must
		// not pick it up (fail_exhausted_commands handles it instead).
		cmdID := createTestAckStuckCommand(t, db, tenantID, offlineSensorID, 3)

		// Run recovery function with max_retries=3
		var recovered int
		err := db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if err != nil {
			t.Fatalf("Failed to run recover_stuck_tenant_commands: %v", err)
		}

		if recovered != 0 {
			t.Errorf("Expected 0 recovered commands (max retries reached), got %d", recovered)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Run("DontRecoverRunningCommands", func(t *testing.T) {
		// Create a running command assigned to offline sensor
		cmdID := createTestCommand(t, db, tenantID, offlineSensorID, "running", 0)

		// Run recovery function
		var recovered int
		err := db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if err != nil {
			t.Fatalf("Failed to run recover_stuck_tenant_commands: %v", err)
		}

		if recovered != 0 {
			t.Errorf("Expected 0 recovered (running commands should not be recovered), got %d", recovered)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Run("DontRecoverPlatformCommands", func(t *testing.T) {
		// Create a platform command (is_platform_job=true)
		cmdID := createTestPlatformCommand(t, db, tenantID, offlineSensorID, "pending", 0)

		// Run recovery function
		var recovered int
		err := db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if err != nil {
			t.Fatalf("Failed to run recover_stuck_tenant_commands: %v", err)
		}

		if recovered != 0 {
			t.Errorf("Expected 0 recovered (platform commands handled separately), got %d", recovered)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Cleanup(func() {
		cleanupCommandTestData(db, tenantID)
	})
}

// TestFailExhaustedCommands tests the fail_exhausted_commands function.
// This function fails commands that have exceeded maximum retry attempts.
//
// Run with: go test -v ./tests/integration -run TestFailExhaustedCommands
func TestFailExhaustedCommands(t *testing.T) {
	db := setupCommandTestDB(t)
	defer db.Close()
	defer lockGlobalSweep(context.Background(), t, db)()

	tenantID := createTestTenantForCommand(t, db)
	offlineSensorID := createTestSensor(t, db, tenantID, "offline")

	t.Run("FailCommandsAtMaxRetries", func(t *testing.T) {
		// Create a command that has reached max retries
		cmdID := createTestCommand(t, db, tenantID, offlineSensorID, "pending", 3)

		// Run fail function
		var failed int
		err := db.QueryRow("SELECT fail_exhausted_commands(3)").Scan(&failed)
		if err != nil {
			t.Fatalf("Failed to run fail_exhausted_commands: %v", err)
		}

		if failed != 1 {
			t.Errorf("Expected 1 failed command, got %d", failed)
		}

		// Verify command was failed
		var status, errorMsg string
		err = db.QueryRow("SELECT status, error_message FROM commands WHERE id = $1", cmdID.String()).
			Scan(&status, &errorMsg)
		if err != nil {
			t.Fatalf("Failed to query command: %v", err)
		}

		if status != "failed" {
			t.Errorf("Expected status 'failed', got '%s'", status)
		}
		if errorMsg == "" {
			t.Error("Expected error_message to be set")
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Run("DontFailCommandsUnderMaxRetries", func(t *testing.T) {
		// Create a command that has not reached max retries
		cmdID := createTestCommand(t, db, tenantID, offlineSensorID, "pending", 2)

		// Run fail function with max_retries=3
		var failed int
		err := db.QueryRow("SELECT fail_exhausted_commands(3)").Scan(&failed)
		if err != nil {
			t.Fatalf("Failed to run fail_exhausted_commands: %v", err)
		}

		if failed != 0 {
			t.Errorf("Expected 0 failed commands (under max retries), got %d", failed)
		}

		// Verify command still pending
		var status string
		err = db.QueryRow("SELECT status FROM commands WHERE id = $1", cmdID.String()).Scan(&status)
		if err != nil {
			t.Fatalf("Failed to query command: %v", err)
		}

		if status != "pending" {
			t.Errorf("Expected status 'pending', got '%s'", status)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Run("DontFailAlreadyFailedCommands", func(t *testing.T) {
		// Create a failed command
		cmdID := createTestCommand(t, db, tenantID, offlineSensorID, "failed", 5)

		// Run fail function
		var failed int
		err := db.QueryRow("SELECT fail_exhausted_commands(3)").Scan(&failed)
		if err != nil {
			t.Fatalf("Failed to run fail_exhausted_commands: %v", err)
		}

		if failed != 0 {
			t.Errorf("Expected 0 failed commands (already failed), got %d", failed)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Run("DontFailCompletedCommands", func(t *testing.T) {
		// Create a completed command with high dispatch attempts
		cmdID := createTestCommand(t, db, tenantID, offlineSensorID, "completed", 5)

		// Run fail function
		var failed int
		err := db.QueryRow("SELECT fail_exhausted_commands(3)").Scan(&failed)
		if err != nil {
			t.Fatalf("Failed to run fail_exhausted_commands: %v", err)
		}

		if failed != 0 {
			t.Errorf("Expected 0 failed commands (already completed), got %d", failed)
		}

		// Verify still completed
		var status string
		err = db.QueryRow("SELECT status FROM commands WHERE id = $1", cmdID.String()).Scan(&status)
		if err != nil {
			t.Fatalf("Failed to query command: %v", err)
		}

		if status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Cleanup(func() {
		cleanupCommandTestData(db, tenantID)
	})
}

// TestRecoveryAndFailIntegration tests the full recovery workflow.
//
// Run with: go test -v ./tests/integration -run TestRecoveryAndFailIntegration
func TestRecoveryAndFailIntegration(t *testing.T) {
	db := setupCommandTestDB(t)
	defer db.Close()
	defer lockGlobalSweep(context.Background(), t, db)()

	tenantID := createTestTenantForCommand(t, db)
	offlineSensorID := createTestSensor(t, db, tenantID, "offline")

	t.Run("FullRecoveryWorkflow", func(t *testing.T) {
		// Simulate: command acknowledged by a sensor that then goes offline.
		cmdID := createTestAckStuckCommand(t, db, tenantID, offlineSensorID, 0)

		// First recovery attempt (dispatch_attempts 0 -> 1)
		var recovered int
		db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if recovered != 1 {
			t.Fatalf("First recovery should recover 1 command, got %d", recovered)
		}

		// Verify command back in pool (sensor_id = NULL)
		var sensorIDNullable sql.NullString
		db.QueryRow("SELECT sensor_id FROM commands WHERE id = $1", cmdID.String()).Scan(&sensorIDNullable)
		if sensorIDNullable.Valid {
			t.Error("Command should be unassigned after recovery")
		}

		// Re-dispatched to a sensor that acknowledges then goes offline again.
		markAckStuck(t, db, cmdID, offlineSensorID)

		// Second recovery (1 -> 2)
		db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if recovered != 1 {
			t.Errorf("Second recovery should recover 1 command, got %d", recovered)
		}

		// Third recovery (2 -> 3)
		markAckStuck(t, db, cmdID, offlineSensorID)
		db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if recovered != 1 {
			t.Errorf("Third recovery should recover 1 command, got %d", recovered)
		}

		// Fourth attempt - should NOT recover (dispatch_attempts now at max = 3)
		markAckStuck(t, db, cmdID, offlineSensorID)
		db.QueryRow("SELECT recover_stuck_tenant_commands(10, 3)").Scan(&recovered)
		if recovered != 0 {
			t.Errorf("Fourth recovery should NOT recover (max retries), got %d", recovered)
		}

		// Now fail_exhausted_commands should mark it as failed
		var failed int
		db.QueryRow("SELECT fail_exhausted_commands(3)").Scan(&failed)
		if failed != 1 {
			t.Errorf("Expected 1 command to be failed, got %d", failed)
		}

		// Verify final state
		var status string
		db.QueryRow("SELECT status FROM commands WHERE id = $1", cmdID.String()).Scan(&status)
		if status != "failed" {
			t.Errorf("Expected final status 'failed', got '%s'", status)
		}

		// Cleanup
		db.Exec("DELETE FROM commands WHERE id = $1", cmdID.String())
	})

	t.Cleanup(func() {
		cleanupCommandTestData(db, tenantID)
	})
}

// =============================================================================
// Test Helpers for Commands
// =============================================================================

func setupCommandTestDB(t *testing.T) *sql.DB {
	t.Helper()

	// No default. These tests write rows and run cross-tenant sweeps; a default
	// of "openctem" pointed an unconfigured `go test ./...` at whatever database
	// that name resolves to on the machine running it - in a dev environment, the
	// real one. Skipping is the only safe unset behavior, and it matches
	// openPlatformJobDB in internal/infra/postgres.
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping command recovery tests")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("Skipping command recovery test: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Skipf("Skipping command recovery test: database not available: %v", err)
	}

	// Verify functions exist
	var exists bool
	err = db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM pg_proc WHERE proname = 'recover_stuck_tenant_commands'
		)
	`).Scan(&exists)
	if err != nil || !exists {
		t.Skip("Skipping: recover_stuck_tenant_commands function not found (run migration 000145)")
	}

	return db
}

func createTestTenantForCommand(t *testing.T, db *sql.DB) shared.ID {
	t.Helper()

	id := shared.NewID()
	slug := fmt.Sprintf("test-cmd-%d", time.Now().UnixNano())

	_, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, id.String(), "Command Test Tenant", slug)
	if err != nil {
		t.Fatalf("Failed to create test tenant: %v", err)
	}

	return id
}

func createTestSensor(t *testing.T, db *sql.DB, tenantID shared.ID, health string) shared.ID {
	t.Helper()

	id := shared.NewID()
	apiKeyHash := fmt.Sprintf("test-hash-%s", id.String())
	apiKeyPrefix := fmt.Sprintf("test-%s", id.String()[:4])

	_, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, type, status, health, api_key_hash, api_key_prefix, created_at, updated_at, last_seen_at)
		VALUES ($1, $2, $3, 'worker', 'active', $4, $5, $6, NOW(), NOW(), NOW())
	`, id.String(), tenantID.String(), fmt.Sprintf("Test Sensor %s", health), health, apiKeyHash, apiKeyPrefix)
	if err != nil {
		t.Fatalf("Failed to create test sensor: %v", err)
	}

	return id
}

func createTestCommand(t *testing.T, db *sql.DB, tenantID, sensorID shared.ID, status string, dispatchAttempts int) shared.ID {
	t.Helper()

	id := shared.NewID()

	_, err := db.Exec(`
		INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, is_platform_job, dispatch_attempts, created_at)
		VALUES ($1, $2, $3, 'scan', $4, '{}', false, $5, NOW() - INTERVAL '30 minutes')
	`, id.String(), tenantID.String(), sensorID.String(), status, dispatchAttempts)
	if err != nil {
		t.Fatalf("Failed to create test command: %v", err)
	}

	return id
}

func createTestPlatformCommand(t *testing.T, db *sql.DB, tenantID, sensorID shared.ID, status string, dispatchAttempts int) shared.ID {
	t.Helper()

	id := shared.NewID()

	_, err := db.Exec(`
		INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, is_platform_job, dispatch_attempts, created_at)
		VALUES ($1, $2, $3, 'scan', $4, '{}', true, $5, NOW() - INTERVAL '30 minutes')
	`, id.String(), tenantID.String(), sensorID.String(), status, dispatchAttempts)
	if err != nil {
		t.Fatalf("Failed to create test platform command: %v", err)
	}

	return id
}

func cleanupCommandTestData(db *sql.DB, tenantID shared.ID) {
	db.Exec("DELETE FROM commands WHERE tenant_id = $1", tenantID.String())
	db.Exec("DELETE FROM sensors WHERE tenant_id = $1", tenantID.String())
	db.Exec("DELETE FROM tenants WHERE id = $1", tenantID.String())
}

// createTestAckStuckCommand creates an 'acknowledged' tenant command that was
// acknowledged long ago (stuck) and is still assigned to a sensor. This is the
// state recover_stuck_tenant_commands acts on: a sensor acknowledged the
// command, then went offline without completing it.
func createTestAckStuckCommand(t *testing.T, db *sql.DB, tenantID, sensorID shared.ID, dispatchAttempts int) shared.ID {
	t.Helper()

	id := shared.NewID()

	_, err := db.Exec(`
		INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, is_platform_job, dispatch_attempts, created_at, acknowledged_at)
		VALUES ($1, $2, $3, 'scan', 'acknowledged', '{}', false, $4, NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '30 minutes')
	`, id.String(), tenantID.String(), sensorID.String(), dispatchAttempts)
	if err != nil {
		t.Fatalf("Failed to create test acknowledged stuck command: %v", err)
	}

	return id
}

// markAckStuck puts an existing command back into the stuck-acknowledged state
// (re-assigned to a sensor that acknowledged it 30 minutes ago), simulating the
// command being re-dispatched and the new sensor going offline again.
func markAckStuck(t *testing.T, db *sql.DB, cmdID, sensorID shared.ID) {
	t.Helper()
	_, err := db.Exec(`
		UPDATE commands
		SET sensor_id = $1, status = 'acknowledged', acknowledged_at = NOW() - INTERVAL '30 minutes'
		WHERE id = $2
	`, sensorID.String(), cmdID.String())
	if err != nil {
		t.Fatalf("Failed to re-stick command: %v", err)
	}
}

// createTestAckRecentCommand creates an 'acknowledged' command acknowledged just
// now (not stuck) — recovery must leave it alone.
func createTestAckRecentCommand(t *testing.T, db *sql.DB, tenantID, sensorID shared.ID, dispatchAttempts int) shared.ID {
	t.Helper()

	id := shared.NewID()

	_, err := db.Exec(`
		INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, is_platform_job, dispatch_attempts, created_at, acknowledged_at)
		VALUES ($1, $2, $3, 'scan', 'acknowledged', '{}', false, $4, NOW(), NOW())
	`, id.String(), tenantID.String(), sensorID.String(), dispatchAttempts)
	if err != nil {
		t.Fatalf("Failed to create test acknowledged recent command: %v", err)
	}

	return id
}
