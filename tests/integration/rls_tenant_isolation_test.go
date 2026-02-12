package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TestRLSTenantIsolation tests Row Level Security tenant isolation.
// These tests require a running PostgreSQL database with RLS enabled.
//
// Run with: go test -v ./tests/integration -run TestRLS
func TestRLSTenantIsolation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test tenants
	tenant1ID := createTestTenant(t, db, "Tenant 1")
	tenant2ID := createTestTenant(t, db, "Tenant 2")

	// Create test assets for each tenant
	asset1ID := createTestAsset(t, db, tenant1ID, "Asset 1")
	asset2ID := createTestAsset(t, db, tenant2ID, "Asset 2")

	// Create test findings for each tenant
	finding1ID := createTestFinding(t, db, tenant1ID, asset1ID, "Finding 1")
	finding2ID := createTestFinding(t, db, tenant2ID, asset2ID, "Finding 2")

	// Create non-superuser connection for RLS tests
	rlsDB := setupRLSTestDB(t)
	defer rlsDB.Close()

	t.Run("NoTenantContext_ReturnsZeroRows", func(t *testing.T) {
		// Query without setting tenant context
		var count int
		err := rlsDB.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if count != 0 {
			t.Errorf("Expected 0 rows without tenant context, got %d", count)
		}
	})

	t.Run("WrongTenantContext_ReturnsZeroRows", func(t *testing.T) {
		tx, err := rlsDB.Begin()
		if err != nil {
			t.Fatalf("Begin failed: %v", err)
		}
		defer tx.Rollback()

		// Set wrong tenant context
		wrongTenantID := shared.NewID()
		setTenantContext(t, tx, wrongTenantID)

		var count int
		err = tx.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if count != 0 {
			t.Errorf("Expected 0 rows with wrong tenant, got %d", count)
		}
	})

	t.Run("CorrectTenantContext_ReturnsTenantData", func(t *testing.T) {
		tx, err := rlsDB.Begin()
		if err != nil {
			t.Fatalf("Begin failed: %v", err)
		}
		defer tx.Rollback()

		// Set correct tenant context
		setTenantContext(t, tx, tenant1ID)

		// Should see tenant1's finding
		var count int
		err = tx.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if count != 1 {
			t.Errorf("Expected 1 row for tenant1, got %d", count)
		}

		// Verify it's the correct finding
		var foundID string
		err = tx.QueryRow("SELECT id FROM findings").Scan(&foundID)
		if err != nil {
			t.Fatalf("Query finding ID failed: %v", err)
		}

		if foundID != finding1ID.String() {
			t.Errorf("Expected finding ID %s, got %s", finding1ID, foundID)
		}
	})

	t.Run("Tenant2Context_SeesTenant2DataOnly", func(t *testing.T) {
		tx, err := rlsDB.Begin()
		if err != nil {
			t.Fatalf("Begin failed: %v", err)
		}
		defer tx.Rollback()

		// Set tenant2 context
		setTenantContext(t, tx, tenant2ID)

		// Should see tenant2's finding only
		var foundID string
		err = tx.QueryRow("SELECT id FROM findings").Scan(&foundID)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if foundID != finding2ID.String() {
			t.Errorf("Expected finding ID %s, got %s", finding2ID, foundID)
		}
	})

	t.Run("PlatformAdminBypass_SeesAllData", func(t *testing.T) {
		tx, err := rlsDB.Begin()
		if err != nil {
			t.Fatalf("Begin failed: %v", err)
		}
		defer tx.Rollback()

		// Set platform admin bypass
		setPlatformAdminContext(t, tx)

		// Should see all findings - use IN with literal values since we can't parameterize easily
		query := fmt.Sprintf("SELECT COUNT(*) FROM findings WHERE id IN ('%s', '%s')",
			finding1ID.String(), finding2ID.String())
		var count int
		err = tx.QueryRow(query).Scan(&count)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if count != 2 {
			t.Errorf("Expected 2 rows as admin, got %d", count)
		}
	})

	t.Run("ContextReset_BlocksAccessAgain", func(t *testing.T) {
		tx, err := rlsDB.Begin()
		if err != nil {
			t.Fatalf("Begin failed: %v", err)
		}
		defer tx.Rollback()

		// Set tenant context
		setTenantContext(t, tx, tenant1ID)

		// Verify we can see data
		var count1 int
		tx.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count1)
		if count1 == 0 {
			t.Error("Should see data with tenant context")
		}

		// Reset context
		_, err = tx.Exec("RESET app.current_tenant_id")
		if err != nil {
			t.Fatalf("Reset context failed: %v", err)
		}

		// Should no longer see data
		var count2 int
		tx.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count2)
		if count2 != 0 {
			t.Errorf("Should not see data after reset, got %d rows", count2)
		}
	})

	t.Run("UpdateWithWrongTenant_AffectsZeroRows", func(t *testing.T) {
		tx, err := rlsDB.Begin()
		if err != nil {
			t.Fatalf("Begin failed: %v", err)
		}
		defer tx.Rollback()

		// Set tenant1 context
		setTenantContext(t, tx, tenant1ID)

		// Try to update tenant2's finding (should affect 0 rows due to RLS)
		query := fmt.Sprintf("UPDATE findings SET message = 'hacked' WHERE id = '%s'",
			finding2ID.String())
		result, err := tx.Exec(query)
		if err != nil {
			t.Fatalf("Update failed: %v", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected != 0 {
			t.Errorf("Expected 0 rows affected when updating other tenant's data, got %d", rowsAffected)
		}
	})

	t.Run("DeleteWithWrongTenant_AffectsZeroRows", func(t *testing.T) {
		tx, err := rlsDB.Begin()
		if err != nil {
			t.Fatalf("Begin failed: %v", err)
		}
		defer tx.Rollback()

		// Set tenant1 context
		setTenantContext(t, tx, tenant1ID)

		// Try to delete tenant2's finding (should affect 0 rows due to RLS)
		query := fmt.Sprintf("DELETE FROM findings WHERE id = '%s'", finding2ID.String())
		result, err := tx.Exec(query)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected != 0 {
			t.Errorf("Expected 0 rows affected when deleting other tenant's data, got %d", rowsAffected)
		}
	})

	// Cleanup test data
	t.Cleanup(func() {
		cleanupTestData(db, tenant1ID, tenant2ID)
	})
}

// TestRLSAssetIsolation tests RLS on assets table.
func TestRLSAssetIsolation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tenant1ID := createTestTenant(t, db, "Asset Test Tenant 1")
	tenant2ID := createTestTenant(t, db, "Asset Test Tenant 2")

	asset1ID := createTestAsset(t, db, tenant1ID, "Asset 1")
	_ = createTestAsset(t, db, tenant2ID, "Asset 2")

	rlsDB := setupRLSTestDB(t)
	defer rlsDB.Close()

	t.Run("AssetIsolation_Tenant1SeesOnlyOwnAssets", func(t *testing.T) {
		tx, err := rlsDB.Begin()
		if err != nil {
			t.Fatalf("Begin failed: %v", err)
		}
		defer tx.Rollback()

		setTenantContext(t, tx, tenant1ID)

		var count int
		err = tx.QueryRow("SELECT COUNT(*) FROM assets").Scan(&count)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if count != 1 {
			t.Errorf("Expected 1 asset for tenant1, got %d", count)
		}

		var foundID string
		tx.QueryRow("SELECT id FROM assets").Scan(&foundID)
		if foundID != asset1ID.String() {
			t.Errorf("Expected asset ID %s, got %s", asset1ID, foundID)
		}
	})

	t.Cleanup(func() {
		cleanupTestData(db, tenant1ID, tenant2ID)
	})
}

// =============================================================================
// Test Helpers
// =============================================================================

// setTenantContext sets the RLS tenant context for the transaction.
// PostgreSQL SET LOCAL doesn't support parameterized queries, so we format it safely.
func setTenantContext(t *testing.T, tx *sql.Tx, tenantID shared.ID) {
	t.Helper()
	// Use format string with quoted identifier for the UUID
	query := fmt.Sprintf("SET LOCAL app.current_tenant_id = '%s'", tenantID.String())
	_, err := tx.Exec(query)
	if err != nil {
		t.Fatalf("Set tenant context failed: %v", err)
	}
}

// setPlatformAdminContext sets the platform admin bypass for RLS.
func setPlatformAdminContext(t *testing.T, tx *sql.Tx) {
	t.Helper()
	_, err := tx.Exec("SET LOCAL app.is_platform_admin = 'true'")
	if err != nil {
		t.Fatalf("Set admin context failed: %v", err)
	}
}

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Try common local development configurations
		dbURL = "postgres://openctem@localhost:5432/openctem?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("Skipping RLS integration test: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Skipf("Skipping RLS integration test: database not available: %v", err)
	}

	return db
}

func setupRLSTestDB(t *testing.T) *sql.DB {
	t.Helper()

	// Connect as non-superuser for RLS testing
	dbURL := os.Getenv("DATABASE_URL_RLS_TEST")
	if dbURL == "" {
		dbURL = "postgres://rls_test_user:test_password_123@localhost:5432/openctem?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("Skipping RLS test: cannot connect as RLS test user: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Skipf("Skipping RLS test: RLS test user not available: %v", err)
	}

	return db
}

func createTestTenant(t *testing.T, db *sql.DB, name string) shared.ID {
	t.Helper()

	id := shared.NewID()
	slug := fmt.Sprintf("test-%s-%d", name, time.Now().UnixNano())

	_, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, id.String(), name, slug)
	if err != nil {
		t.Fatalf("Failed to create test tenant: %v", err)
	}

	return id
}

func createTestAsset(t *testing.T, db *sql.DB, tenantID shared.ID, name string) shared.ID {
	t.Helper()

	id := shared.NewID()

	_, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'repository', 'medium', 'active', NOW(), NOW())
	`, id.String(), tenantID.String(), name)
	if err != nil {
		t.Fatalf("Failed to create test asset: %v", err)
	}

	return id
}

func createTestFinding(t *testing.T, db *sql.DB, tenantID, assetID shared.ID, msg string) shared.ID {
	t.Helper()

	id := shared.NewID()
	fingerprint := fmt.Sprintf("test-fp-%s", id.String())

	_, err := db.Exec(`
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, created_at, updated_at)
		VALUES ($1, $2, $3, 'manual', 'rls_test', $4, 'low', 'new', $5, NOW(), NOW())
	`, id.String(), tenantID.String(), assetID.String(), msg, fingerprint)
	if err != nil {
		t.Fatalf("Failed to create test finding: %v", err)
	}

	return id
}

func cleanupTestData(db *sql.DB, tenantIDs ...shared.ID) {
	for _, id := range tenantIDs {
		// Delete findings first (FK constraint)
		db.Exec("DELETE FROM findings WHERE tenant_id = $1", id.String())
		// Delete assets
		db.Exec("DELETE FROM assets WHERE tenant_id = $1", id.String())
		// Delete tenant
		db.Exec("DELETE FROM tenants WHERE id = $1", id.String())
	}
}
