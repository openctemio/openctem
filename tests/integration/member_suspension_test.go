package integration

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// TestMemberSuspensionListVisibility verifies that suspending a membership
// is visible through every member-list endpoint the UI consumes:
//
//   - ListMembersWithUserInfo  → returns status="suspended"
//   - SearchMembersWithUserInfo → returns status="suspended" + correct count
//   - GetMemberStats           → ActiveMembers excludes suspended rows
//   - GetMemberByEmail         → returns status="suspended"
//
// This is a regression guard for the bug where the queries selected
// users.status (always 'active') instead of tenant_members.status, which
// caused the UI to silently lie to operators after they clicked "Suspend".
//
// Run with: go test -v ./tests/integration -run TestMemberSuspensionListVisibility
func TestMemberSuspensionListVisibility(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test tenant + user + active membership.
	tenantID := createTestTenant(t, db, "Suspension Visibility")
	defer cleanupTestData(db, tenantID)

	// Unique email per run so this test can be invoked repeatedly without
	// hitting the users.email UNIQUE constraint.
	email := fmt.Sprintf("suspension-vis-%d@example.com", time.Now().UnixNano())
	userID := createTestUser(t, db, email, "Suspension Vis")
	defer db.Exec("DELETE FROM users WHERE id = $1", userID.String())

	memberID := createTestMembership(t, db, tenantID, userID, "member")
	defer db.Exec("DELETE FROM tenant_members WHERE id = $1", memberID.String())

	repo := postgres.NewTenantRepository(&postgres.DB{DB: db})

	// --- Sanity check: before suspension, status should be 'active' ---
	t.Run("ActiveBaseline", func(t *testing.T) {
		members, err := repo.ListMembersWithUserInfo(context.Background(), tenantID)
		if err != nil {
			t.Fatalf("ListMembersWithUserInfo: %v", err)
		}
		got := findMember(members, userID)
		if got == nil {
			t.Fatalf("expected to find member %s in list, got %d members", userID.String(), len(members))
		}
		if got.Status != string(tenant.MemberStatusActive) {
			t.Errorf("baseline status: want %q, got %q", tenant.MemberStatusActive, got.Status)
		}
	})

	// --- Suspend at the SQL level (simulates what TenantService.SuspendMember persists) ---
	if _, err := db.Exec(`
		UPDATE tenant_members
		SET status = 'suspended', suspended_at = NOW()
		WHERE id = $1
	`, memberID.String()); err != nil {
		t.Fatalf("suspend update failed: %v", err)
	}

	// --- ListMembersWithUserInfo must reflect the new status ---
	t.Run("ListReturnsSuspended", func(t *testing.T) {
		members, err := repo.ListMembersWithUserInfo(context.Background(), tenantID)
		if err != nil {
			t.Fatalf("ListMembersWithUserInfo: %v", err)
		}
		got := findMember(members, userID)
		if got == nil {
			t.Fatalf("member not in list after suspension")
		}
		if got.Status != string(tenant.MemberStatusSuspended) {
			t.Errorf("after suspend, want status=%q, got %q (regression: query may be reading users.status again)",
				tenant.MemberStatusSuspended, got.Status)
		}
	})

	// --- SearchMembersWithUserInfo must reflect it too ---
	t.Run("SearchReturnsSuspended", func(t *testing.T) {
		result, err := repo.SearchMembersWithUserInfo(context.Background(), tenantID, tenant.MemberSearchFilters{
			Search: email,
			Limit:  50,
		})
		if err != nil {
			t.Fatalf("SearchMembersWithUserInfo: %v", err)
		}
		got := findMember(result.Members, userID)
		if got == nil {
			t.Fatalf("member not in search result; total=%d, returned=%d", result.Total, len(result.Members))
		}
		if got.Status != string(tenant.MemberStatusSuspended) {
			t.Errorf("after suspend (search), want status=%q, got %q", tenant.MemberStatusSuspended, got.Status)
		}
	})

	// --- GetMemberByEmail single-row path ---
	t.Run("GetByEmailReturnsSuspended", func(t *testing.T) {
		got, err := repo.GetMemberByEmail(context.Background(), tenantID, email)
		if err != nil {
			t.Fatalf("GetMemberByEmail: %v", err)
		}
		if got.Status != string(tenant.MemberStatusSuspended) {
			t.Errorf("after suspend (by email), want status=%q, got %q", tenant.MemberStatusSuspended, got.Status)
		}
	})

	// --- GetMemberStats: ActiveMembers must NOT count the suspended row ---
	t.Run("StatsExcludeSuspended", func(t *testing.T) {
		stats, err := repo.GetMemberStats(context.Background(), tenantID)
		if err != nil {
			t.Fatalf("GetMemberStats: %v", err)
		}
		if stats.TotalMembers != 1 {
			t.Errorf("TotalMembers: want 1, got %d", stats.TotalMembers)
		}
		if stats.ActiveMembers != 0 {
			t.Errorf("ActiveMembers after suspension: want 0, got %d (regression: stats may be counting users.status='active')",
				stats.ActiveMembers)
		}
	})

	// --- Reactivate and verify the round-trip works too ---
	if _, err := db.Exec(`
		UPDATE tenant_members
		SET status = 'active', suspended_at = NULL, suspended_by = NULL
		WHERE id = $1
	`, memberID.String()); err != nil {
		t.Fatalf("reactivate update failed: %v", err)
	}

	t.Run("ListReturnsActiveAfterReactivate", func(t *testing.T) {
		members, err := repo.ListMembersWithUserInfo(context.Background(), tenantID)
		if err != nil {
			t.Fatalf("ListMembersWithUserInfo: %v", err)
		}
		got := findMember(members, userID)
		if got == nil {
			t.Fatalf("member not in list after reactivate")
		}
		if got.Status != string(tenant.MemberStatusActive) {
			t.Errorf("after reactivate, want status=%q, got %q", tenant.MemberStatusActive, got.Status)
		}
	})
}

// findMember locates a member by user id in a slice of MemberWithUser.
func findMember(members []*tenant.MemberWithUser, userID shared.ID) *tenant.MemberWithUser {
	for _, m := range members {
		if m.UserID == userID {
			return m
		}
	}
	return nil
}

// createTestUser inserts a minimal user row and returns the new id.
// The caller is responsible for choosing an email that won't collide with
// existing rows (use shared.NewID() in the email if running concurrently).
func createTestUser(t *testing.T, db *sql.DB, email, name string) shared.ID {
	t.Helper()

	id := shared.NewID()
	_, err := db.Exec(`
		INSERT INTO users (id, email, name, status, auth_provider, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', 'local', true, NOW(), NOW())
	`, id.String(), email, name)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	return id
}

// createTestMembership inserts a tenant_members row and returns its id.
func createTestMembership(t *testing.T, db *sql.DB, tenantID, userID shared.ID, role string) shared.ID {
	t.Helper()

	id := shared.NewID()
	_, err := db.Exec(`
		INSERT INTO tenant_members (id, tenant_id, user_id, role, status, joined_at)
		VALUES ($1, $2, $3, $4, 'active', NOW())
	`, id.String(), tenantID.String(), userID.String(), role)
	if err != nil {
		t.Fatalf("Failed to create test membership: %v", err)
	}

	return id
}
