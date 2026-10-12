package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// TestMemberSearch_ServerSidePagingAndFilters backs the settings Members page,
// which used to load one capped page (100) and filter it in the browser, so
// member 101 and beyond were unreachable (23a B20). The page now pages,
// searches and filters on the server; this pins that every member is
// reachable by offset, that status/role filters narrow the total, and that
// another organization's members never appear.
func TestMemberSearch_ServerSidePagingAndFilters(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenantA := createTestTenant(t, db, "member-paging-a")
	tenantB := createTestTenant(t, db, "member-paging-b")
	defer cleanupTestData(db, tenantA, tenantB)

	stamp := time.Now().UnixNano()
	const n = 25
	var userIDs []shared.ID
	defer func() {
		for _, id := range userIDs {
			_, _ = db.Exec("DELETE FROM user_roles WHERE user_id = $1", id.String())
			_, _ = db.Exec("DELETE FROM tenant_members WHERE user_id = $1", id.String())
			_, _ = db.Exec("DELETE FROM users WHERE id = $1", id.String())
		}
	}()
	for i := 0; i < n; i++ {
		uid := createTestUser(t, db, fmt.Sprintf("paging-%d-%02d@example.com", stamp, i), fmt.Sprintf("Paging %02d", i))
		userIDs = append(userIDs, uid)
		mid := createTestMembership(t, db, tenantA, uid, "member")
		if i < 3 { // three admins
			if _, err := db.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, '00000000-0000-0000-0000-000000000002')`,
				uid.String(), tenantA.String()); err != nil {
				t.Fatalf("grant admin: %v", err)
			}
		}
		if i >= n-4 { // four suspended
			if _, err := db.Exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = NOW() WHERE id = $1`, mid.String()); err != nil {
				t.Fatalf("suspend: %v", err)
			}
		}
	}
	// A member of another organization, with a matching name.
	other := createTestUser(t, db, fmt.Sprintf("paging-%d-other@example.com", stamp), "Paging other org")
	userIDs = append(userIDs, other)
	createTestMembership(t, db, tenantB, other, "member")

	repo := postgres.NewTenantRepository(&postgres.DB{DB: db})
	search := func(f tenant.MemberSearchFilters) *tenant.MemberSearchResult {
		t.Helper()
		f.Search = fmt.Sprintf("paging-%d", stamp)
		r, err := repo.SearchMembersWithUserInfo(ctx, tenantA, f)
		if err != nil {
			t.Fatalf("search %+v: %v", f, err)
		}
		return r
	}

	t.Run("every member reachable by offset, none from another tenant", func(t *testing.T) {
		seen := map[shared.ID]bool{}
		for off := 0; off < n; off += 10 {
			r := search(tenant.MemberSearchFilters{Limit: 10, Offset: off})
			if r.Total != n {
				t.Fatalf("total = %d, want %d", r.Total, n)
			}
			for _, m := range r.Members {
				if m.UserID == other {
					t.Fatalf("member of another organization listed")
				}
				seen[m.UserID] = true
			}
		}
		if len(seen) != n {
			t.Fatalf("reached %d distinct members over all pages, want %d", len(seen), n)
		}
	})

	t.Run("status filter", func(t *testing.T) {
		if got := search(tenant.MemberSearchFilters{Limit: 10, Status: "suspended"}).Total; got != 4 {
			t.Errorf("suspended total = %d, want 4", got)
		}
		if got := search(tenant.MemberSearchFilters{Limit: 10, Status: "active"}).Total; got != n-4 {
			t.Errorf("active total = %d, want %d", got, n-4)
		}
	})

	t.Run("role filter", func(t *testing.T) {
		r := search(tenant.MemberSearchFilters{Limit: 10, Role: "admin"})
		if r.Total != 3 {
			t.Errorf("admin total = %d, want 3", r.Total)
		}
		for _, m := range r.Members {
			if m.Role.String() != "admin" {
				t.Errorf("role filter returned %s", m.Role)
			}
		}
		if got := search(tenant.MemberSearchFilters{Limit: 10, Role: "member"}).Total; got != n-3 {
			t.Errorf("member total = %d, want %d", got, n-3)
		}
	})
}
