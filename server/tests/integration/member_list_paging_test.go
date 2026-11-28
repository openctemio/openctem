package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
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

// TestMemberSearch_UserIDsFilter backs the people chip: it resolves the
// handful of ids on screen, however large the organization, and never answers
// for a user who is not a member of the listed organization.
func TestMemberSearch_UserIDsFilter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenantA := createTestTenant(t, db, "member-ids-a")
	tenantB := createTestTenant(t, db, "member-ids-b")
	defer cleanupTestData(db, tenantA, tenantB)

	stamp := time.Now().UnixNano()
	var users []shared.ID
	defer func() {
		for _, id := range users {
			_, _ = db.Exec("DELETE FROM tenant_members WHERE user_id = $1", id.String())
			_, _ = db.Exec("DELETE FROM users WHERE id = $1", id.String())
		}
	}()
	for i := 0; i < 5; i++ {
		uid := createTestUser(t, db, fmt.Sprintf("ids-%d-%d@example.com", stamp, i), fmt.Sprintf("Ids %d", i))
		users = append(users, uid)
		createTestMembership(t, db, tenantA, uid, "member")
	}
	outsider := createTestUser(t, db, fmt.Sprintf("ids-%d-out@example.com", stamp), "Outsider")
	users = append(users, outsider)
	createTestMembership(t, db, tenantB, outsider, "member")

	repo := postgres.NewTenantRepository(&postgres.DB{DB: db})
	// Page size 1 would hide members 2..5 if the filter relied on the first page.
	r, err := repo.SearchMembersWithUserInfo(ctx, tenantA, tenant.MemberSearchFilters{
		Limit:   100,
		UserIDs: []string{users[4].String(), users[0].String(), outsider.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 2 || len(r.Members) != 2 {
		t.Fatalf("got %d/%d members, want exactly the two members asked for (the other tenant's user must be absent)", len(r.Members), r.Total)
	}
	for _, m := range r.Members {
		if m.UserID == outsider {
			t.Fatal("a user of another organization was returned")
		}
	}
}

// TestMemberSearch_AccountFilter backs the settings Members page, which listed
// an organization's service accounts as people (a synthetic
// svc-…@service-accounts.invalid address, no roles). The directory asks for
// account=person; service accounts are listed only with account=service, each
// marked, and never another organization's.
func TestMemberSearch_AccountFilter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenantA := createTestTenant(t, db, "member-account-a")
	tenantB := createTestTenant(t, db, "member-account-b")
	defer cleanupTestData(db, tenantA, tenantB)

	stamp := time.Now().UnixNano()
	tag := fmt.Sprintf("acct-%d", stamp)
	var users []shared.ID
	defer func() {
		for _, id := range users {
			_, _ = db.ExecContext(ctx, "DELETE FROM tenant_members WHERE user_id = $1", id.String())
			_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id.String())
		}
	}()
	person := createTestUser(t, db, tag+"-person@example.com", tag+" person")
	users = append(users, person)
	createTestMembership(t, db, tenantA, person, "member")

	service := func(tenantID shared.ID, name string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name, kind, service_tenant_id, service_owner_id)
			VALUES ($1, $2, $3, 'service', $4, $5)`,
			id.String(), "svc-"+id.String()+"@service-accounts.invalid", name, tenantID.String(), person.String()); err != nil {
			t.Fatalf("seed service account: %v", err)
		}
		users = append(users, id)
		createTestMembership(t, db, tenantID, id, "member")
		return id
	}
	svcA := service(tenantA, tag+" ci bot")
	svcB := service(tenantB, tag+" other org bot")

	repo := postgres.NewTenantRepository(&postgres.DB{DB: db})
	search := func(account string) *tenant.MemberSearchResult {
		t.Helper()
		r, err := repo.SearchMembersWithUserInfo(ctx, tenantA, tenant.MemberSearchFilters{Search: tag, Limit: 10, Account: account})
		if err != nil {
			t.Fatalf("search account=%q: %v", account, err)
		}
		return r
	}
	ids := func(r *tenant.MemberSearchResult) map[shared.ID]bool {
		out := map[shared.ID]bool{}
		for _, m := range r.Members {
			out[m.UserID] = true
		}
		return out
	}

	t.Run("people only", func(t *testing.T) {
		r := search(tenant.MemberAccountPerson)
		if r.Total != 1 || !ids(r)[person] {
			t.Fatalf("account=person: total %d, members %v; want only the person", r.Total, ids(r))
		}
		if r.Members[0].ServiceAccount {
			t.Errorf("a person is marked as a service account")
		}
	})

	t.Run("service accounts only, marked, never another organization's", func(t *testing.T) {
		r := search(tenant.MemberAccountService)
		got := ids(r)
		if r.Total != 1 || !got[svcA] {
			t.Fatalf("account=service: total %d, members %v; want only this organization's service account", r.Total, got)
		}
		if got[svcB] {
			t.Fatalf("another organization's service account listed")
		}
		if !r.Members[0].ServiceAccount {
			t.Errorf("service account not marked")
		}
	})

	t.Run("the directory figures count people only", func(t *testing.T) {
		stats, err := repo.GetMemberStats(ctx, tenantA)
		if err != nil {
			t.Fatalf("stats: %v", err)
		}
		if stats.TotalMembers != 1 {
			t.Errorf("total members = %d, want 1 (the person, not the service account)", stats.TotalMembers)
		}
	})

	t.Run("no filter lists both, still tenant scoped", func(t *testing.T) {
		got := ids(search(""))
		if !got[person] || !got[svcA] || got[svcB] {
			t.Fatalf("no account filter: %v", got)
		}
	})
}
