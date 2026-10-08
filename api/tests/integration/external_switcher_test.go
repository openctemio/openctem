package integration

// The organization switcher and the External members view (RFC-058): the
// caller's own memberships carry kind, end of access and the reason an
// organization is blocked; the member list filters on kind.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestExternalMembership_SwitcherAndKindFilter(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	repo := postgres.NewTenantRepository(&postgres.DB{DB: db})

	host := createTestTenant(t, db, "ext-host")
	other := createTestTenant(t, db, "ext-other")
	stamp := shared.NewID().String()[:8]
	ext := createTestUser(t, db, "ext-"+stamp+"@gmail.com", "Ext")
	in := createTestUser(t, db, "in-"+stamp+"@host.example", "In")
	t.Cleanup(func() {
		for _, tn := range []shared.ID{host, other} {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM tenant_members WHERE tenant_id = $1`, tn.String())
			cleanupTestData(db, tn)
		}
	})
	createTestMembership(t, db, host, ext, "viewer")
	createTestMembership(t, db, other, ext, "viewer")
	createTestMembership(t, db, host, in, "member")
	until := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	// In host: an active external member with an end date. In other: the
	// same person, suspended because the access expired.
	if _, err := db.ExecContext(ctx, `UPDATE tenant_members SET kind = 'external', home_domain = 'gmail.com', expires_at = $3
		WHERE tenant_id = $1 AND user_id = $2`, host.String(), ext.String(), until); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tenant_members SET kind = 'external', home_domain = 'gmail.com', expires_at = $3,
		status = 'suspended', suspended_reason = 'expired' WHERE tenant_id = $1 AND user_id = $2`, other.String(), ext.String(), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	mine, err := repo.ListTenantsByUser(ctx, ext)
	if err != nil {
		t.Fatal(err)
	}
	got := map[shared.ID]*tenant.TenantWithRole{}
	for _, m := range mine {
		got[m.Tenant.ID()] = m
	}
	h, o := got[host], got[other]
	if h == nil || o == nil {
		t.Fatalf("both organizations must be listed, got %d", len(mine))
	}
	if h.Kind != tenant.MemberKindExternal || h.ExpiresAt == nil || !h.ExpiresAt.Equal(until) || h.BlockedReason() != "" {
		t.Fatalf("host: kind=%s expires=%v blocked=%q", h.Kind, h.ExpiresAt, h.BlockedReason())
	}
	if o.BlockedReason() != tenant.SuspendedReasonExpired {
		t.Fatalf("other: blocked=%q, want expired", o.BlockedReason())
	}

	for _, tc := range []struct {
		kind string
		want []shared.ID
	}{
		{"external", []shared.ID{ext}},
		{"internal", []shared.ID{in}},
		{"", []shared.ID{ext, in}},
	} {
		res, err := repo.SearchMembersWithUserInfo(ctx, host, tenant.MemberSearchFilters{Kind: tc.kind, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		ids := map[shared.ID]bool{}
		for _, m := range res.Members {
			ids[m.UserID] = true
		}
		if len(ids) != len(tc.want) || res.Total != len(tc.want) {
			t.Fatalf("kind=%q: got %d members (total %d), want %d", tc.kind, len(ids), res.Total, len(tc.want))
		}
		for _, id := range tc.want {
			if !ids[id] {
				t.Fatalf("kind=%q: %s missing", tc.kind, id)
			}
		}
	}
}
