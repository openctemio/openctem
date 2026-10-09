package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Team membership expiry (RFC-050 W22, migration 001459): the end date round
// trips, only memberships past it are listed, and removing one takes the
// team's assets out of that member's data scope while the other member keeps
// them. Requires DATABASE_URL.
func TestGroupMembershipExpiry(t *testing.T) {
	ctx := context.Background()
	db := openRoleRaceDB(t)
	repo := NewGroupRepository(db)

	tenantID := seedTenant(ctx, t, db)
	expired, current := seedUser(ctx, t, db), seedUser(ctx, t, db)
	for _, u := range []shared.ID{expired, current} {
		addTenantMember(ctx, t, db.DB, tenantID, u)
	}
	assetID := seedAsset(ctx, t, db.DB, tenantID)

	groupID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO groups (id, tenant_id, name, slug, group_type) VALUES ($1, $2, 'Engagement', $3, 'external')`,
		groupID.String(), tenantID.String(), "eng-"+groupID.String()); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'primary')`,
		assetID.String(), groupID.String()); err != nil {
		t.Fatalf("seed asset owner: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	future := now.Add(48 * time.Hour)
	mExpired, _ := group.NewMember(groupID, expired, group.MemberRoleMember, nil)
	mCurrent, _ := group.NewMember(groupID, current, group.MemberRoleMember, nil)
	if err := mCurrent.SetExpiry(&future, "engagement Q4", now); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*group.Member{mExpired, mCurrent} {
		if err := repo.AddMember(ctx, m); err != nil {
			t.Fatalf("add member: %v", err)
		}
	}
	// The first membership's end date passes (written directly: SetExpiry
	// refuses a past date).
	if _, err := db.ExecContext(ctx,
		`UPDATE group_members SET expires_at = $3, expiry_reason = 'audit' WHERE group_id = $1 AND user_id = $2`,
		groupID.String(), expired.String(), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, u := range []shared.ID{expired, current} {
		if _, err := db.ExecContext(ctx, `SELECT refresh_access_for_user($1, $2)`, tenantID.String(), u.String()); err != nil {
			t.Fatalf("refresh access: %v", err)
		}
		if n := countAccessRows(ctx, t, db.DB, u); n != 1 {
			t.Fatalf("user %s sees %d assets before expiry, want 1", u, n)
		}
	}

	got, err := repo.GetMember(ctx, groupID, current)
	if err != nil || got.ExpiresAt() == nil || !got.ExpiresAt().Equal(future) || got.ExpiryReason() != "engagement Q4" {
		t.Fatalf("round trip: %+v %v", got, err)
	}

	list, err := repo.ListExpiredMembers(ctx, now, 50)
	if err != nil {
		t.Fatal(err)
	}
	var mine []group.ExpiredMember
	for _, e := range list {
		if e.GroupID == groupID {
			mine = append(mine, e)
		}
	}
	if len(mine) != 1 || mine[0].UserID != expired || mine[0].TenantID != tenantID || mine[0].Reason != "audit" {
		t.Fatalf("expired memberships of the group = %+v, want only the expired one", mine)
	}

	if err := repo.RemoveMember(ctx, groupID, expired); err != nil {
		t.Fatal(err)
	}
	if n := countAccessRows(ctx, t, db.DB, expired); n != 0 {
		t.Errorf("the expired member still sees %d assets", n)
	}
	if n := countAccessRows(ctx, t, db.DB, current); n != 1 {
		t.Errorf("the current member sees %d assets, want 1", n)
	}
}
