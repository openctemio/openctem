package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	accesscontrolsvc "github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Team membership expiry (RFC-050 W22).

func TestMemberSetExpiry_Rules(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	m, _ := group.NewMember(shared.NewID(), shared.NewID(), group.MemberRoleMember, nil)
	past, tooFar, ok := now.Add(-time.Second), now.Add(366*24*time.Hour), now.Add(30*24*time.Hour)

	if err := m.SetExpiry(&past, "", now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a past end date: %v", err)
	}
	if err := m.SetExpiry(&tooFar, "", now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("an end date beyond 365 days: %v", err)
	}
	long := make([]byte, group.MaxExpiryReasonLength+1)
	if err := m.SetExpiry(&ok, string(long), now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a reason that is too long: %v", err)
	}
	if err := m.SetExpiry(&ok, "engagement", now); err != nil || !m.ExpiresAt().Equal(ok) || m.ExpiryReason() != "engagement" {
		t.Fatalf("a valid end date: %v %v %q", err, m.ExpiresAt(), m.ExpiryReason())
	}
	if m.IsExpired(now) || !m.IsExpired(ok) {
		t.Error("IsExpired")
	}
	if err := m.SetExpiry(nil, "ignored", now); err != nil || m.ExpiresAt() != nil || m.ExpiryReason() != "" {
		t.Errorf("clearing: %v %v %q", err, m.ExpiresAt(), m.ExpiryReason())
	}
}

func expiryService(repo group.Repository, lister group.ExpiredMemberLister) *accesscontrolsvc.GroupService {
	return accesscontrolsvc.NewGroupService(repo, logger.NewNop(), accesscontrolsvc.WithExpiredMemberLister(lister))
}

// An external team (engagements, audits) admits a member only with an end
// date; an internal team admits one without.
func TestAddMember_ExternalTeamNeedsAnEndDate(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	ext, _ := group.NewGroup(tenantID, "Engagement", "engagement", group.GroupTypeExternal)
	team, _ := group.NewGroup(tenantID, "Team", "team", group.GroupTypeTeam)
	repo := newMockGroupRepoForBulk()
	repo.addGroup(ext)
	repo.addGroup(team)
	repo.getMemberErr = group.ErrMemberNotFound
	svc := expiryService(repo, nil)
	actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorID: shared.NewID().String()}

	_, err := svc.AddMember(ctx, accesscontrolsvc.AddGroupMemberInput{
		GroupID: ext.ID().String(), UserID: shared.NewID(), Role: "member",
	}, actx)
	if !errors.Is(err, accesscontrolsvc.ErrExpiryRequired) {
		t.Fatalf("external team without an end date: %v", err)
	}

	end := time.Now().UTC().Add(30 * 24 * time.Hour)
	m, err := svc.AddMember(ctx, accesscontrolsvc.AddGroupMemberInput{
		GroupID: ext.ID().String(), UserID: shared.NewID(), Role: "member", ExpiresAt: &end, ExpiryReason: "pentest Q4",
	}, actx)
	if err != nil || m.ExpiresAt() == nil {
		t.Fatalf("external team with an end date: %v", err)
	}

	past := time.Now().UTC().Add(-time.Hour)
	if _, err := svc.AddMember(ctx, accesscontrolsvc.AddGroupMemberInput{
		GroupID: team.ID().String(), UserID: shared.NewID(), Role: "member", ExpiresAt: &past,
	}, actx); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a past end date: %v", err)
	}
	if _, err := svc.AddMember(ctx, accesscontrolsvc.AddGroupMemberInput{
		GroupID: team.ID().String(), UserID: shared.NewID(), Role: "member",
	}, actx); err != nil {
		t.Fatalf("internal team without an end date: %v", err)
	}
}

// Clearing the end date of an external team's member is refused; moving it
// is allowed, and nobody changes their own membership.
func TestSetMemberAccess(t *testing.T) {
	ctx := context.Background()
	tenantID, user := shared.NewID(), shared.NewID()
	ext, _ := group.NewGroup(tenantID, "Engagement", "engagement", group.GroupTypeExternal)
	repo := newMockGroupRepoForBulk()
	repo.addGroup(ext)
	member, _ := group.NewMember(ext.ID(), user, group.MemberRoleMember, nil)
	end := time.Now().UTC().Add(24 * time.Hour)
	_ = member.SetExpiry(&end, "", time.Now().UTC())
	repo.getMemberResult = member
	svc := expiryService(repo, nil)
	actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorID: shared.NewID().String()}

	if _, err := svc.SetMemberAccess(ctx, accesscontrolsvc.SetGroupMemberAccessInput{
		GroupID: ext.ID().String(), UserID: user, ExpiresAt: nil,
	}, actx); !errors.Is(err, accesscontrolsvc.ErrExpiryRequired) {
		t.Fatalf("clearing an external member's end date: %v", err)
	}
	later := time.Now().UTC().Add(10 * 24 * time.Hour)
	if m, err := svc.SetMemberAccess(ctx, accesscontrolsvc.SetGroupMemberAccessInput{
		GroupID: ext.ID().String(), UserID: user, ExpiresAt: &later, Reason: "extended",
	}, actx); err != nil || !m.ExpiresAt().Equal(later) {
		t.Fatalf("moving the end date: %v", err)
	}
	// Another organization's caller cannot see the team.
	other := auditapp.AuditContext{TenantID: shared.NewID().String(), ActorID: actx.ActorID}
	if _, err := svc.SetMemberAccess(ctx, accesscontrolsvc.SetGroupMemberAccessInput{
		GroupID: ext.ID().String(), UserID: user, ExpiresAt: &later,
	}, other); err == nil {
		t.Fatal("a caller from another organization changed the membership")
	}
}

type fakeExpiredLister struct{ items []group.ExpiredMember }

func (f fakeExpiredLister) ListExpiredMembers(context.Context, time.Time, int) ([]group.ExpiredMember, error) {
	return f.items, nil
}

type removalRecorder struct {
	*mockGroupRepoForBulk
	removed []shared.ID
}

func (r *removalRecorder) RemoveMember(_ context.Context, _, userID shared.ID) error {
	r.removed = append(r.removed, userID)
	return nil
}

// The sweep removes every listed membership.
func TestExpireMemberships_RemovesListed(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	rec := &removalRecorder{mockGroupRepoForBulk: newMockGroupRepoForBulk()}
	lister := fakeExpiredLister{items: []group.ExpiredMember{
		{TenantID: shared.NewID(), GroupID: shared.NewID(), UserID: a, ExpiresAt: time.Now()},
		{TenantID: shared.NewID(), GroupID: shared.NewID(), UserID: b, ExpiresAt: time.Now()},
	}}
	n, err := expiryService(rec, lister).ExpireMemberships(context.Background(), time.Now(), 10)
	if err != nil || n != 2 || len(rec.removed) != 2 || rec.removed[0] != a || rec.removed[1] != b {
		t.Fatalf("removed %d %v (%v)", n, rec.removed, err)
	}
	// Without a lister the sweep does nothing.
	if n, err := expiryService(rec, nil).ExpireMemberships(context.Background(), time.Now(), 10); n != 0 || err != nil {
		t.Fatalf("no lister: %d %v", n, err)
	}
}
