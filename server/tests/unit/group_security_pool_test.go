package unit

import (
	"context"
	"errors"
	"testing"

	accesscontrolsvc "github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type poolStepUpGate struct{ refuse bool }

var errPoolStepUp = errors.New("step up required")

func (g poolStepUpGate) RequireRecentAuth(context.Context, string) error {
	if g.refuse {
		return errPoolStepUp
	}
	return nil
}

// Adding or removing a member of the approval policy's security pool group,
// and deleting the group, need a recent re-authentication; any other group
// does not. With the check unavailable the edit of the pool is refused.
func TestSecurityPoolGroupEditsNeedStepUp(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	pool, _ := group.NewGroup(tenantID, "Security", "security", group.GroupTypeTeam)
	other, _ := group.NewGroup(tenantID, "Other", "other", group.GroupTypeTeam)
	repo := newMockGroupRepoForBulk()
	repo.addGroup(pool)
	repo.addGroup(other)
	repo.getMemberErr = group.ErrMemberNotFound
	svc := accesscontrolsvc.NewGroupService(repo, logger.NewNop())
	svc.SetSecurityPoolGuard(func(_ context.Context, _, id shared.ID) (bool, error) { return id == pool.ID(), nil })
	actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorID: shared.NewID().String()}
	add := func(g *group.Group) error {
		_, err := svc.AddMember(ctx, accesscontrolsvc.AddGroupMemberInput{GroupID: g.ID().String(), UserID: shared.NewID(), Role: "member"}, actx)
		return err
	}

	if err := add(pool); !errors.Is(err, accesscontrolsvc.ErrSecurityPoolStepUpUnavailable) {
		t.Fatalf("no step-up gate wired: %v", err)
	}
	svc.SetStepUpGate(poolStepUpGate{refuse: true})
	if err := add(pool); !errors.Is(err, errPoolStepUp) {
		t.Fatalf("stale session adding to the pool: %v", err)
	}
	if err := add(other); err != nil {
		t.Fatalf("another group needs no step-up: %v", err)
	}
	if err := svc.DeleteGroup(ctx, pool.ID().String(), actx); !errors.Is(err, errPoolStepUp) {
		t.Fatalf("stale session deleting the pool: %v", err)
	}
	svc.SetStepUpGate(poolStepUpGate{})
	if err := add(pool); err != nil {
		t.Fatalf("recent sign-in adding to the pool: %v", err)
	}
}
