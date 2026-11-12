package remediation

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OwnerFindingRef is what the owner picker needs of a finding: its asset and
// assignee, to decide whether a candidate can see it. No title or content.
type OwnerFindingRef struct {
	FindingID  shared.ID
	AssetID    shared.ID
	AssignedTo *shared.ID
}

// OwnerUser is a person the picker can offer.
type OwnerUser struct {
	ID    shared.ID
	Name  string
	Email string
}

// OwnerGroup is a team the picker can offer.
type OwnerGroup struct {
	ID   shared.ID
	Name string
}

// OwnerAccessRepository reads what the owner picker and the owner access
// rule need. Every method is tenant-scoped.
type OwnerAccessRepository interface {
	// OpenFindingRefs: the open findings among ids (closed or foreign ids are absent).
	OpenFindingRefs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]OwnerFindingRef, error)
	// TaskOpenPrimaryRefs: the open, active primary findings of a task.
	TaskOpenPrimaryRefs(ctx context.Context, tenantID, taskID shared.ID) ([]OwnerFindingRef, error)
	SearchOwnerUsers(ctx context.Context, tenantID shared.ID, q string, limit int) ([]OwnerUser, error)
	SearchOwnerGroups(ctx context.Context, tenantID shared.ID, q string, limit int) ([]OwnerGroup, error)
	// GroupActiveMembers: the active, unexpired members of a team (at most
	// limit) and the number of them in all.
	GroupActiveMembers(ctx context.Context, tenantID, groupID shared.ID, limit int) ([]shared.ID, int, error)
}
