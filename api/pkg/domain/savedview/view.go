// Package savedview is the saved list view (UI style contract D15, research
// 17 R3, docs/rfcs/RFC-048-list-query-contract.md §3.6): a named lens on one
// list page. It stores an RFC-048 FilterDocument and page state, never SQL and
// never results, and it always runs as the person using it.
package savedview

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Pages that have saved views, and limits.
const (
	PageFindings = "findings"

	MaxNameLen        = 120
	MaxDescriptionLen = 500
	MaxColumns        = 50
	MaxPerOwner       = 100
	MaxPerGroup       = 100
)

// Errors.
var (
	ErrNotFound    = errors.New("saved view not found")
	ErrNotOwner    = errors.New("only the owner of a saved view can change it")
	ErrLimit       = errors.New("too many saved views")
	ErrInvalid     = errors.New("invalid saved view")
	ErrUnknownPage = errors.New("unknown page")
)

// View is one saved view.
type View struct {
	ID          shared.ID
	TenantID    shared.ID
	OwnerID     shared.ID
	OwnerName   string
	GroupID     *shared.ID
	GroupName   string
	Page        string
	Name        string
	Description string
	// Filter is the RFC-048 FilterDocument (JSON), validated on save and
	// again on every run.
	Filter    []byte
	GroupBy   string
	Columns   []string
	Density   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Repository stores saved views. Every method is tenant-bound; reads return
// only views the user may see (their own, or shared with an active group
// they belong to).
type Repository interface {
	Create(ctx context.Context, v *View) error
	// Update changes a view the owner owns; ErrNotFound otherwise.
	Update(ctx context.Context, v *View) error
	// Delete removes a view the owner owns; ErrNotFound otherwise.
	Delete(ctx context.Context, tenantID, id, ownerID shared.ID) error
	GetVisible(ctx context.Context, tenantID, id, userID shared.ID) (*View, error)
	ListVisible(ctx context.Context, tenantID, userID shared.ID, page string) ([]*View, error)
	CountByOwner(ctx context.Context, tenantID, ownerID shared.ID) (int, error)
	CountByGroup(ctx context.Context, tenantID, groupID shared.ID) (int, error)
	// IsActiveGroupMember reports whether the user is a member of an active
	// group of the tenant.
	IsActiveGroupMember(ctx context.Context, tenantID, groupID, userID shared.ID) (bool, error)
	// ActiveGroupInTenant reports whether the group is an active group of
	// the tenant.
	ActiveGroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error)
}
