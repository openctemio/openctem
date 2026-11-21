// Package savedview is the saved list view (UI style contract D15, research
// 17 R3, docs/rfcs/RFC-048-list-query-contract.md §3.6): a named lens on one
// list page. It stores an RFC-048 FilterDocument and page state, never SQL and
// never results, and it always runs as the person using it.
package savedview

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Limits (the page registry and its limits are in pages.go).
const (
	MaxNameLen        = 120
	MaxDescriptionLen = 500
	MaxColumns        = 50
	MaxPerOwner       = 100
	MaxPerGroup       = 100
	MaxSharedWithOrg  = 100
)

// Errors.
var (
	ErrNotFound = errors.New("saved view not found")
	ErrNotOwner = errors.New("only the owner of a saved view can change it")
	ErrLimit    = errors.New("too many saved views")
	ErrInvalid  = errors.New("invalid saved view")
	// ErrUnknownPage: the page key is not in the registry (pages.go).
	ErrUnknownPage = errors.New("unknown page key")
	// ErrPageForbidden: the caller may not read the list the page key names.
	ErrPageForbidden = errors.New("the list of this page key is not readable by the caller")
	// ErrShareForbidden: sharing with the organization needs
	// findings:views:share.
	ErrShareForbidden = errors.New("sharing a view with the organization needs the findings:views:share permission")
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
	Filter  []byte
	GroupBy string
	Columns []string
	Density string
	// PageParams are the page's own params that are not findings filters
	// (the vulnerabilities list's kev, epss_gte, q, sort), validated by the
	// page on save and again on every run. On a page without a filter
	// registry they are the whole list state (filters, sort, search) as the
	// page's own URL params: stored as text, never read by the server.
	PageParams map[string]string
	// SharedWithOrg: every member of the organization may use the view
	// (set only with findings:views:share); never together with GroupID.
	SharedWithOrg bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
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
	// CountByOwner counts the owner's views in the tenant: all of them, and
	// the ones of one page.
	CountByOwner(ctx context.Context, tenantID, ownerID shared.ID, page string) (total, onPage int, err error)
	CountByGroup(ctx context.Context, tenantID, groupID shared.ID) (int, error)
	CountSharedWithOrg(ctx context.Context, tenantID shared.ID) (int, error)
	// IsActiveGroupMember reports whether the user is a member of an active
	// group of the tenant.
	IsActiveGroupMember(ctx context.Context, tenantID, groupID, userID shared.ID) (bool, error)
	// ActiveGroupInTenant reports whether the group is an active group of
	// the tenant.
	ActiveGroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error)
}
