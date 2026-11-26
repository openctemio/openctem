package datascope

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// ErrScopeUnresolved is a list read by a caller who is not an
// administrator and whose data scope did not resolve (no user and no API
// key): the read is refused rather than run unrestricted.
var ErrScopeUnresolved = fmt.Errorf("%w: data scope did not resolve", shared.ErrForbidden)

// ListCaller is the person or API key reading a list on the list query
// contract (docs/architecture/list-query-contract.md).
type ListCaller struct {
	TenantID string
	UserID   string
	IsAdmin  bool
	APIKey   bool
}

// ListActor resolves the filterspec actor a list is compiled as: the
// caller's tenant and, for a member, their data scope. Administrators are
// not narrowed to scope rows, but private program assets stay hidden from
// those who are neither owners nor members of the program. It fails
// closed: a caller who is not an administrator always gets a resolved
// scope (a user-less API key gets one with no rows; a has_full_data_access
// role holder sees the tenant), and a missing enforcer or a scope that does
// not resolve is an error, never an unrestricted read.
func ListActor(ctx context.Context, e *Enforcer, c ListCaller) (filterspec.Actor, shared.ID, error) {
	tenantID, err := shared.IDFromString(c.TenantID)
	if err != nil {
		return filterspec.Actor{}, tenantID, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	var userID shared.ID
	if c.UserID != "" {
		if userID, err = shared.IDFromString(c.UserID); err != nil {
			return filterspec.Actor{}, tenantID, fmt.Errorf("%w: invalid acting user", shared.ErrValidation)
		}
	}
	var scope *shared.DataScope
	switch {
	case !c.IsAdmin:
		// A member, or a user-less API key (its scope has no rows). A
		// non-administrator with neither a user nor an API key is not an
		// internal call here: it resolves no scope and is refused.
		if e == nil {
			return filterspec.Actor{}, tenantID, errors.New("data scope enforcer not configured")
		}
		var kind Resolution
		scope, kind, err = e.ResolveForKind(ctx, tenantID, Caller{UserID: c.UserID, APIKey: c.APIKey})
		// A nil scope is fine only when the caller sees the whole tenant by
		// right (a has_full_data_access role); nothing resolved is refused.
		if err == nil && kind == ResolutionNone {
			return filterspec.Actor{}, tenantID, ErrScopeUnresolved
		}
	case c.UserID != "" && e != nil:
		scope, err = e.ResolveFor(ctx, tenantID, Caller{UserID: c.UserID, IsAdmin: true,
			IsOwner: e.CallerOf(ctx).IsOwner, APIKey: c.APIKey})
	}
	if err != nil {
		return filterspec.Actor{}, tenantID, fmt.Errorf("resolve data scope: %w", err)
	}
	a, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenantID, UserID: userID, IsAdmin: c.IsAdmin, Scope: scope})
	return a, tenantID, err
}
