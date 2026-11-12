package datascope

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

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
// those who are neither owners nor members of the program. A nil enforcer
// refuses every member read (fail closed).
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
	case !c.IsAdmin && c.UserID != "":
		if e == nil {
			return filterspec.Actor{}, tenantID, errors.New("data scope enforcer not configured")
		}
		scope, err = e.ResolveFor(ctx, tenantID, Caller{UserID: c.UserID, APIKey: c.APIKey})
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
