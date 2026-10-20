package attack

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeScopeRepo is a data-scope repository for a restricted member who holds
// scope rows for the assets in inScope. HasFullDataRole is false, so the
// member is restricted.
type fakeScopeRepo struct {
	datascope.Repository
	inScope map[string]bool
}

func (f fakeScopeRepo) HasFullDataRole(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}

func (f fakeScopeRepo) AssetIDsInScope(_ context.Context, _, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	var out []shared.ID
	for _, id := range ids {
		if f.inScope[id.String()] {
			out = append(out, id)
		}
	}
	return out, nil
}

// restrictedEnforcer resolves every request to a restricted member whose scope
// rows cover inScope.
func restrictedEnforcer(inScope ...shared.ID) *datascope.Enforcer {
	set := map[string]bool{}
	for _, id := range inScope {
		set[id.String()] = true
	}
	return datascope.New(fakeScopeRepo{inScope: set}, func(context.Context) datascope.Caller {
		return datascope.Caller{UserID: shared.NewID().String()}
	}, logger.NewNop())
}

// ownerEnforcer resolves every request to an organization owner (unrestricted).
func ownerEnforcer() *datascope.Enforcer {
	return datascope.New(fakeScopeRepo{}, func(context.Context) datascope.Caller {
		return datascope.Caller{UserID: shared.NewID().String(), IsOwner: true}
	}, logger.NewNop())
}
