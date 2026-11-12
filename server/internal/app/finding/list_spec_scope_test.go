package finding

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fullDataScopeRepo answers that every user holds a full-data role and has no
// hidden program assets, so only the caller kind decides the scope.
type fullDataScopeRepo struct{ fullDataCalls int }

func (r *fullDataScopeRepo) AssetIDsInScope(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (r *fullDataScopeRepo) FindingAssetID(context.Context, shared.ID, shared.ID) (shared.ID, error) {
	return shared.ID{}, shared.ErrNotFound
}
func (r *fullDataScopeRepo) HasFullDataRole(context.Context, shared.ID, shared.ID) (bool, error) {
	r.fullDataCalls++
	return true, nil
}
func (r *fullDataScopeRepo) FindingIDsInScope(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (r *fullDataScopeRepo) AssetIDsInTenant(context.Context, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (r *fullDataScopeRepo) HasHiddenAssets(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}
func (r *fullDataScopeRepo) AssetIDsVisible(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (r *fullDataScopeRepo) FindingIDsVisible(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func newFullDataEnforcer(repo *fullDataScopeRepo) *datascope.Enforcer {
	return datascope.New(repo, func(context.Context) datascope.Caller { return datascope.Caller{} }, logger.NewNop())
}

// A user with a full-data role reads every finding in a session, but an API
// key they hold never inherits that bypass: the findings list stays narrowed
// to the user's scope rows, as on every other data-scope path.
func TestFilterActor_APIKeyNeverGetsFullData(t *testing.T) {
	tenant, user := shared.NewID().String(), shared.NewID().String()

	repo := &fullDataScopeRepo{}
	session, err := filterActor(context.Background(), newFullDataEnforcer(repo), FilterCaller{TenantID: tenant, UserID: user})
	if err != nil {
		t.Fatal(err)
	}
	if session.Restricted() {
		t.Fatal("control: a session of a full-data user must not be narrowed")
	}

	repo = &fullDataScopeRepo{}
	key, err := filterActor(context.Background(), newFullDataEnforcer(repo), FilterCaller{TenantID: tenant, UserID: user, APIKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if !key.Restricted() {
		t.Fatal("an API key of a full-data user must be narrowed to the user's scope rows")
	}
	if repo.fullDataCalls != 0 {
		t.Fatalf("the full-data role must not be consulted for an API key, got %d lookups", repo.fullDataCalls)
	}
}

// A caller with no user is not trusted as internal on a request path: it
// compiles with an empty scope (no rows), never an unrestricted one.
func TestFilterActor_EmptyUserFailsClosed(t *testing.T) {
	tenant := shared.NewID().String()
	for name, c := range map[string]FilterCaller{
		"member":  {TenantID: tenant},
		"admin":   {TenantID: tenant, IsAdmin: true},
		"api_key": {TenantID: tenant, APIKey: true},
	} {
		t.Run(name, func(t *testing.T) {
			actor, err := filterActor(context.Background(), newFullDataEnforcer(&fullDataScopeRepo{}), c)
			if err != nil {
				return // refusing is also fail-closed
			}
			if !actor.Restricted() {
				t.Fatal("a caller with no user must not read unrestricted")
			}
		})
	}
}
