// Package datascope enforces the Layer 2 (group) data scope: which assets,
// and so which findings and other asset-bound rows, a member may see and
// change.
//
// The scope rows live in user_accessible_assets. Who is restricted is
// unchanged from the list endpoints that already honored it:
//
//   - administrators (owner/admin) and internal calls with no user are
//     never restricted;
//   - a member with at least one scope row sees only those assets;
//   - a member with no scope row sees what the organization's policy says
//     (tenants.members_without_group_see): everything (fail-open) or
//     nothing (fail-closed).
//
// Every service that reads or writes an asset-bound row by id, or lists
// such rows indirectly, goes through one Enforcer instead of repeating the
// check. Out-of-scope by-id access returns shared.ErrNotFound, never a
// forbidden error, so the response does not confirm the row exists.
package datascope

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Caller is the identity a request acts as.
type Caller struct {
	UserID  string
	IsAdmin bool
	// APIKey marks a request authenticated with an API key. A key never
	// inherits its holder's full-data role: full data through a key needs an
	// explicit full-data key (research doc 15, §5.7), not built yet.
	APIKey bool
}

// CallerFunc reads the acting caller from a request context. It is wired at
// the composition root to the HTTP auth accessors, so the admin decision is
// whatever the auth layer decided for this request. A context with no user
// (background jobs, sensors) yields an empty Caller, which is unrestricted.
type CallerFunc func(ctx context.Context) Caller

// AdminLookup decides whether a user administers a tenant when there is no
// request context to ask (for example a WebSocket subscription).
type AdminLookup func(ctx context.Context, tenantID, userID shared.ID) (bool, error)

// Repository is the storage the enforcer needs.
type Repository interface {
	// HasAnyScopeAssignment reports whether the user has any scope row in the tenant.
	HasAnyScopeAssignment(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	// AssetIDsInScope returns the subset of assetIDs the user has a scope row for.
	AssetIDsInScope(ctx context.Context, tenantID, userID shared.ID, assetIDs []shared.ID) ([]shared.ID, error)
	// FindingAssetID returns the asset of a finding in the tenant, or
	// shared.ErrNotFound.
	FindingAssetID(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error)
	// HasFullDataRole reports whether the user holds, in the tenant, a role
	// with has_full_data_access (the system Owner and Administrator roles,
	// and any custom role such as a Global Reader).
	HasFullDataRole(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	// FindingIDsInScope returns the subset of findingIDs (in the tenant) whose
	// asset the user has a scope row for.
	FindingIDsInScope(ctx context.Context, tenantID, userID shared.ID, findingIDs []shared.ID) ([]shared.ID, error)
	// AssetIDsInTenant returns the subset of assetIDs that are live (not
	// soft-deleted) assets of the tenant.
	AssetIDsInTenant(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]shared.ID, error)
}

// Policy reports whether a tenant runs data scope fail-closed.
type Policy interface {
	RestrictedDataScope(ctx context.Context, tenantID string) bool
}

// Enforcer resolves and enforces the caller's data scope. A nil *Enforcer is
// valid and never restricts, so services that were not wired keep working.
type Enforcer struct {
	repo        Repository
	policy      Policy
	caller      CallerFunc
	adminLookup AdminLookup
	logger      *logger.Logger
}

// New creates an Enforcer. policy may be nil (fail-open everywhere).
func New(repo Repository, policy Policy, caller CallerFunc, log *logger.Logger) *Enforcer {
	if log == nil {
		log = logger.NewNop()
	}
	return &Enforcer{repo: repo, policy: policy, caller: caller, logger: log.With("component", "datascope")}
}

// SetAdminLookup wires the admin decision used when there is no request
// context (ForUser). Without it, ForUser treats every user as a member.
func (e *Enforcer) SetAdminLookup(fn AdminLookup) {
	if e != nil {
		e.adminLookup = fn
	}
}

// Strict reports whether the tenant runs data scope fail-closed.
func (e *Enforcer) Strict(ctx context.Context, tenantID shared.ID) bool {
	return e != nil && e.policy != nil && e.policy.RestrictedDataScope(ctx, tenantID.String())
}

// CallerOf returns the caller of a request context (empty when unwired).
func (e *Enforcer) CallerOf(ctx context.Context) Caller {
	if e == nil || e.caller == nil {
		return Caller{}
	}
	return e.caller(ctx)
}

// Resolve returns the data scope of the request's caller in tenantID, or nil
// when the caller is unrestricted.
func (e *Enforcer) Resolve(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error) {
	return e.ResolveFor(ctx, tenantID, e.CallerOf(ctx))
}

// ResolveFor is Resolve for an explicit caller.
func (e *Enforcer) ResolveFor(ctx context.Context, tenantID shared.ID, c Caller) (*shared.DataScope, error) {
	if e == nil || e.repo == nil || c.IsAdmin || c.UserID == "" {
		return nil, nil
	}
	userID, err := shared.IDFromString(c.UserID)
	if err != nil {
		// An unparseable acting user cannot be matched to any scope row.
		return nil, fmt.Errorf("%w: invalid acting user", shared.ErrNotFound)
	}
	// A role with has_full_data_access is the Layer 2 bypass (owner decision
	// D3): it sees every asset of the tenant whatever its group rows say.
	// Owner and Administrator hold it through their system roles; a lookup
	// error restricts (fail closed).
	if !c.APIKey {
		full, ferr := e.repo.HasFullDataRole(ctx, tenantID, userID)
		if ferr != nil {
			return nil, fmt.Errorf("resolve full data access: %w", ferr)
		}
		if full {
			return nil, nil
		}
	}
	has, err := e.repo.HasAnyScopeAssignment(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if !has && !e.Strict(ctx, tenantID) {
		return nil, nil // fail-open default: no assignment, sees everything
	}
	return &shared.DataScope{TenantID: tenantID, UserID: userID}, nil
}

// FullData reports whether actingUserID holds a has_full_data_access role in
// the tenant (false for an API-key request, an empty user, or no
// repository; an unparseable user is an error). The older list paths use it
// to apply the same bypass as ResolveFor.
func (e *Enforcer) FullData(ctx context.Context, tenantID shared.ID, actingUserID string) (bool, error) {
	if e == nil || e.repo == nil || actingUserID == "" || e.CallerOf(ctx).APIKey {
		return false, nil
	}
	userID, err := shared.IDFromString(actingUserID)
	if err != nil {
		// Refuse rather than fall through: a caller that cannot be matched
		// to a user must not reach any path that skips the scope.
		return false, fmt.Errorf("%w: invalid acting user", shared.ErrNotFound)
	}
	return e.repo.HasFullDataRole(ctx, tenantID, userID)
}

// ResolveActing is Resolve for the older services that are handed the acting
// user and the admin flag instead of reading the request: the same decision
// (admin, full-data role, scope rows, policy), so every path agrees. The
// API-key marker still comes from the request.
func (e *Enforcer) ResolveActing(ctx context.Context, tenantID shared.ID, actingUserID string, isAdmin bool) (*shared.DataScope, error) {
	return e.ResolveFor(ctx, tenantID, Caller{UserID: actingUserID, IsAdmin: isAdmin, APIKey: e.CallerOf(ctx).APIKey})
}

// ForUser resolves the scope of a user outside a request (no auth context),
// using the admin lookup. Fails closed: a lookup error restricts.
func (e *Enforcer) ForUser(ctx context.Context, tenantID, userID shared.ID) (*shared.DataScope, error) {
	if e == nil {
		return nil, nil
	}
	isAdmin := false
	if e.adminLookup != nil {
		admin, err := e.adminLookup(ctx, tenantID, userID)
		if err != nil {
			return nil, fmt.Errorf("resolve admin: %w", err)
		}
		isAdmin = admin
	}
	return e.ResolveFor(ctx, tenantID, Caller{UserID: userID.String(), IsAdmin: isAdmin})
}

// InScope reports whether assetID is inside scope. A nil scope admits all.
func (e *Enforcer) InScope(ctx context.Context, scope *shared.DataScope, assetID shared.ID) (bool, error) {
	if scope == nil {
		return true, nil
	}
	if e == nil || e.repo == nil {
		return false, nil
	}
	ids, err := e.repo.AssetIDsInScope(ctx, scope.TenantID, scope.UserID, []shared.ID{assetID})
	if err != nil {
		return false, err
	}
	return len(ids) == 1, nil
}

// AssertAsset returns shared.ErrNotFound unless the request's caller may see
// the asset. Any error while checking also denies (fail closed).
func (e *Enforcer) AssertAsset(ctx context.Context, tenantID, assetID shared.ID) error {
	scope, err := e.Resolve(ctx, tenantID)
	if err != nil {
		e.logger.Warn("data scope check failed", "error", err)
		return shared.ErrNotFound
	}
	return e.assertIn(ctx, scope, assetID)
}

// AssertAssetRef is the check for an asset id a caller supplies to be
// written onto a row (a finding, a component link, ...). It returns
// shared.ErrNotFound unless the asset is a live asset of the tenant AND the
// request's caller may see it. Unlike AssertAsset it checks the tenant for
// unrestricted callers too, because a foreign or unknown id must never be
// stored, whoever sends it; both cases get the same error, so the answer is
// no existence oracle. Any error while checking also denies (fail closed).
func (e *Enforcer) AssertAssetRef(ctx context.Context, tenantID, assetID shared.ID) error {
	if e == nil || e.repo == nil || assetID.IsZero() {
		return shared.ErrNotFound
	}
	ids, err := e.repo.AssetIDsInTenant(ctx, tenantID, []shared.ID{assetID})
	if err != nil {
		e.logger.Warn("asset tenant check failed", "error", err)
		return shared.ErrNotFound
	}
	if len(ids) != 1 {
		return shared.ErrNotFound
	}
	return e.AssertAsset(ctx, tenantID, assetID)
}

// AssertFinding is AssertAsset for the asset a finding belongs to. A finding
// that does not exist in the tenant is also ErrNotFound.
func (e *Enforcer) AssertFinding(ctx context.Context, tenantID, findingID shared.ID) error {
	scope, err := e.Resolve(ctx, tenantID)
	if err != nil {
		e.logger.Warn("data scope check failed", "error", err)
		return shared.ErrNotFound
	}
	return e.assertFindingIn(ctx, scope, tenantID, findingID)
}

// AssertFindingForUser is AssertFinding for a user outside a request.
func (e *Enforcer) AssertFindingForUser(ctx context.Context, tenantID, userID, findingID shared.ID) error {
	scope, err := e.ForUser(ctx, tenantID, userID)
	if err != nil {
		e.logger.Warn("data scope check failed", "error", err)
		return shared.ErrNotFound
	}
	return e.assertFindingIn(ctx, scope, tenantID, findingID)
}

func (e *Enforcer) assertFindingIn(ctx context.Context, scope *shared.DataScope, tenantID, findingID shared.ID) error {
	if scope == nil {
		return nil
	}
	assetID, err := e.repo.FindingAssetID(ctx, tenantID, findingID)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			e.logger.Warn("data scope finding lookup failed", "error", err)
		}
		return shared.ErrNotFound
	}
	return e.assertIn(ctx, scope, assetID)
}

func (e *Enforcer) assertIn(ctx context.Context, scope *shared.DataScope, assetID shared.ID) error {
	ok, err := e.InScope(ctx, scope, assetID)
	if err != nil {
		e.logger.Warn("data scope asset check failed", "error", err)
		return shared.ErrNotFound
	}
	if !ok {
		return shared.ErrNotFound
	}
	return nil
}

// Filter returns a predicate that admits the asset ids in scope, resolved
// with one query over assetIDs. A nil scope admits everything.
func (e *Enforcer) Filter(ctx context.Context, scope *shared.DataScope, assetIDs []shared.ID) (func(shared.ID) bool, error) {
	if scope == nil {
		return func(shared.ID) bool { return true }, nil
	}
	if e == nil || e.repo == nil || len(assetIDs) == 0 {
		return func(shared.ID) bool { return false }, nil
	}
	in, err := e.repo.AssetIDsInScope(ctx, scope.TenantID, scope.UserID, dedupe(assetIDs))
	if err != nil {
		return nil, fmt.Errorf("filter by data scope: %w", err)
	}
	return setOf(in), nil
}

func setOf(ids []shared.ID) func(shared.ID) bool {
	set := make(map[shared.ID]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return func(id shared.ID) bool {
		_, ok := set[id]
		return ok
	}
}

// FilterFindings returns a predicate that admits the finding ids whose asset
// is in scope, resolved with one query. A nil scope admits everything.
func (e *Enforcer) FilterFindings(ctx context.Context, scope *shared.DataScope, findingIDs []shared.ID) (func(shared.ID) bool, error) {
	if scope == nil {
		return func(shared.ID) bool { return true }, nil
	}
	if e == nil || e.repo == nil || len(findingIDs) == 0 {
		return func(shared.ID) bool { return false }, nil
	}
	in, err := e.repo.FindingIDsInScope(ctx, scope.TenantID, scope.UserID, dedupe(findingIDs))
	if err != nil {
		return nil, fmt.Errorf("filter findings by data scope: %w", err)
	}
	return setOf(in), nil
}

// CanActOnAssets is the one check of "may this actor act on (scan, probe)
// these assets". The actor is the request's caller; without a user in the
// context (a scheduled run) it is fallbackUser, resolved like ForUser; with
// neither it is the system, which is unrestricted. unrestricted reports that
// the actor may act on every asset of the tenant (today an administrator, or
// a member of a fail-open organization with no scope row). Any lookup error
// is returned, and the caller must refuse (fail closed).
func (e *Enforcer) CanActOnAssets(ctx context.Context, tenantID shared.ID, fallbackUser *shared.ID, assetIDs []shared.ID) (canAct func(shared.ID) bool, unrestricted bool, err error) {
	var scope *shared.DataScope
	c := e.CallerOf(ctx)
	switch {
	case c.UserID != "" || c.IsAdmin:
		scope, err = e.ResolveFor(ctx, tenantID, c)
	case fallbackUser != nil && !fallbackUser.IsZero():
		scope, err = e.ForUser(ctx, tenantID, *fallbackUser)
	}
	if err != nil {
		return nil, false, fmt.Errorf("resolve act scope: %w", err)
	}
	if scope == nil {
		return func(shared.ID) bool { return true }, true, nil
	}
	pred, err := e.Filter(ctx, scope, assetIDs)
	if err != nil {
		return nil, false, err
	}
	return pred, false, nil
}

// FilterForCaller is Filter for the request's caller.
func (e *Enforcer) FilterForCaller(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (func(shared.ID) bool, error) {
	scope, err := e.Resolve(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return e.Filter(ctx, scope, assetIDs)
}

func dedupe(ids []shared.ID) []shared.ID {
	seen := make(map[shared.ID]struct{}, len(ids))
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok || id.IsZero() {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
