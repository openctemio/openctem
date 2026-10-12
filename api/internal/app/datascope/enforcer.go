// Package datascope enforces the Layer 2 (group) data scope: which assets,
// and so which findings and other asset-bound rows, a member may see and
// change.
//
// The scope rows live in user_accessible_assets. Who is restricted:
//
//   - owners and internal calls with no user are never restricted;
//     administrators and holders of a has_full_data_access role see every
//     asset except the program-only assets of private bug-bounty programs
//     they are not a member of (RFC-065 §15.3; DataScope.Unrestricted);
//   - every other member sees only the assets of their scope rows, and a
//     member with no scope row sees nothing (fail closed). There is no
//     per-organization "see everything" mode any more (owner decision D2,
//     research doc 15 L-04; its column was dropped by migration 001483).
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
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ErrInactivePrincipal is returned when the user a job acts for is not an
// active member (disabled or offboarded) or not an active account. Callers
// refuse (fail closed); nothing runs on behalf of a person who left.
var ErrInactivePrincipal = fmt.Errorf("%w: the acting member is not active", shared.ErrForbidden)

// Caller is the identity a request acts as.
type Caller struct {
	UserID  string
	IsAdmin bool
	// IsOwner: the caller owns the tenant. Owners see private program
	// assets without being program members.
	IsOwner bool
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

// OwnerLookup decides whether a user owns a tenant when there is no request
// context to ask.
type OwnerLookup func(ctx context.Context, tenantID, userID shared.ID) (bool, error)

// Repository is the storage the enforcer needs.
type Repository interface {
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
	// HasHiddenAssets reports whether any asset of the tenant is hidden
	// from the user (a program-only asset of private programs the user is
	// not a member of).
	HasHiddenAssets(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	// AssetIDsVisible returns the subset of assetIDs that are not hidden
	// from the user.
	AssetIDsVisible(ctx context.Context, tenantID, userID shared.ID, assetIDs []shared.ID) ([]shared.ID, error)
	// FindingIDsVisible returns the subset of findingIDs (in the tenant)
	// whose asset is not hidden from the user.
	FindingIDsVisible(ctx context.Context, tenantID, userID shared.ID, findingIDs []shared.ID) ([]shared.ID, error)
}

// Enforcer resolves and enforces the caller's data scope. A nil *Enforcer is
// valid and never restricts, so services that were not wired keep working.
type Enforcer struct {
	repo        Repository
	caller      CallerFunc
	adminLookup AdminLookup
	ownerLookup OwnerLookup
	logger      *logger.Logger
}

// New creates an Enforcer.
func New(repo Repository, caller CallerFunc, log *logger.Logger) *Enforcer {
	if log == nil {
		log = logger.NewNop()
	}
	return &Enforcer{repo: repo, caller: caller, logger: log.With("component", "datascope")}
}

// SetAdminLookup wires the admin decision used when there is no request
// context (ForUser). Without it, ForUser treats every user as a member.
func (e *Enforcer) SetAdminLookup(fn AdminLookup) {
	if e != nil {
		e.adminLookup = fn
	}
}

// SetOwnerLookup wires the owner decision used when there is no request
// context (ForUser). Without it, ForUser treats no user as an owner, so
// private program assets stay hidden (fail closed).
func (e *Enforcer) SetOwnerLookup(fn OwnerLookup) {
	if e != nil {
		e.ownerLookup = fn
	}
}

// CallerOf returns the caller of a request context (empty when unwired).
func (e *Enforcer) CallerOf(ctx context.Context) Caller {
	if e == nil || e.caller == nil {
		return Caller{}
	}
	return e.caller(ctx)
}

// CallerUserID is the user a request acts as ("" for none).
func (e *Enforcer) CallerUserID(ctx context.Context) string { return e.CallerOf(ctx).UserID }

// Resolve returns the data scope of the request's caller in tenantID, or nil
// when the caller is unrestricted.
func (e *Enforcer) Resolve(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error) {
	return e.ResolveFor(ctx, tenantID, e.CallerOf(ctx))
}

// ResolveFor is Resolve for an explicit caller.
func (e *Enforcer) ResolveFor(ctx context.Context, tenantID shared.ID, c Caller) (*shared.DataScope, error) {
	if e == nil || e.repo == nil || c.UserID == "" || c.IsOwner {
		return nil, nil
	}
	userID, err := shared.IDFromString(c.UserID)
	if err != nil {
		// An unparseable acting user cannot be matched to any scope row.
		return nil, fmt.Errorf("%w: invalid acting user", shared.ErrNotFound)
	}
	// An administrator, and a role with has_full_data_access (the Layer 2
	// bypass, owner decision D3), see every asset of the tenant whatever
	// their group rows say, except the private program assets of programs
	// they are not a member of. A lookup error restricts (fail closed).
	full := c.IsAdmin
	if !full && !c.APIKey {
		f, ferr := e.repo.HasFullDataRole(ctx, tenantID, userID)
		if ferr != nil {
			return nil, fmt.Errorf("resolve full data access: %w", ferr)
		}
		full = f
	}
	if full {
		hidden, herr := e.repo.HasHiddenAssets(ctx, tenantID, userID)
		if herr != nil {
			return nil, fmt.Errorf("resolve private program assets: %w", herr)
		}
		if hidden {
			return &shared.DataScope{TenantID: tenantID, UserID: userID, Unrestricted: true}, nil
		}
		return nil, nil
	}
	// Every other member is restricted to their scope rows; no row means
	// nothing (fail closed, in every organization).
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
// (admin, full-data role, scope rows), so every path agrees. The
// API-key marker still comes from the request.
func (e *Enforcer) ResolveActing(ctx context.Context, tenantID shared.ID, actingUserID string, isAdmin bool) (*shared.DataScope, error) {
	c := e.CallerOf(ctx)
	// Owner visibility (private program assets) is the request caller's
	// only: an acting user who is not the caller is never treated as owner.
	return e.ResolveFor(ctx, tenantID, Caller{UserID: actingUserID, IsAdmin: isAdmin,
		IsOwner: c.IsOwner && c.UserID == actingUserID, APIKey: c.APIKey})
}

// ForUser resolves the scope of a user outside a request (no auth context),
// using the admin lookup. Fails closed: a lookup error restricts.
func (e *Enforcer) ForUser(ctx context.Context, tenantID, userID shared.ID) (*shared.DataScope, error) {
	if e == nil {
		return nil, nil
	}
	isAdmin, isOwner := false, false
	if e.adminLookup != nil {
		admin, err := e.adminLookup(ctx, tenantID, userID)
		if err != nil {
			return nil, fmt.Errorf("resolve admin: %w", err)
		}
		isAdmin = admin
	}
	if isAdmin && e.ownerLookup != nil {
		owner, err := e.ownerLookup(ctx, tenantID, userID)
		if err != nil {
			return nil, fmt.Errorf("resolve owner: %w", err)
		}
		isOwner = owner
	}
	return e.ResolveFor(ctx, tenantID, Caller{UserID: userID.String(), IsAdmin: isAdmin, IsOwner: isOwner})
}

// InScope reports whether assetID is inside scope. A nil scope admits all.
func (e *Enforcer) InScope(ctx context.Context, scope *shared.DataScope, assetID shared.ID) (bool, error) {
	if scope == nil {
		return true, nil
	}
	if e == nil || e.repo == nil {
		return false, nil
	}
	ids, err := e.assetIDsIn(ctx, scope, []shared.ID{assetID})
	if err != nil {
		return false, err
	}
	return len(ids) == 1, nil
}

// assetIDsIn is the subset of assetIDs inside a non-nil scope: not hidden
// for an Unrestricted scope, in the scope rows (and not hidden) otherwise.
func (e *Enforcer) assetIDsIn(ctx context.Context, scope *shared.DataScope, assetIDs []shared.ID) ([]shared.ID, error) {
	if scope.Unrestricted {
		return e.repo.AssetIDsVisible(ctx, scope.TenantID, scope.UserID, assetIDs)
	}
	return e.repo.AssetIDsInScope(ctx, scope.TenantID, scope.UserID, assetIDs)
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

// FilterAssetRefs is AssertAssetRef for a batch of asset ids, resolved with
// at most three queries: the predicate admits an id only when it is a live
// asset of the tenant AND the request's caller may see it. Use it where a
// bulk write drops refused items instead of failing the whole request. An
// unwired enforcer admits nothing (fail closed); a lookup error is returned
// and the caller must refuse.
func (e *Enforcer) FilterAssetRefs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (func(shared.ID) bool, error) {
	if e == nil || e.repo == nil {
		return func(shared.ID) bool { return false }, nil
	}
	ids := dedupe(assetIDs) // also drops zero ids
	if len(ids) == 0 {
		return func(shared.ID) bool { return false }, nil
	}
	inTenant, err := e.repo.AssetIDsInTenant(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("asset tenant check: %w", err)
	}
	if len(inTenant) == 0 {
		return func(shared.ID) bool { return false }, nil
	}
	inScope, err := e.FilterForCaller(ctx, tenantID, inTenant)
	if err != nil {
		return nil, err
	}
	tenantSet := setOf(inTenant)
	return func(id shared.ID) bool { return tenantSet(id) && inScope(id) }, nil
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
	in, err := e.assetIDsIn(ctx, scope, dedupe(assetIDs))
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
	var in []shared.ID
	var err error
	if scope.Unrestricted {
		in, err = e.repo.FindingIDsVisible(ctx, scope.TenantID, scope.UserID, dedupe(findingIDs))
	} else {
		in, err = e.repo.FindingIDsInScope(ctx, scope.TenantID, scope.UserID, dedupe(findingIDs))
	}
	if err != nil {
		return nil, fmt.Errorf("filter findings by data scope: %w", err)
	}
	return setOf(in), nil
}

// CanActOnAssets is the one check of "may this actor act on (scan, probe)
// these assets". The actor is the request's caller; without a user in the
// context (a scheduled run) it is fallbackUser, resolved like ForUser; with
// neither it is the system, which is unrestricted. unrestricted reports that
// the actor may act on every asset of the tenant (an administrator, a
// full-data role, or the system). Any lookup error
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
	if !scope.Restricted() {
		// Hiding private program assets is about what one sees, not what
		// an administrator may act on.
		return func(shared.ID) bool { return true }, true, nil
	}
	pred, err := e.Filter(ctx, scope, assetIDs)
	if err != nil {
		return nil, false, err
	}
	return pred, false, nil
}

// Delegable returns a predicate admitting the assets the request's caller
// may hand to others (assign to a group, grant, add a member to a group that
// holds them). Owner decision D13 (research doc 15 L-09): a caller can only
// delegate scope they hold themselves. An unrestricted caller (admin,
// full-data role, internal call) may delegate any asset of the tenant; that is the second
// return value.
func (e *Enforcer) Delegable(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (func(shared.ID) bool, bool, error) {
	scope, err := e.Resolve(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
	if !scope.Restricted() {
		return func(shared.ID) bool { return true }, true, nil
	}
	admit, err := e.Filter(ctx, scope, assetIDs)
	return admit, false, err
}

// FullDataCaller reports whether the request's caller has full data access:
// an admin, a holder of a has_full_data_access role (not through an API key),
// or an internal call with no user. Changes that widen the caller's own
// scope (adding themselves to a group) need it.
func (e *Enforcer) FullDataCaller(ctx context.Context, tenantID shared.ID) (bool, error) {
	c := e.CallerOf(ctx)
	if c.IsAdmin || c.UserID == "" {
		return true, nil
	}
	return e.FullData(ctx, tenantID, c.UserID)
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

// MembershipReader reads a user's membership in a tenant (tenant.Repository).
type MembershipReader interface {
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
}

// MembershipAdminLookup is the AdminLookup production wires: the team role
// (GetMembership reads v_user_effective_role) is owner or admin, the way the
// access token decides it. A membership that is not ACTIVE (disabled or
// offboarded) acts as nobody: ErrInactivePrincipal makes ForUser, and every
// background job acting on the member's behalf (a scheduled scan, a report),
// refuse instead of running with a bypass the person no longer holds.
func MembershipAdminLookup(members MembershipReader) AdminLookup {
	return func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := members.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		if !m.IsActive() {
			return false, ErrInactivePrincipal
		}
		return m.IsOwner() || m.IsAdmin(), nil
	}
}

// MembershipOwnerLookup is the OwnerLookup production wires: the team role
// is owner and the membership is active.
func MembershipOwnerLookup(members MembershipReader) OwnerLookup {
	return func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := members.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		return m.IsActive() && m.IsOwner(), nil
	}
}
