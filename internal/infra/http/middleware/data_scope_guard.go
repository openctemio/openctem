package middleware

import (
	"context"
	"net/http"
	"path"
	"strings"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
)

// DataScopeAsserter is the slice of the data-scope enforcer the guard needs
// (implemented by *datascope.Enforcer). Both methods return an error —
// shared.ErrNotFound — when the request's caller may not see the row.
type DataScopeAsserter interface {
	AssertAsset(ctx context.Context, tenantID, assetID shared.ID) error
	AssertFinding(ctx context.Context, tenantID, findingID shared.ID) error
}

// dataScopeKind is the kind of object a guarded path names.
type dataScopeKind int

const (
	dataScopeAsset dataScopeKind = iota + 1
	dataScopeFinding
)

// dataScopePrefixes maps each guarded path prefix to the kind of id that
// follows it. Every route under "<prefix><uuid>" — the object itself and all
// of its sub-resources (comments, activities, owners, relationships,
// evidence, approvals, ...) — is checked, including routes added later.
// Non-UUID segments (stats, bulk, actions, import, dedup, ...) are not ids
// and pass through to their own handlers.
//
//nolint:gochecknoglobals // static routing table
var dataScopePrefixes = []struct {
	prefix string
	kind   dataScopeKind
}{
	{"/api/v1/assets/", dataScopeAsset},
	{"/api/v1/findings/", dataScopeFinding},
	{"/api/v1/compliance/findings/", dataScopeFinding},
	{"/api/v1/verification-checklists/", dataScopeFinding},
}

// DataScopeGuard enforces the Layer 2 data scope on every by-id asset and
// finding route. For a restricted member, a request that names an asset or
// finding outside their scope gets 404 — the same answer GET of a missing
// row gives, so the response does not reveal that the row exists. Reads and
// writes are treated alike.
//
// It must run after authentication and RequireTenant. Administrators,
// unrestricted members and requests that name no guarded id pass through;
// the scope decision itself (who is restricted) lives in the enforcer.
func DataScopeGuard(a DataScopeAsserter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			kind, id, ok := dataScopeTarget(r.URL.Path)
			if !ok || a == nil {
				next.ServeHTTP(w, r)
				return
			}
			tenantID, err := shared.IDFromString(GetTenantID(r.Context()))
			if err != nil {
				// No tenant: RequireTenant has already refused the request on
				// tenant chains; never guess one here.
				next.ServeHTTP(w, r)
				return
			}
			switch kind {
			case dataScopeAsset:
				if a.AssertAsset(r.Context(), tenantID, id) != nil {
					apierror.NotFound("Asset").WriteJSON(w)
					return
				}
			case dataScopeFinding:
				if a.AssertFinding(r.Context(), tenantID, id) != nil {
					apierror.NotFound("Finding").WriteJSON(w)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// dataScopeTarget extracts the guarded object id from a request path. The
// path is cleaned the same way the router cleans it before matching, so
// "//" or "./" variants cannot slip past.
func dataScopeTarget(p string) (dataScopeKind, shared.ID, bool) {
	p = path.Clean("/" + p)
	for _, g := range dataScopePrefixes {
		rest, found := strings.CutPrefix(p, g.prefix)
		if !found {
			continue
		}
		seg, _, _ := strings.Cut(rest, "/")
		id, err := shared.IDFromString(seg)
		if err != nil {
			// Not an id segment (e.g. /findings/stats): not a by-id route.
			// A longer prefix may still match (compliance/findings).
			continue
		}
		return g.kind, id, true
	}
	return 0, shared.ID{}, false
}
