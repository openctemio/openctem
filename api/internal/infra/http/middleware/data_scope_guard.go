package middleware

import (
	"context"
	"net/http"
	"path"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DataScopeAsserter is the slice of the data-scope enforcer the guard needs
// (implemented by *datascope.Enforcer). Both methods return an error —
// shared.ErrNotFound — when the request's caller may not see the row.
type DataScopeAsserter interface {
	AssertAsset(ctx context.Context, tenantID, assetID shared.ID) error
	AssertFinding(ctx context.Context, tenantID, findingID shared.ID) error
}

// TaskWorkAsserter is the optional extra of an asserter: the finding check
// for a route of the fix workflow, which admits the owner of a live task
// holding the finding too. viaTask reports that the task relation, not the
// data scope, admitted the caller.
type TaskWorkAsserter interface {
	AssertFindingForFixWork(ctx context.Context, tenantID, findingID shared.ID) (viaTask bool, err error)
}

// CampaignAsserter is the optional extra of an asserter: the pentest
// campaign check for a finding id. It returns shared.ErrNotFound when the
// finding belongs to a pentest campaign the caller may not see. The guard
// runs it on every by-id finding route, so a sub-resource of a finding (AI
// triage, approvals, ticket links, activity, ...) is as closed as the finding.
type CampaignAsserter interface {
	AssertFindingCampaign(ctx context.Context, tenantID, findingID shared.ID) error
}

// RequestMemoInstaller is the optional extra of an asserter: it returns a
// context that memoizes the request's data-scope answers (the guard's check
// and the same checks the services repeat). The memo belongs to one request
// only and is keyed by tenant and caller.
type RequestMemoInstaller interface {
	WithRequestMemo(ctx context.Context) context.Context
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
			if mi, ok := a.(RequestMemoInstaller); ok {
				r = r.WithContext(mi.WithRequestMemo(r.Context()))
			}
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
				if ca, ok := a.(CampaignAsserter); ok {
					if ca.AssertFindingCampaign(r.Context(), tenantID, id) != nil {
						apierror.NotFound("Finding").WriteJSON(w)
						return
					}
				}
				if tw, ok := a.(TaskWorkAsserter); ok && fixWorkRoute(r.Method, r.URL.Path) {
					via, err := tw.AssertFindingForFixWork(r.Context(), tenantID, id)
					if err != nil {
						apierror.NotFound("Finding").WriteJSON(w)
						return
					}
					if via {
						r = r.WithContext(shared.WithTaskOwnerView(r.Context()))
					}
				} else if a.AssertFinding(r.Context(), tenantID, id) != nil {
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

// fixWorkRoute reports whether a request under /api/v1/findings/{id} is a
// read or a step of the fix workflow that the owner of a live task holding
// the finding may make without the finding being in their data scope: any
// read, a comment, a status change (the status path narrows it to the fix
// moves), a manual evidence note, a proof-of-fix check and a retest request.
// Everything else (assign, severity, classify, tags, duplicates,
// correlation, approvals, tickets, delete, ...) keeps the finding's real
// scope.
func fixWorkRoute(method, p string) bool {
	rest, found := strings.CutPrefix(path.Clean("/"+p), "/api/v1/findings/")
	if !found {
		return false
	}
	_, sub, _ := strings.Cut(rest, "/")
	switch method {
	case http.MethodGet, http.MethodHead:
		return true
	case http.MethodPost:
		switch sub {
		case "comments", "evidence", "validate", "retests":
			return true
		}
	case http.MethodPut, http.MethodDelete:
		return strings.HasPrefix(sub, "comments/") && strings.Count(sub, "/") == 1
	case http.MethodPatch:
		return sub == "status"
	}
	return false
}
