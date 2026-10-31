package handler

import (
	"net/http"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// Status counts on the scope lists (include=status_counts): the scope page
// shows a count per tab and per status next to the list it opens, and used
// to read each one with its own per_page=1 request (six per visit). The list
// answers them with its page instead. The counts cover every entry the caller
// may see in the organization, per stored status, whatever the list's other
// filters: the tenant of the authenticated principal and, for targets, the
// private programs the caller may not see left out, as in the list itself.

// ScopeTargetListResponse is GET /scope/targets.
type ScopeTargetListResponse struct {
	ListResponse[ScopeTargetResponse]
	// StatusCounts is present with include=status_counts.
	StatusCounts *map[string]int64 `json:"status_counts,omitempty"`
}

// ScopeExclusionListResponse is GET /scope/exclusions.
type ScopeExclusionListResponse struct {
	ListResponse[ScopeExclusionResponse]
	// StatusCounts is present with include=status_counts.
	StatusCounts *map[string]int64 `json:"status_counts,omitempty"`
}

func wantsStatusCounts(r *http.Request) bool { return wantsInclude(r, "status_counts") }

// wantsInclude reports whether the comma-separated include parameter names part.
func wantsInclude(r *http.Request, part string) bool {
	for _, v := range parseQueryArray(r.URL.Query().Get("include")) {
		if v == part {
			return true
		}
	}
	return false
}

// statusCountsJSON is never nil, so an organization without entries answers {}.
func statusCountsJSON(counts map[scopedom.Status]int64) *map[string]int64 {
	out := make(map[string]int64, len(counts))
	for st, n := range counts {
		out[string(st)] = n
	}
	return &out
}
