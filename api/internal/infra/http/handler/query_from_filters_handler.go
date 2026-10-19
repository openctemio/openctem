package handler

// POST /api/v1/query/from-filters: the findings list's filters as query
// text, so a list filter opens in the query editor (one filter, two views;
// docs/architecture/query-language.md).

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"

	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

// QueryFromFiltersRequest is a list's URL query string.
type QueryFromFiltersRequest struct {
	// Entity is "findings".
	Entity string `json:"entity"`
	// Params is the list's query string, e.g. "severity=critical,high&status=new".
	Params string `json:"params"`
}

// QueryFromFiltersResponse is the query text of the filters.
type QueryFromFiltersResponse struct {
	Query string `json:"query"`
	// Ignored are params that are not filters of the entity (they are left
	// out of the query; sort and paging are never filters).
	Ignored []string `json:"ignored"`
}

// FromFilters handles POST /api/v1/query/from-filters
// @Summary      Turn list filters into query text
// @Description  Parses a findings list query string with the list's own filter registry and returns the same filter as query text ("findings where ..."). Nothing is run. Params that are not filters are returned in ignored.
// @Tags         Query
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  QueryFromFiltersRequest  true  "Filters"
// @Success      200  {object}  QueryFromFiltersResponse
// @Failure      400  {object}  apierror.Error
// @Router       /query/from-filters [post]
func (h *QueryHandler) FromFilters(w http.ResponseWriter, r *http.Request) {
	var req QueryFromFiltersRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxQueryBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if req.Entity != querylang.Findings.Name {
		apierror.BadRequest("entity must be findings").WriteJSON(w)
		return
	}
	vals, err := url.ParseQuery(req.Params)
	if err != nil {
		apierror.BadRequest("params is not a query string").WriteJSON(w)
		return
	}
	for _, k := range []string{"sort", "page", "per_page", "cursor", "limit"} {
		vals.Del(k)
	}
	spec, err := filterspec.ParseValues(vals, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownWarn})
	if err != nil {
		filterquery.WriteError(w, err)
		return
	}
	ignored := append([]string{}, spec.UnknownParams...)
	sort.Strings(ignored)
	h.write(w, QueryFromFiltersResponse{Query: querylang.Format(querylang.FromSpec(querylang.Findings, spec)), Ignored: ignored})
}
