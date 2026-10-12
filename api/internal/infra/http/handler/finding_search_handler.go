package handler

// POST /findings/search and GET /meta/filters/findings: the FilterDocument
// encoding of the findings list query contract
// (docs/rfcs/RFC-048-list-query-contract.md). The document compiles through
// the same registry and the same caller-bound compiler as GET /findings.

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// FindingSearchRequest documents the FilterDocument body (RFC-048 §3.6). The
// server parses the raw body with filterspec.ParseDocument; this type exists
// for the OpenAPI spec.
type FindingSearchRequest struct {
	// V is the document version (1).
	V int `json:"v,omitempty" example:"1"`
	// Filter is a node ({"all":[...]}, {"any":[...]}, {"not":{...}} or a
	// {"field","op","value"} leaf) or the flat-name shorthand
	// ({"severity":["critical"],"epss_score_gte":0.1}).
	Filter map[string]any `json:"filter,omitempty"`
	// Q is free text over title, description and file path.
	Q string `json:"q,omitempty"`
	// Sort keys, "-" for descending.
	Sort []string `json:"sort,omitempty"`
	// Page selects the page: {"page": 1, "per_page": 50}.
	Page *FindingSearchPage `json:"page,omitempty"`
}

// FindingSearchPage is the page block of a FindingSearchRequest.
type FindingSearchPage struct {
	Page    int `json:"page,omitempty"`
	PerPage int `json:"per_page,omitempty"`
}

// SearchFindings handles POST /api/v1/findings/search
// @Summary      Search findings with a filter document
// @Description  Lists findings selected by a FilterDocument (RFC-048): all/any/not groups with field/op/value
// @Description  leaves, for OR, nesting and id lists of up to 500. Same fields, permission, scope and
// @Description  response as GET /findings. Limits: 50 leaves, depth 3, 32 KB body. A bad document is 400
// @Description  INVALID_FILTER with the JSON path of each problem. Read-only.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  FindingSearchRequest  true  "Filter document"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}  "INVALID_FILTER with details[].path"
// @Failure      401  {object}  map[string]string
// @Router       /findings/search [post]
func (h *VulnerabilityHandler) SearchFindings(w http.ResponseWriter, r *http.Request) {
	route := h.findingsListRoute()
	route.Name = "POST /findings/search"
	spec, ok := route.ParseBody(w, r)
	if !ok {
		return
	}
	h.writeFindingList(w, r, spec)
}

// FindingFilterMeta handles GET /api/v1/meta/filters/findings
// @Summary      Findings filter contract
// @Description  The machine-readable filter contract of the findings list (RFC-048): fields, types, operators,
// @Description  flat param names, enums, sortability, old param aliases and limits, plus the FilterDocument
// @Description  JSON Schema. Fields the caller may not use are left out.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]interface{}
// @Router       /meta/filters/findings [get]
func (h *VulnerabilityHandler) FindingFilterMeta(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	desc := vulnerability.FindingFields.Describe(func(p string) bool { return middleware.HasPermission(ctx, p) })
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"contract":        desc,
		"document_schema": json.RawMessage(filterspec.DocumentSchema),
	})
}

// writeFindingList runs a decoded filter as the caller and writes the list
// response (shared by GET /findings and POST /findings/search).
func (h *VulnerabilityHandler) writeFindingList(w http.ResponseWriter, r *http.Request, spec *filterspec.Spec) {
	result, err := h.service.ListFindingsBySpec(r.Context(), filterCaller(r), spec)
	if err != nil {
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
			return
		}
		h.handleServiceError(w, err, "Finding")
		return
	}

	data := make([]FindingResponse, len(result.Data))
	for i, f := range result.Data {
		data[i] = toFindingResponse(f)
	}
	// Show the asset name instead of an opaque UUID.
	h.enrichFindingsWithAssetInfo(r.Context(), middleware.MustGetTenantID(r.Context()), data)

	response := ListResponse[FindingResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}
