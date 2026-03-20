package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// FindingLifecycleHandler handles closed-loop finding lifecycle operations.
type FindingLifecycleHandler struct {
	service *app.FindingLifecycleService
	logger  *logger.Logger
}

// NewFindingLifecycleHandler creates a new FindingLifecycleHandler.
func NewFindingLifecycleHandler(svc *app.FindingLifecycleService, log *logger.Logger) *FindingLifecycleHandler {
	return &FindingLifecycleHandler{service: svc, logger: log}
}

// --- Group View ---

// ListFindingGroups handles GET /api/v1/findings/groups
func (h *FindingLifecycleHandler) ListFindingGroups(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	groupBy := r.URL.Query().Get("group_by")
	if groupBy == "" {
		groupBy = "cve_id"
	}

	filter := h.buildFilter(r)
	page := h.buildPagination(r, 50) // default 50 per page

	result, err := h.service.ListFindingGroups(r.Context(), tenantID, groupBy, filter, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"data":       result.Data,
		"pagination": map[string]any{
			"total":    result.Total,
			"page":     result.Page,
			"per_page": result.PerPage,
		},
	})
}

// --- Related CVEs ---

// GetRelatedCVEs handles GET /api/v1/findings/related-cves/{cveId}
func (h *FindingLifecycleHandler) GetRelatedCVEs(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	cveID := chi.URLParam(r, "cveId")
	if cveID == "" {
		apierror.BadRequest("cveId is required").WriteJSON(w)
		return
	}

	filter := h.buildFilter(r)
	result, err := h.service.GetRelatedCVEs(r.Context(), tenantID, cveID, filter)
	if err != nil {
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"source_cve":   cveID,
		"related_cves": result,
	})
}

// --- Fix Applied ---

// FixAppliedRequest is the request body for POST /api/v1/findings/actions/fix-applied
type FixAppliedRequest struct {
	Filter             FindingFilterRequest `json:"filter"`
	IncludeRelatedCVEs bool                 `json:"include_related_cves"`
	Note               string               `json:"note"`
	Reference          string               `json:"reference"`
}

// FindingFilterRequest is the filter in request body.
type FindingFilterRequest struct {
	CVEIDs    []string `json:"cve_ids"`
	AssetTags []string `json:"asset_tags"`
}

// FixApplied handles POST /api/v1/findings/actions/fix-applied
func (h *FindingLifecycleHandler) FixApplied(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetLocalUserID(r.Context())

	var req FixAppliedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	filter := vulnerability.NewFindingFilter()
	if len(req.Filter.CVEIDs) > 0 {
		filter = filter.WithCVEIDs(req.Filter.CVEIDs)
	}
	if len(req.Filter.AssetTags) > 0 {
		filter = filter.WithAssetTags(req.Filter.AssetTags)
	}

	input := app.BulkFixAppliedInput{
		Filter:             filter,
		IncludeRelatedCVEs: req.IncludeRelatedCVEs,
		Note:               req.Note,
		Reference:          req.Reference,
	}

	result, err := h.service.BulkFixApplied(r.Context(), tenantID, userID.String(), input)
	if err != nil {
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// --- Verify (by IDs or by filter) ---

// VerifyRequest supports both finding_ids and filter. At least one must be provided.
type VerifyRequest struct {
	FindingIDs []string             `json:"finding_ids"` // verify specific findings
	Filter     *FindingFilterRequest `json:"filter"`      // verify all matching filter
	Note       string               `json:"note"`
}

// Verify handles POST /api/v1/findings/actions/verify
func (h *FindingLifecycleHandler) Verify(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetLocalUserID(r.Context())

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// By filter (Pending Review tab uses this)
	if req.Filter != nil && (len(req.Filter.CVEIDs) > 0 || len(req.Filter.AssetTags) > 0) {
		filter := vulnerability.NewFindingFilter()
		if len(req.Filter.CVEIDs) > 0 {
			filter = filter.WithCVEIDs(req.Filter.CVEIDs)
		}
		if len(req.Filter.AssetTags) > 0 {
			filter = filter.WithAssetTags(req.Filter.AssetTags)
		}
		count, err := h.service.BulkVerifyByFilter(r.Context(), tenantID, userID.String(), app.VerifyByFilterInput{
			Filter: filter, Note: req.Note,
		})
		if err != nil {
			h.handleError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"updated": count})
		return
	}

	// By IDs
	if len(req.FindingIDs) == 0 {
		apierror.BadRequest("finding_ids or filter is required").WriteJSON(w)
		return
	}

	result, err := h.service.BulkVerify(r.Context(), tenantID, userID.String(), req.FindingIDs, req.Note)
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// --- Reject Fix (by IDs or by filter) ---

// RejectFixRequest supports both finding_ids and filter.
type RejectFixRequest struct {
	FindingIDs []string             `json:"finding_ids"`
	Filter     *FindingFilterRequest `json:"filter"`
	Reason     string               `json:"reason"`
}

// RejectFix handles POST /api/v1/findings/actions/reject-fix
func (h *FindingLifecycleHandler) RejectFix(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetLocalUserID(r.Context())

	var req RejectFixRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// By filter
	if req.Filter != nil && (len(req.Filter.CVEIDs) > 0 || len(req.Filter.AssetTags) > 0) {
		filter := vulnerability.NewFindingFilter()
		if len(req.Filter.CVEIDs) > 0 {
			filter = filter.WithCVEIDs(req.Filter.CVEIDs)
		}
		if len(req.Filter.AssetTags) > 0 {
			filter = filter.WithAssetTags(req.Filter.AssetTags)
		}
		count, err := h.service.BulkRejectByFilter(r.Context(), tenantID, userID.String(), app.RejectByFilterInput{
			Filter: filter, Reason: req.Reason,
		})
		if err != nil {
			h.handleError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"updated": count})
		return
	}

	// By IDs
	if len(req.FindingIDs) == 0 {
		apierror.BadRequest("finding_ids or filter is required").WriteJSON(w)
		return
	}

	result, err := h.service.BulkRejectFix(r.Context(), tenantID, userID.String(), req.FindingIDs, req.Reason)
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// --- Auto-Assign ---

// AssignToOwnersRequest is the request body for POST /api/v1/findings/actions/assign-to-owners
type AssignToOwnersRequest struct {
	Filter FindingFilterRequest `json:"filter"`
}

// AssignToOwners handles POST /api/v1/findings/actions/assign-to-owners
func (h *FindingLifecycleHandler) AssignToOwners(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetLocalUserID(r.Context())

	var req AssignToOwnersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	filter := vulnerability.NewFindingFilter()
	if len(req.Filter.CVEIDs) > 0 {
		filter = filter.WithCVEIDs(req.Filter.CVEIDs)
	}
	if len(req.Filter.AssetTags) > 0 {
		filter = filter.WithAssetTags(req.Filter.AssetTags)
	}

	result, err := h.service.AutoAssignToOwners(r.Context(), tenantID, userID.String(), filter)
	if err != nil {
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// --- Helpers ---

func (h *FindingLifecycleHandler) buildFilter(r *http.Request) vulnerability.FindingFilter {
	filter := vulnerability.NewFindingFilter()
	q := r.URL.Query()

	if sevs := q.Get("severities"); sevs != "" {
		for _, s := range splitCSV(sevs) {
			sev, err := vulnerability.ParseSeverity(s)
			if err == nil {
				filter.Severities = append(filter.Severities, sev)
			}
		}
	}

	if stats := q.Get("statuses"); stats != "" {
		for _, s := range splitCSV(stats) {
			st, err := vulnerability.ParseFindingStatus(s)
			if err == nil {
				filter.Statuses = append(filter.Statuses, st)
			}
		}
	}

	if sources := q.Get("sources"); sources != "" {
		for _, s := range splitCSV(sources) {
			src, err := vulnerability.ParseFindingSource(s)
			if err == nil {
				filter.Sources = append(filter.Sources, src)
			}
		}
	}

	if cves := q.Get("cve_ids"); cves != "" {
		filter.CVEIDs = splitCSV(cves)
	}

	if tags := q.Get("asset_tags"); tags != "" {
		filter.AssetTags = splitCSV(tags)
	}

	return filter
}

func (h *FindingLifecycleHandler) buildPagination(r *http.Request, defaultPerPage int) pagination.Pagination {
	q := r.URL.Query()
	perPage := defaultPerPage
	page := 1

	if pp := q.Get("per_page"); pp != "" {
		if v, err := strconv.Atoi(pp); err == nil && v > 0 && v <= 100 {
			perPage = v
		}
	}
	if p := q.Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}

	return pagination.New(perPage, (page-1)*perPage)
}

func (h *FindingLifecycleHandler) handleError(w http.ResponseWriter, err error) {
	if errors.Is(err, shared.ErrValidation) {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	h.logger.Error("finding lifecycle error", "error", err)
	apierror.InternalServerError("Internal server error").WriteJSON(w)
}

func (h *FindingLifecycleHandler) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func splitCSV(s string) []string {
	parts := make([]string, 0)
	for _, p := range splitByComma(s) {
		p = trimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitByComma(s string) []string {
	result := make([]string, 0)
	start := 0
	for i := range len(s) {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && s[i] == ' ' {
		i++
	}
	for j > i && s[j-1] == ' ' {
		j--
	}
	return s[i:j]
}
