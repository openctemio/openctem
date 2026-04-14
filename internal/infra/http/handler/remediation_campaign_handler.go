package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// RemediationCampaignHandler handles remediation campaign endpoints.
type RemediationCampaignHandler struct {
	service *app.RemediationCampaignService
	logger  *logger.Logger
}

// NewRemediationCampaignHandler creates a new handler.
func NewRemediationCampaignHandler(svc *app.RemediationCampaignService, log *logger.Logger) *RemediationCampaignHandler {
	return &RemediationCampaignHandler{service: svc, logger: log}
}

// List lists remediation campaigns.
func (h *RemediationCampaignHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage < 1 {
		perPage = 20
	} else if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(max(parseQueryInt(r.URL.Query().Get("page"), 1), 1), perPage)

	filter := remediation.CampaignFilter{}
	if s := r.URL.Query().Get("status"); s != "" {
		st := remediation.CampaignStatus(s)
		filter.Status = &st
	}
	if p := r.URL.Query().Get("priority"); p != "" {
		pr := remediation.CampaignPriority(p)
		filter.Priority = &pr
	}
	if q := r.URL.Query().Get("search"); q != "" {
		filter.Search = &q
	}

	result, err := h.service.ListCampaigns(r.Context(), tenantID, filter, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	resp := make([]RemediationCampaignResponse, 0, len(result.Data))
	for _, c := range result.Data {
		resp = append(resp, toRemediationCampaignResp(c))
	}
	writeJSON(w, http.StatusOK, pagination.NewResult(resp, result.Total, page))
}

// Create creates a new campaign.
func (h *RemediationCampaignHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateRemCampaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	campaign, err := h.service.CreateCampaign(r.Context(), app.CreateRemediationCampaignInput{
		TenantID:      tenantID,
		Name:          req.Name,
		Description:   req.Description,
		Priority:      req.Priority,
		FindingFilter: req.FindingFilter,
		AssignedTo:    req.AssignedTo,
		Tags:          req.Tags,
		ActorID:       userID,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, toRemediationCampaignResp(campaign))
}

// Get retrieves a campaign.
func (h *RemediationCampaignHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	campaign, err := h.service.GetCampaign(r.Context(), tenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRemediationCampaignResp(campaign))
}

// UpdateStatus transitions campaign status.
func (h *RemediationCampaignHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	campaign, err := h.service.UpdateCampaignStatus(r.Context(), tenantID, id, req.Status)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRemediationCampaignResp(campaign))
}

// Update updates campaign fields (name, description, priority, tags, due_date).
func (h *RemediationCampaignHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req UpdateRemCampaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	campaign, err := h.service.UpdateCampaign(r.Context(), tenantID, id, app.UpdateRemediationCampaignInput{
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Tags:        req.Tags,
		DueDate:     req.DueDate,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRemediationCampaignResp(campaign))
}

// Delete deletes a campaign.
func (h *RemediationCampaignHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	if err := h.service.DeleteCampaign(r.Context(), tenantID, id); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RemediationCampaignHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("campaign not found").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("remediation campaign error", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}

// Request/Response types

type CreateRemCampaignRequest struct {
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Priority      string         `json:"priority"`
	FindingFilter map[string]any `json:"finding_filter"`
	AssignedTo    string         `json:"assigned_to"`
	Tags          []string       `json:"tags"`
}

type UpdateRemCampaignRequest struct {
	Name        *string    `json:"name,omitempty"`
	Description *string    `json:"description,omitempty"`
	Priority    *string    `json:"priority,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
}

type RemediationCampaignResponse struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Status        string         `json:"status"`
	Priority      string         `json:"priority"`
	FindingFilter map[string]any `json:"finding_filter,omitempty"`
	FindingCount  int            `json:"finding_count"`
	ResolvedCount int            `json:"resolved_count"`
	Progress      float64        `json:"progress"`
	RiskBefore    *float64       `json:"risk_before,omitempty"`
	RiskAfter     *float64       `json:"risk_after,omitempty"`
	RiskReduction *float64       `json:"risk_reduction,omitempty"`
	IsOverdue     bool           `json:"is_overdue"`
	StartDate     *time.Time     `json:"start_date,omitempty"`
	DueDate       *time.Time     `json:"due_date,omitempty"`
	CompletedAt   *time.Time     `json:"completed_at,omitempty"`
	Tags          []string       `json:"tags"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

func toRemediationCampaignResp(c *remediation.Campaign) RemediationCampaignResponse {
	return RemediationCampaignResponse{
		ID:            c.ID().String(),
		Name:          c.Name(),
		Description:   c.Description(),
		Status:        string(c.Status()),
		Priority:      string(c.Priority()),
		FindingFilter: c.FindingFilter(),
		FindingCount:  c.FindingCount(),
		ResolvedCount: c.ResolvedCount(),
		Progress:      c.Progress(),
		RiskBefore:    c.RiskBefore(),
		RiskAfter:     c.RiskAfter(),
		RiskReduction: c.RiskReduction(),
		IsOverdue:     c.IsOverdue(),
		StartDate:     c.StartDate(),
		DueDate:       c.DueDate(),
		CompletedAt:   c.CompletedAt(),
		Tags:          c.Tags(),
		CreatedAt:     c.CreatedAt(),
		UpdatedAt:     c.UpdatedAt(),
	}
}
