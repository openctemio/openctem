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
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatactor"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ThreatActorHandler handles threat actor HTTP endpoints.
type ThreatActorHandler struct {
	service *app.ThreatActorService
	logger  *logger.Logger
}

// NewThreatActorHandler creates a new threat actor handler.
func NewThreatActorHandler(svc *app.ThreatActorService, log *logger.Logger) *ThreatActorHandler {
	return &ThreatActorHandler{service: svc, logger: log}
}

// List lists all threat actors for the tenant.
func (h *ThreatActorHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage < 1 {
		perPage = 20
	} else if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(max(parseQueryInt(r.URL.Query().Get("page"), 1), 1), perPage)

	filter := threatactor.Filter{}
	if t := r.URL.Query().Get("type"); t != "" {
		at := threatactor.ActorType(t)
		filter.ActorType = &at
	}
	if q := r.URL.Query().Get("search"); q != "" {
		filter.Search = &q
	}

	result, err := h.service.ListThreatActors(r.Context(), tenantID, filter, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	resp := make([]ThreatActorResponse, 0, len(result.Data))
	for _, a := range result.Data {
		resp = append(resp, toThreatActorResponse(a))
	}

	writeJSON(w, http.StatusOK, pagination.NewResult(resp, result.Total, page))
}

// Create creates a new threat actor.
func (h *ThreatActorHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateThreatActorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	actor, err := h.service.CreateThreatActor(r.Context(), app.CreateThreatActorInput{
		TenantID:         tenantID,
		Name:             req.Name,
		Aliases:          req.Aliases,
		Description:      req.Description,
		ActorType:        req.ActorType,
		Sophistication:   req.Sophistication,
		Motivation:       req.Motivation,
		CountryOfOrigin:  req.CountryOfOrigin,
		MitreGroupID:     req.MitreGroupID,
		TTPs:             req.TTPs,
		TargetIndustries: req.TargetIndustries,
		TargetRegions:    req.TargetRegions,
		Tags:             req.Tags,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, toThreatActorResponse(actor))
}

// Get retrieves a threat actor by ID.
func (h *ThreatActorHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	actorID := chi.URLParam(r, "id")

	actor, err := h.service.GetThreatActor(r.Context(), tenantID, actorID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toThreatActorResponse(actor))
}

// Delete deletes a threat actor.
func (h *ThreatActorHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	actorID := chi.URLParam(r, "id")

	if err := h.service.DeleteThreatActor(r.Context(), tenantID, actorID); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ThreatActorHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("resource not found").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("threat actor handler error", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}

// ─── Request/Response Types ───

type CreateThreatActorRequest struct {
	Name             string            `json:"name"`
	Aliases          []string          `json:"aliases"`
	Description      string            `json:"description"`
	ActorType        string            `json:"actor_type"`
	Sophistication   string            `json:"sophistication"`
	Motivation       string            `json:"motivation"`
	CountryOfOrigin  string            `json:"country_of_origin"`
	MitreGroupID     string            `json:"mitre_group_id"`
	TTPs             []threatactor.TTP `json:"ttps"`
	TargetIndustries []string          `json:"target_industries"`
	TargetRegions    []string          `json:"target_regions"`
	Tags             []string          `json:"tags"`
}

type ThreatActorResponse struct {
	ID                 string                           `json:"id"`
	Name               string                           `json:"name"`
	Aliases            []string                         `json:"aliases"`
	Description        string                           `json:"description"`
	ActorType          string                           `json:"actor_type"`
	Sophistication     string                           `json:"sophistication,omitempty"`
	Motivation         string                           `json:"motivation,omitempty"`
	CountryOfOrigin    string                           `json:"country_of_origin,omitempty"`
	IsActive           bool                             `json:"is_active"`
	MitreGroupID       string                           `json:"mitre_group_id,omitempty"`
	TTPs               []threatactor.TTP                `json:"ttps"`
	TargetIndustries   []string                         `json:"target_industries"`
	TargetRegions      []string                         `json:"target_regions"`
	ExternalReferences []threatactor.ExternalReference   `json:"external_references"`
	Tags               []string                         `json:"tags"`
	CreatedAt          time.Time                        `json:"created_at"`
	UpdatedAt          time.Time                        `json:"updated_at"`
}

func toThreatActorResponse(a *threatactor.ThreatActor) ThreatActorResponse {
	return ThreatActorResponse{
		ID:                 a.ID().String(),
		Name:               a.Name(),
		Aliases:            a.Aliases(),
		Description:        a.Description(),
		ActorType:          string(a.ActorType()),
		Sophistication:     a.Sophistication(),
		Motivation:         a.Motivation(),
		CountryOfOrigin:    a.CountryOfOrigin(),
		IsActive:           a.IsActive(),
		MitreGroupID:       a.MitreGroupID(),
		TTPs:               a.TTPs(),
		TargetIndustries:   a.TargetIndustries(),
		TargetRegions:      a.TargetRegions(),
		ExternalReferences: a.ExternalReferences(),
		Tags:               a.Tags(),
		CreatedAt:          a.CreatedAt(),
		UpdatedAt:          a.UpdatedAt(),
	}
}
