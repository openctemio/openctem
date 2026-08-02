package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/app/threat"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatactor"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/validator"
)

// ThreatActorHandler handles threat actor HTTP endpoints.
type ThreatActorHandler struct {
	service   *threat.ActorService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewThreatActorHandler creates a new threat actor handler.
func NewThreatActorHandler(svc *threat.ActorService, v *validator.Validator, log *logger.Logger) *ThreatActorHandler {
	return &ThreatActorHandler{service: svc, validator: v, logger: log}
}

// decodeAndValidate reads the JSON body into dst and runs struct validation so
// the `validate:` tags on the request structs are actually enforced. On failure
// it writes a 400 and returns false, so callers do
// `if !h.decodeAndValidate(w, r, &req) { return }`.
func (h *ThreatActorHandler) decodeAndValidate(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return false
	}
	if h.validator != nil {
		if err := h.validator.Validate(dst); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return false
		}
	}
	return true
}

// List lists all threat actors for the tenant.
func (h *ThreatActorHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryIntBounded(r.URL.Query().Get("per_page"), 20, 1, MaxPerPage)
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

	result, err := h.service.ListActors(r.Context(), tenantID, filter, page)
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
	if !h.decodeAndValidate(w, r, &req) {
		return
	}

	actor, err := h.service.CreateActor(r.Context(), threat.CreateActorInput{
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

	actor, err := h.service.GetActor(r.Context(), tenantID, actorID)
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

	if err := h.service.DeleteActor(r.Context(), tenantID, actorID); err != nil {
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
	Name             string            `json:"name" validate:"required,min=1,max=255"`
	Aliases          []string          `json:"aliases" validate:"omitempty,max=50,dive,max=255"`
	Description      string            `json:"description" validate:"omitempty,max=5000"`
	ActorType        string            `json:"actor_type" validate:"omitempty,oneof=apt cybercrime hacktivist insider nation_state unknown"`
	Sophistication   string            `json:"sophistication" validate:"omitempty,max=100"`
	Motivation       string            `json:"motivation" validate:"omitempty,max=255"`
	CountryOfOrigin  string            `json:"country_of_origin" validate:"omitempty,max=100"`
	MitreGroupID     string            `json:"mitre_group_id" validate:"omitempty,max=50"`
	TTPs             []threatactor.TTP `json:"ttps" validate:"omitempty,max=500"`
	TargetIndustries []string          `json:"target_industries" validate:"omitempty,max=100,dive,max=255"`
	TargetRegions    []string          `json:"target_regions" validate:"omitempty,max=100,dive,max=255"`
	Tags             []string          `json:"tags" validate:"omitempty,max=100,dive,max=100"`
}

type ThreatActorResponse struct {
	ID                 string                          `json:"id"`
	Name               string                          `json:"name"`
	Aliases            []string                        `json:"aliases"`
	Description        string                          `json:"description"`
	ActorType          string                          `json:"actor_type"`
	Sophistication     string                          `json:"sophistication,omitempty"`
	Motivation         string                          `json:"motivation,omitempty"`
	CountryOfOrigin    string                          `json:"country_of_origin,omitempty"`
	IsActive           bool                            `json:"is_active"`
	MitreGroupID       string                          `json:"mitre_group_id,omitempty"`
	TTPs               []threatactor.TTP               `json:"ttps"`
	TargetIndustries   []string                        `json:"target_industries"`
	TargetRegions      []string                        `json:"target_regions"`
	ExternalReferences []threatactor.ExternalReference `json:"external_references"`
	Tags               []string                        `json:"tags"`
	CreatedAt          time.Time                       `json:"created_at"`
	UpdatedAt          time.Time                       `json:"updated_at"`
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
