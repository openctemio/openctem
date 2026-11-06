package handler

// Network seeds of EASM discovery (docs/rfcs/RFC-082-network-seeds.md).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMNetworkSeeds manages network seeds.
type EASMNetworkSeeds interface {
	List(ctx context.Context, tenantID shared.ID) ([]easmapp.SeedView, error)
	Create(ctx context.Context, tenantID shared.ID, actor *shared.ID, kind easmseed.Kind, value, label string) (*easmapp.SeedView, error)
	Delete(ctx context.Context, tenantID shared.ID, id string) error
	Expand(ctx context.Context, tenantID shared.ID, id string) error
}

// EASMNetworkSeedHandler serves /api/v1/easm/network-seeds.
type EASMNetworkSeedHandler struct {
	svc    EASMNetworkSeeds
	audit  AttributionAuditor
	logger *logger.Logger
}

// NewEASMNetworkSeedHandler creates the handler. A nil auditor skips audit
// records (tests only).
func NewEASMNetworkSeedHandler(svc EASMNetworkSeeds, audit AttributionAuditor, log *logger.Logger) *EASMNetworkSeedHandler {
	return &EASMNetworkSeedHandler{svc: svc, audit: audit, logger: log.With("handler", "easm-network-seeds")}
}

// EASMNetworkSeedList is the organization's network seeds.
type EASMNetworkSeedList struct {
	Items []easmapp.SeedView `json:"items"`
	Max   int                `json:"max"`
}

// EASMNetworkSeedRequest adds a network seed.
type EASMNetworkSeedRequest struct {
	Kind  string `json:"kind"` // asn or org_name
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

func (h *EASMNetworkSeedHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *EASMNetworkSeedHandler) auditEvent(r *http.Request, action auditdom.Action, id, name, msg string) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeEASMNetworkSeed, id).WithResourceName(name).WithMessage(msg)
	auditapp.RecordOrWarn(ctx, h.logger, h.audit, auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context()),
	}, ev)
}

// List handles GET /api/v1/easm/network-seeds
// @Summary      Network seeds
// @Description  The organization's AS number and organization-name seeds with what public routing data says about them: the AS holder and the prefixes it announces (each checked against the platform guardrails, offered as a CIDR scope entry to add through the scope flow), or the AS numbers registered to the organization name. A seed never authorizes a probe.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  EASMNetworkSeedList
// @Router       /easm/network-seeds [get]
func (h *EASMNetworkSeedHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	items, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("network seeds: list", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list network seeds").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(EASMNetworkSeedList{Items: items, Max: easmseed.MaxSeedsPerTenant})
}

// Create handles POST /api/v1/easm/network-seeds
// @Summary      Add a network seed
// @Description  Adds an AS number (AS13335) or an organization name. The value is sent to the public RIPEstat service to expand it (in the background). Reserved and private AS numbers are refused; at most 50 seeds. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body EASMNetworkSeedRequest true "Seed"
// @Success      201  {object}  easmapp.SeedView
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /easm/network-seeds [post]
func (h *EASMNetworkSeedHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req EASMNetworkSeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	var actor *shared.ID
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		actor = &uid
	}
	v, err := h.svc.Create(r.Context(), tenantID, actor, easmseed.Kind(req.Kind), req.Value, req.Label)
	if err != nil {
		switch {
		case errors.Is(err, shared.ErrValidation):
			apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
		case errors.Is(err, shared.ErrConflict):
			apierror.Conflict("The seed exists already, or the organization has the maximum number of seeds").WriteJSON(w)
		default:
			h.logger.Error("network seeds: create", "error", logger.SanitizeError(err))
			apierror.InternalServerError("failed to add the seed").WriteJSON(w)
		}
		return
	}
	h.auditEvent(r, auditdom.ActionEASMNetworkSeedAdded, v.ID, v.Value, "Network seed '"+v.Value+"' ("+string(v.Kind)+") added")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(v)
}

// Delete handles DELETE /api/v1/easm/network-seeds/{id}
// @Summary      Remove a network seed
// @Description  Scope entries added from its suggestions stay. Audited.
// @Tags         Attack Surface
// @Security     BearerAuth
// @Param        id   path  string  true  "Seed ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /easm/network-seeds/{id} [delete]
func (h *EASMNetworkSeedHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := h.svc.Delete(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Seed").WriteJSON(w)
			return
		}
		h.logger.Error("network seeds: delete", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to remove the seed").WriteJSON(w)
		return
	}
	h.auditEvent(r, auditdom.ActionEASMNetworkSeedDeleted, id, "", "Network seed removed")
	w.WriteHeader(http.StatusNoContent)
}

// Expand handles POST /api/v1/easm/network-seeds/{id}/expand
// @Summary      Refresh a network seed
// @Description  Looks the seed up again in public routing data, in the background. At most once per 15 minutes per seed (429). Audited.
// @Tags         Attack Surface
// @Security     BearerAuth
// @Param        id   path  string  true  "Seed ID"
// @Success      202
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /easm/network-seeds/{id}/expand [post]
func (h *EASMNetworkSeedHandler) Expand(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := h.svc.Expand(r.Context(), tenantID, id); err != nil {
		switch {
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("Seed").WriteJSON(w)
		case errors.Is(err, easmapp.ErrLookupsOff):
			apierror.Conflict("Lookups in public routing data are turned off for the organization").WriteJSON(w)
		case errors.Is(err, easmapp.ErrExpandTooSoon):
			w.Header().Set("Retry-After", "900")
			apierror.TooManyRequests("The seed was refreshed less than 15 minutes ago").WriteJSON(w)
		default:
			h.logger.Error("network seeds: expand", "error", logger.SanitizeError(err))
			apierror.InternalServerError("failed to refresh the seed").WriteJSON(w)
		}
		return
	}
	h.auditEvent(r, auditdom.ActionEASMNetworkSeedExpanded, id, "", "Network seed refresh requested")
	w.WriteHeader(http.StatusAccepted)
}
