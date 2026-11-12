package handler

// Passive lookalike-domain monitoring (docs/rfcs/RFC-083-lookalike-domains.md).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/lookalike"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMLookalikes manages lookalike watches.
type EASMLookalikes interface {
	ListWatches(ctx context.Context, tenantID shared.ID) ([]lookalike.Watch, error)
	CreateWatch(ctx context.Context, tenantID shared.ID, actor *shared.ID, domain string, techs []string, maxN int) (*lookalike.Watch, error)
	UpdateWatch(ctx context.Context, tenantID shared.ID, id string, enabled bool, techs []string, maxN int) (*lookalike.Watch, error)
	DeleteWatch(ctx context.Context, tenantID shared.ID, id string) error
	Registered(ctx context.Context, tenantID shared.ID, id string) ([]lookalike.CandidateRecord, error)
}

// EASMLookalikeHandler serves /api/v1/easm/lookalikes.
type EASMLookalikeHandler struct {
	svc    EASMLookalikes
	audit  AttributionAuditor
	logger *logger.Logger
}

// NewEASMLookalikeHandler creates the handler.
func NewEASMLookalikeHandler(svc EASMLookalikes, audit AttributionAuditor, log *logger.Logger) *EASMLookalikeHandler {
	return &EASMLookalikeHandler{svc: svc, audit: audit, logger: log.With("handler", "easm-lookalikes")}
}

// LookalikeWatchList lists the watches.
type LookalikeWatchList struct {
	Items      []lookalike.Watch     `json:"items"`
	Max        int                   `json:"max"`
	Techniques []lookalike.Technique `json:"techniques"`
}

// LookalikeWatchRequest creates or changes a watch.
type LookalikeWatchRequest struct {
	Domain        string   `json:"domain,omitempty"` // create only
	Enabled       *bool    `json:"enabled,omitempty"`
	Techniques    []string `json:"techniques"`
	MaxCandidates int      `json:"max_candidates"`
}

// LookalikeCandidateList lists a watch's registered lookalikes.
type LookalikeCandidateList struct {
	Items []lookalike.CandidateRecord `json:"items"`
}

func (h *EASMLookalikeHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *EASMLookalikeHandler) auditEvent(r *http.Request, action auditdom.Action, id, domain, msg string) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeEASMLookalikeWatch, id).WithResourceName(domain).WithMessage(msg)
	auditapp.RecordOrWarn(ctx, h.logger, h.audit, auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context()),
	}, ev)
}

func (h *EASMLookalikeHandler) writeErr(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Watch").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("The domain is watched already, or the organization has the maximum number of watches").WriteJSON(w)
	default:
		h.logger.Error("lookalikes: "+what, "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to " + what).WriteJSON(w)
	}
}

// List handles GET /api/v1/easm/lookalikes/watches
// @Summary      Lookalike-domain watches
// @Description  The organization's root domains watched for registered lookalikes (typos, homoglyphs, bit flips, hyphens, other TLDs), with how many candidates were generated, checked and found registered. Checks are passive only: DNS through the platform resolver and Certificate Transparency.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  LookalikeWatchList
// @Router       /easm/lookalikes/watches [get]
func (h *EASMLookalikeHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	items, err := h.svc.ListWatches(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "list watches")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(LookalikeWatchList{Items: items, Max: lookalike.MaxWatchesPerTenant, Techniques: lookalike.AllTechniques()})
}

// Create handles POST /api/v1/easm/lookalikes/watches
// @Summary      Watch a root domain for lookalikes
// @Description  The domain must be one of the organization's roots: a permanent domain scope entry or a verified domain. techniques empty = all; max_candidates 10 to 1000 (default 300). At most 20 watches. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body LookalikeWatchRequest true "Watch"
// @Success      201  {object}  lookalike.Watch
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /easm/lookalikes/watches [post]
func (h *EASMLookalikeHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req LookalikeWatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	var actor *shared.ID
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		actor = &uid
	}
	wt, err := h.svc.CreateWatch(r.Context(), tenantID, actor, req.Domain, req.Techniques, req.MaxCandidates)
	if err != nil {
		h.writeErr(w, err, "add the watch")
		return
	}
	h.auditEvent(r, auditdom.ActionEASMLookalikeWatchAdded, wt.ID, wt.Domain, "Lookalike watch added for '"+wt.Domain+"'")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(wt)
}

// Update handles PUT /api/v1/easm/lookalikes/watches/{id}
// @Summary      Change a lookalike watch
// @Description  Turn the watch off or on and change its techniques or candidate cap (candidates are generated again). Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Watch ID"
// @Param        body body LookalikeWatchRequest true "Settings"
// @Success      200  {object}  lookalike.Watch
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /easm/lookalikes/watches/{id} [put]
func (h *EASMLookalikeHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req LookalikeWatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	wt, err := h.svc.UpdateWatch(r.Context(), tenantID, r.PathValue("id"), enabled, req.Techniques, req.MaxCandidates)
	if err != nil {
		h.writeErr(w, err, "change the watch")
		return
	}
	h.auditEvent(r, auditdom.ActionEASMLookalikeWatchUpdated, wt.ID, wt.Domain, "Lookalike watch changed for '"+wt.Domain+"'")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wt)
}

// Delete handles DELETE /api/v1/easm/lookalikes/watches/{id}
// @Summary      Stop watching a domain for lookalikes
// @Description  Its open lookalike exposures are resolved. Audited.
// @Tags         Attack Surface
// @Security     BearerAuth
// @Param        id   path  string  true  "Watch ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /easm/lookalikes/watches/{id} [delete]
func (h *EASMLookalikeHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := h.svc.DeleteWatch(r.Context(), tenantID, id); err != nil {
		h.writeErr(w, err, "remove the watch")
		return
	}
	h.auditEvent(r, auditdom.ActionEASMLookalikeWatchDeleted, id, "", "Lookalike watch removed")
	w.WriteHeader(http.StatusNoContent)
}

// Registered handles GET /api/v1/easm/lookalikes/watches/{id}/registered
// @Summary      Registered lookalikes of a watched domain
// @Description  Candidates found registered, newest first (at most 200): technique, whether the name has addresses and mail servers, its name servers and how many unexpired certificates CT logs list. Triage them as exposures (lookalike_domain).
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Watch ID"
// @Success      200  {object}  LookalikeCandidateList
// @Failure      404  {object}  apierror.Error
// @Router       /easm/lookalikes/watches/{id}/registered [get]
func (h *EASMLookalikeHandler) Registered(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	items, err := h.svc.Registered(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeErr(w, err, "list registered lookalikes")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(LookalikeCandidateList{Items: items})
}
