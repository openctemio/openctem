package handler

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

// EASMSeeder manages EASM seeds (RFC-036 §6.3).
type EASMSeeder interface {
	List(ctx context.Context, tenantID shared.ID) ([]easmapp.SeedView, error)
	Create(ctx context.Context, tenantID shared.ID, in easmapp.CreateSeedInput) (*easmapp.SeedView, error)
	Update(ctx context.Context, tenantID, id shared.ID, label *string, discovery *bool) (*easmapp.SeedView, error)
	Delete(ctx context.Context, tenantID, id shared.ID) (*easmseed.Seed, error)
}

// EASMSeedHandler serves /api/v1/easm/seeds.
type EASMSeedHandler struct {
	svc     EASMSeeder
	audit   AttributionAuditor
	logger  *logger.Logger
	sweeper SeedSweeper
}

// SeedSweeper starts a sweep for a tenant after a seed is added
// (*easm.SweepService; research/22 P0-11).
type SeedSweeper interface {
	SweepForSeed(tenantID shared.ID)
}

// SetSweeper makes a new seed with discovery on start a sweep, so its first
// results arrive in minutes instead of at the next daily run.
func (h *EASMSeedHandler) SetSweeper(s SeedSweeper) { h.sweeper = s }

// NewEASMSeedHandler creates the handler. A nil auditor skips audit records
// (tests only; production wires the audit service).
func NewEASMSeedHandler(svc EASMSeeder, audit AttributionAuditor, log *logger.Logger) *EASMSeedHandler {
	return &EASMSeedHandler{svc: svc, audit: audit, logger: log}
}

// EASMSeedListResponse is the seed list.
type EASMSeedListResponse struct {
	Data []easmapp.SeedView `json:"data"`
}

// EASMSeedCreateRequest is a new seed.
type EASMSeedCreateRequest struct {
	// Kind: root_domain (other RFC-036 kinds are accepted once their
	// collectors exist).
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
	// DiscoveryEnabled defaults to true.
	DiscoveryEnabled *bool `json:"discovery_enabled,omitempty"`
	// Attested must be true: the caller states the organization is authorized
	// to have this seed discovered and checked. Recorded with the user and time.
	Attested bool `json:"attested"`
}

// EASMSeedUpdateRequest changes a seed.
type EASMSeedUpdateRequest struct {
	Label            *string `json:"label,omitempty"`
	DiscoveryEnabled *bool   `json:"discovery_enabled,omitempty"`
}

func (h *EASMSeedHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *EASMSeedHandler) writeErr(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("This seed already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Seed").WriteJSON(w)
	default:
		h.logger.Error("easm seed: "+what, "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to " + what).WriteJSON(w)
	}
}

func (h *EASMSeedHandler) auditEvent(r *http.Request, action auditdom.Action, id, name string, meta map[string]any) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeEASMSeed, id).WithResourceName(name)
	for k, v := range meta {
		ev = ev.WithMetadata(k, v)
	}
	_ = h.audit.LogEvent(ctx, auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}, ev)
}

// List handles GET /api/v1/easm/seeds
// @Summary      List EASM seeds
// @Description  The organization's seeds: what external-surface discovery expands from. A root_domain seed is verified (dns_txt) while the organization has a verified DNS TXT record for it or a parent.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  EASMSeedListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/seeds [get]
func (h *EASMSeedHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	seeds, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "list seeds")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(EASMSeedListResponse{Data: seeds})
}

// Create handles POST /api/v1/easm/seeds
// @Summary      Add an EASM seed
// @Description  Adds a seed discovery expands from. The caller must attest that the organization is authorized to have it discovered and checked (recorded with the user and time). Public suffixes and providers' shared domains are refused. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body EASMSeedCreateRequest true "Seed"
// @Success      201  {object}  easmapp.SeedView
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/seeds [post]
func (h *EASMSeedHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req EASMSeedCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	v, err := h.svc.Create(r.Context(), tenantID, easmapp.CreateSeedInput{
		Kind: req.Kind, Value: req.Value, Label: req.Label, DiscoveryEnabled: req.DiscoveryEnabled,
		Attested: req.Attested, ActorID: middleware.GetUserID(r.Context()),
	})
	if err != nil {
		h.writeErr(w, err, "add seed")
		return
	}
	h.auditEvent(r, auditdom.ActionEASMSeedCreated, v.ID, v.Value, map[string]any{
		"kind": v.Kind, "value": v.Value, "discovery_enabled": v.DiscoveryEnabled, "attested": true,
	})
	if h.sweeper != nil && v.DiscoveryEnabled {
		h.sweeper.SweepForSeed(tenantID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(v)
}

// Update handles PATCH /api/v1/easm/seeds/{id}
// @Summary      Change an EASM seed
// @Description  Changes a seed's label or turns discovery from it on or off. The kind and value cannot change: delete and add instead. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Seed ID"
// @Param        body body EASMSeedUpdateRequest true "Changes"
// @Success      200  {object}  easmapp.SeedView
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/seeds/{id} [patch]
func (h *EASMSeedHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound("Seed").WriteJSON(w)
		return
	}
	limitBody(w, r)
	var req EASMSeedUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	v, err := h.svc.Update(r.Context(), tenantID, id, req.Label, req.DiscoveryEnabled)
	if err != nil {
		h.writeErr(w, err, "change seed")
		return
	}
	meta := map[string]any{"kind": v.Kind, "value": v.Value}
	if req.DiscoveryEnabled != nil {
		meta["discovery_enabled"] = *req.DiscoveryEnabled
	}
	if req.Label != nil {
		meta["label_changed"] = true
	}
	h.auditEvent(r, auditdom.ActionEASMSeedUpdated, v.ID, v.Value, meta)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Delete handles DELETE /api/v1/easm/seeds/{id}
// @Summary      Remove an EASM seed
// @Description  Removes a seed. Assets already discovered from it stay in the inventory with their evidence. Audited.
// @Tags         Attack Surface
// @Security     BearerAuth
// @Param        id path string true "Seed ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/seeds/{id} [delete]
func (h *EASMSeedHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound("Seed").WriteJSON(w)
		return
	}
	sd, err := h.svc.Delete(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "remove seed")
		return
	}
	h.auditEvent(r, auditdom.ActionEASMSeedDeleted, sd.ID.String(), sd.Value, map[string]any{
		"kind": string(sd.Kind), "value": sd.Value,
	})
	w.WriteHeader(http.StatusNoContent)
}
