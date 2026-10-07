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
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMSeeder manages EASM seeds (RFC-036 §6.3).
type EASMSeeder interface {
	List(ctx context.Context, tenantID shared.ID) ([]easmapp.SeedView, error)
	Create(ctx context.Context, tenantID shared.ID, in easmapp.CreateSeedInput) (*scopedom.Target, error)
	Update(ctx context.Context, tenantID, id shared.ID, label *string, discovery *bool) (*easmapp.SeedView, bool, error)
	Delete(ctx context.Context, tenantID, id shared.ID) (*easmseed.Seed, error)
}

// EASMSeedHandler serves /api/v1/easm/seeds.
type EASMSeedHandler struct {
	svc       EASMSeeder
	audit     AttributionAuditor
	logger    *logger.Logger
	sweeper   SeedSweeper
	admins    SeedAdminNotifier
	scopeJoin ScopeJoinReevaluator
	actors    MemberNamer
}

// SetActorNamer names the people on the returned scope entry.
func (h *EASMSeedHandler) SetActorNamer(n MemberNamer) { h.actors = n }

// SeedAdminNotifier tells every administrator that scope grew
// (*scope.Service).
type SeedAdminNotifier interface {
	NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body string)
}

// SetAdminNotifier announces discovery turned on for a seed to the
// administrators (RFC-054 §7). A new seed is announced by the scope entry
// path itself.
func (h *EASMSeedHandler) SetAdminNotifier(n SeedAdminNotifier) { h.admins = n }

// SetScopeJoin re-evaluates the review queue once a new seed's scope entry
// is in effect, as a scope entry created on the Scope page does (S4).
func (h *EASMSeedHandler) SetScopeJoin(j ScopeJoinReevaluator) { h.scopeJoin = j }

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
	if writeScopeEntryError(w, err) {
		return
	}
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
// @Description  Adds a root-domain seed as the permanent scope entry "*.<domain>" (RFC-054): it authorizes active checks of the domain and every name below it, confirms discovered names under it and starts discovery. Adding one widens scope, so it goes through the scope entry path: attack_surface:scope:approve, a recent re-authentication (403 STEP_UP_REQUIRED), the organization's approval count (202 with a pending entry that authorizes nothing until approved), the platform guardrails (public suffixes, the deny list), and a notification to every administrator. A member cannot add a seed (403 WIDENING_NEEDS_APPROVER); members request one-off entries on POST /scope/targets. The caller must attest that the organization is authorized to have it discovered and checked. Audited as a scope entry.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body EASMSeedCreateRequest true "Seed"
// @Success      201  {object}  ScopeTargetResponse  "in effect"
// @Success      202  {object}  ScopeTargetResponse  "pending approval"
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
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
	t, err := h.svc.Create(r.Context(), tenantID, easmapp.CreateSeedInput{
		Kind: req.Kind, Value: req.Value, Label: req.Label, DiscoveryEnabled: req.DiscoveryEnabled,
		Attested: req.Attested, Actor: scopeActor(r),
	})
	if err != nil {
		h.writeErr(w, err, "add seed")
		return
	}
	h.auditEntry(r, t)
	status := http.StatusAccepted
	if t.IsActive() {
		status = http.StatusCreated
		if h.sweeper != nil {
			h.sweeper.SweepForSeed(tenantID)
		}
		h.reevaluate(tenantID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	out := toScopeTargetResponse(t)
	resolveActors(r.Context(), h.actors, h.logger, tenantID.String(), targetActorRefs(&out))
	_ = json.NewEncoder(w).Encode(out)
}

// auditEntry records the seed's scope entry as a scope entry creation, with
// the entry's state, so the scope history shows it beside entries made on
// the Scope page.
func (h *EASMSeedHandler) auditEntry(r *http.Request, t *scopedom.Target) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	ev := auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, t.ID().String()).
		WithResourceName(t.Pattern()).
		WithMessage("Scope entry "+t.Pattern()+" added as a root-domain seed ("+t.Status().String()+")").
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("via", "easm_seed").
		WithMetadata("status", t.Status().String()).
		WithMetadata("approvals_required", t.ApprovalsRequired()).
		WithMetadata("max_tier", t.MaxTier().String()).
		WithMetadata("attested", true)
	_ = h.audit.LogEvent(ctx, auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}, ev)
}

func (h *EASMSeedHandler) reevaluate(tenantID shared.ID) {
	if h.scopeJoin == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), scopeJoinTimeout)
		defer cancel()
		if _, err := h.scopeJoin.Reevaluate(ctx, tenantID); err != nil {
			h.logger.Warn("scope join after a new seed failed", "error", logger.SanitizeError(err))
		}
	}()
}

// Update handles PATCH /api/v1/easm/seeds/{id}
// @Summary      Change an EASM seed
// @Description  Changes a seed's label or turns discovery from it on or off. The kind and value cannot change: delete and add instead. Needs attack_surface:scope:approve and a recent re-authentication (403 STEP_UP_REQUIRED); turning discovery on notifies every administrator. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Seed ID"
// @Param        body body EASMSeedUpdateRequest true "Changes"
// @Success      200  {object}  easmapp.SeedView
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
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
	v, turnedOn, err := h.svc.Update(r.Context(), tenantID, id, req.Label, req.DiscoveryEnabled)
	if err != nil {
		h.writeErr(w, err, "change seed")
		return
	}
	if turnedOn && h.admins != nil {
		h.admins.NotifyAdmins(r.Context(), tenantID, "Discovery turned on for a seed",
			"Discovery from the root-domain seed "+v.Value+" is on again: names found under it join the inventory.")
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
