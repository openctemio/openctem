package handler

// Bulk decisions on the addresses card (research/425): the tenant comes from
// the authenticated principal, the actor from the session; everything posted
// is checked again against the caller's own card (easmapp.AddressDecisions).
// Each decision is one audit event listing its items, and every scope entry
// it adds is audited as an ordinary scope entry creation.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMAddressDecider applies bulk decisions (*easmapp.AddressDecisions).
type EASMAddressDecider interface {
	Add(ctx context.Context, tenantID shared.ID, actor easmapp.ScopeActor, in easmapp.AddressAddInput) (*easmapp.AddressAddResult, error)
	Reject(ctx context.Context, tenantID shared.ID, actor easmapp.ScopeActor, sel easmapp.AddressSelection) (*easmapp.AddressRejectResult, error)
	RetryLookup(ctx context.Context, tenantID shared.ID, sel easmapp.AddressSelection) (*easmapp.LookupRetryResult, error)
	NetworkIsOurs(ctx context.Context, tenantID shared.ID, actor easmapp.ScopeActor, key string) (*easmapp.NetworkAnswerResult, error)
	NetworkNotOurs(ctx context.Context, tenantID shared.ID, actor easmapp.ScopeActor, key string) (*easmapp.NetworkAnswerResult, error)
	Undecline(ctx context.Context, tenantID shared.ID, id string) (*easmseed.Declined, error)
}

// SetAddressDecisions wires the bulk decisions.
func (h *EASMHandler) SetAddressDecisions(d EASMAddressDecider) *EASMHandler {
	h.decisions = d
	return h
}

// HasAddressDecisions reports whether the bulk decisions are wired.
func (h *EASMHandler) HasAddressDecisions() bool { return h.decisions != nil }

// EASMAddressSelection is what the person chose on the card: addresses,
// whole groups (keys from the card) and/or every waiting address, also
// those past the card's list.
type EASMAddressSelection struct {
	Addresses  []string `json:"addresses" validate:"max=2000"`
	Groups     []string `json:"groups" validate:"max=500"`
	AllWaiting bool     `json:"all_waiting"`
}

func (s EASMAddressSelection) app() easmapp.AddressSelection {
	return easmapp.AddressSelection{Addresses: s.Addresses, Groups: s.Groups, AllWaiting: s.AllWaiting}
}

// EASMAddressAddRequest adds addresses (and own ranges) of the card.
type EASMAddressAddRequest struct {
	EASMAddressSelection
	Ranges []string `json:"ranges" validate:"max=200"`
	// IncludeShared also adds the chosen shared, provider and declined
	// addresses (each an exact entry); without it a selection holding one
	// is refused.
	IncludeShared bool `json:"include_shared"`
}

// EASMAddressRejectRequest marks addresses of the card not the organization's.
type EASMAddressRejectRequest struct {
	EASMAddressSelection
}

// maxDecisionBody bounds a decision body (2000 addresses fit).
const maxDecisionBody = 256 << 10

func decodeDecision(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxDecisionBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// EASMNetworkAnswerRequest answers "is this network yours?" for one group.
type EASMNetworkAnswerRequest struct {
	// Key: the group's key on the card.
	Key string `json:"key"`
}

func (h *EASMHandler) decisionTenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return tenantID, true
}

func (h *EASMHandler) decisionError(w http.ResponseWriter, what string, err error) {
	if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
		return
	}
	var de *shared.DomainError
	switch {
	case errors.As(err, &de) && errors.Is(err, shared.ErrValidation) && de.Code != "":
		apierror.New(http.StatusBadRequest, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound(what).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("The network is already one of your network seeds").WriteJSON(w)
	default:
		h.logger.Error("address decision failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to save the decision").WriteJSON(w)
	}
}

func (h *EASMHandler) decisionAudit(r *http.Request, event auditapp.AuditEvent) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	auditapp.RecordOrWarn(ctx, h.logger, h.audit, auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx),
	}, event)
}

func writeDecisionJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// AddAddresses handles POST /api/v1/easm/suggestions/addresses/add
// @Summary      Add addresses from the Decisions card
// @Description  Adds addresses the organization's in-scope names resolve to, and the organization's own prefixes the card offers, as scope entries in one decision. Every address and range must be on the caller's own addresses card (tenant, data scope, not covered yet); otherwise nothing is written (400 DECISION_NOT_PENDING). A shared, CDN or provider address is added only on its own with include_shared (400 DECISION_SHARED otherwise). Entries go through the scope service as the caller: guardrails, deny list, step-up (403 STEP_UP_REQUIRED), the approval policy (an entry may be pending) and the signer ledger; each entry and the decision are audited. At most 200 items.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      EASMAddressAddRequest  true  "Addresses and ranges"
// @Success      200   {object}  easmapp.AddressAddResult
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Router       /easm/suggestions/addresses/add [post]
func (h *EASMHandler) AddAddresses(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.decisionTenant(w, r)
	if !ok {
		return
	}
	var req EASMAddressAddRequest
	if !decodeDecision(w, r, &req) {
		return
	}
	res, err := h.decisions.Add(r.Context(), tenantID, confirmActor(r.Context()), easmapp.AddressAddInput{
		AddressSelection: req.app(), Ranges: req.Ranges, IncludeShared: req.IncludeShared,
	})
	if err != nil {
		h.decisionError(w, "Addresses", err)
		return
	}
	patterns := make([]string, 0, len(res.Items))
	for _, it := range res.Items {
		patterns = append(patterns, it.Pattern)
		if it.Result != easmapp.AddressResultCreated {
			continue
		}
		h.decisionAudit(r, auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, it.ID).
			WithResourceName(it.Pattern).
			WithMessage("Scope entry added from the Decisions card: in-scope names resolve to it").
			WithMetadata("origin", "confirmed_asset").
			WithMetadata("status", it.Status).
			WithMetadata("via", "decisions_card"))
	}
	h.decisionAudit(r, auditapp.NewSuccessEvent(auditdom.ActionEASMAddressesAdded, auditdom.ResourceTypeScopeTarget, "").
		WithMessage("Addresses added to scope from the Decisions card").
		WithMetadata("items", strings.Join(patterns, ",")).
		WithMetadata("created", res.Created).
		WithMetadata("pending", res.Pending).
		WithMetadata("existing", res.Existing).
		WithMetadata("refused", res.Refused).
		WithMetadata("shared", req.IncludeShared).
		WithMetadata("resolved_from", strings.Join(res.Names, ",")).
		WithSeverity(auditdom.SeverityHigh))
	writeDecisionJSON(w, res)
}

// RejectAddresses handles POST /api/v1/easm/suggestions/addresses/reject
// @Summary      Mark addresses from the Decisions card as not yours
// @Description  Marks addresses of the caller's own addresses card as not the organization's (attribution rejected: never scanned or suggested again until undone with state automatic). Every address must be on the card (400 DECISION_NOT_PENDING otherwise; nothing is written). One audit event lists them. At most 200.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      EASMAddressRejectRequest  true  "Addresses"
// @Success      200   {object}  easmapp.AddressRejectResult
// @Failure      400   {object}  apierror.Error
// @Router       /easm/suggestions/addresses/reject [post]
func (h *EASMHandler) RejectAddresses(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.decisionTenant(w, r)
	if !ok {
		return
	}
	var req EASMAddressRejectRequest
	if !decodeDecision(w, r, &req) {
		return
	}
	res, err := h.decisions.Reject(r.Context(), tenantID, confirmActor(r.Context()), req.app())
	if err != nil {
		h.decisionError(w, "Addresses", err)
		return
	}
	h.decisionAudit(r, auditapp.NewSuccessEvent(auditdom.ActionEASMAddressesRejected, auditdom.ResourceTypeAsset, "").
		WithMessage("Addresses marked not the organization's from the Decisions card").
		WithMetadata("items", strings.Join(res.Addresses, ",")).
		WithMetadata("asset_ids", strings.Join(res.AssetIDs, ",")).
		WithMetadata("count", len(res.AssetIDs)))
	writeDecisionJSON(w, res)
}

// RetryAddressLookup handles POST /api/v1/easm/suggestions/addresses/lookup
// @Summary      Look up the network of addresses again
// @Description  Makes the network lookup (lookup.asn) of chosen addresses of the caller's own addresses card due now, for the addresses whose network is still unknown. The coverage loop sends the lookups to a sensor; the platform itself looks nothing up. Every address and group must be on the card (400 DECISION_NOT_PENDING otherwise); a lookup already queued is left alone. One audit event lists the addresses.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      EASMAddressSelection  true  "Addresses, groups or every waiting address"
// @Success      200   {object}  easmapp.LookupRetryResult
// @Failure      400   {object}  apierror.Error
// @Router       /easm/suggestions/addresses/lookup [post]
func (h *EASMHandler) RetryAddressLookup(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.decisionTenant(w, r)
	if !ok {
		return
	}
	var req EASMAddressSelection
	if !decodeDecision(w, r, &req) {
		return
	}
	res, err := h.decisions.RetryLookup(r.Context(), tenantID, req.app())
	if err != nil {
		h.decisionError(w, "Addresses", err)
		return
	}
	h.decisionAudit(r, auditapp.NewSuccessEvent(auditdom.ActionEASMAddressLookupRetried, auditdom.ResourceTypeAsset, "").
		WithMessage("Network lookup asked again from the Decisions card").
		WithMetadata("items", strings.Join(res.Addresses, ",")).
		WithMetadata("queued", res.Queued))
	writeDecisionJSON(w, res)
}

func (h *EASMHandler) networkAnswer(w http.ResponseWriter, r *http.Request) (shared.ID, string, bool) {
	tenantID, ok := h.decisionTenant(w, r)
	if !ok {
		return shared.ID{}, "", false
	}
	limitBody(w, r)
	var req EASMNetworkAnswerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Key) == "" || len(req.Key) > 300 {
		apierror.BadRequest("key is required").WriteJSON(w)
		return shared.ID{}, "", false
	}
	return tenantID, req.Key, true
}

// NetworkIsOurs handles POST /api/v1/easm/suggestions/networks/ours
// @Summary      Answer "this network is ours"
// @Description  Records the network of one group of the caller's addresses card (its AS, or its holder's name when it has no AS) as a network seed of the organization. The group must ask the question on the card (400 NETWORK_NOT_ASKED). With the address setting on, the addresses the seed makes strong are added at once through the approval policy (auto_added); the others stay on the card with their evidence. Needs a recent re-authentication. Audited; undo by removing the seed.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      EASMNetworkAnswerRequest  true  "The group"
// @Success      200   {object}  easmapp.NetworkAnswerResult
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Router       /easm/suggestions/networks/ours [post]
func (h *EASMHandler) NetworkIsOurs(w http.ResponseWriter, r *http.Request) {
	tenantID, key, ok := h.networkAnswer(w, r)
	if !ok {
		return
	}
	res, err := h.decisions.NetworkIsOurs(r.Context(), tenantID, confirmActor(r.Context()), key)
	if err != nil {
		h.decisionError(w, "Network", err)
		return
	}
	h.decisionAudit(r, auditapp.NewSuccessEvent(auditdom.ActionEASMNetworkSeedAdded, auditdom.ResourceTypeEASMNetworkSeed, res.SeedID).
		WithResourceName(res.Value).
		WithMessage("Network seed added from the Decisions card: the organization said the network is its own").
		WithMetadata("kind", res.Kind).
		WithMetadata("auto_added", res.AutoAdded).
		WithMetadata("via", "decisions_card"))
	writeDecisionJSON(w, res)
}

// NetworkNotOurs handles POST /api/v1/easm/suggestions/networks/not-ours
// @Summary      Answer "this network is not ours"
// @Description  Records the network of one group of the caller's addresses card as not the organization's and marks the group's addresses not its own; addresses in that network are no longer offered and the question is not asked again. The group must ask the question (400 NETWORK_NOT_ASKED). Audited; undo with DELETE /easm/suggestions/declined-networks/{id} and the rejection's undo.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      EASMNetworkAnswerRequest  true  "The group"
// @Success      200   {object}  easmapp.NetworkAnswerResult
// @Failure      400   {object}  apierror.Error
// @Router       /easm/suggestions/networks/not-ours [post]
func (h *EASMHandler) NetworkNotOurs(w http.ResponseWriter, r *http.Request) {
	tenantID, key, ok := h.networkAnswer(w, r)
	if !ok {
		return
	}
	res, err := h.decisions.NetworkNotOurs(r.Context(), tenantID, confirmActor(r.Context()), key)
	if err != nil {
		h.decisionError(w, "Network", err)
		return
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionEASMNetworkDeclined, auditdom.ResourceTypeEASMNetworkSeed, res.DeclinedID).
		WithResourceName(res.Value).
		WithMessage("Network marked not the organization's from the Decisions card").
		WithMetadata("kind", res.Kind)
	if res.Rejected != nil {
		ev = ev.WithMetadata("items", strings.Join(res.Rejected.Addresses, ",")).
			WithMetadata("asset_ids", strings.Join(res.Rejected.AssetIDs, ","))
	}
	h.decisionAudit(r, ev)
	writeDecisionJSON(w, res)
}

// UndeclineNetwork handles DELETE /api/v1/easm/suggestions/declined-networks/{id}
// @Summary      Undo "this network is not ours"
// @Description  Removes one of the organization's "not ours" network answers: the question is asked again. The addresses it marked stay rejected until undone on their own. Audited.
// @Tags         Attack Surface
// @Security     BearerAuth
// @Param        id   path  string  true  "Declined network ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /easm/suggestions/declined-networks/{id} [delete]
func (h *EASMHandler) UndeclineNetwork(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.decisionTenant(w, r)
	if !ok {
		return
	}
	d, err := h.decisions.Undecline(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.decisionError(w, "Declined network", err)
		return
	}
	h.decisionAudit(r, auditapp.NewSuccessEvent(auditdom.ActionEASMNetworkDeclineUndone, auditdom.ResourceTypeEASMNetworkSeed, d.ID).
		WithResourceName(d.Value).
		WithMessage("Network \"not ours\" answer removed").
		WithMetadata("kind", string(d.Kind)))
	w.WriteHeader(http.StatusNoContent)
}
