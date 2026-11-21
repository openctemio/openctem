package handler

// The Scope page's provider addresses card (docs/architecture/
// provider-shared-addresses.md): GET /api/v1/scope/provider-addresses, and
// per provider POST .../move (out of scope; preview first) and POST
// .../keep (keep scanning; step-up).

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	auditsvc "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/scope"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
)

// ScopeProviderEntryResponse is one scope entry on a provider's shared
// addresses.
type ScopeProviderEntryResponse struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	Pattern    string    `json:"pattern"`
	Origin     string    `json:"origin"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

// ScopeProviderConfirmedResponse is an address a person confirmed as the
// organization's that lies inside a provider's shared range.
type ScopeProviderConfirmedResponse struct {
	AssetID   string     `json:"asset_id"`
	Name      string     `json:"name"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
}

// ScopeProviderGroupResponse is one provider's row of the card.
type ScopeProviderGroupResponse struct {
	Provider string `json:"provider"`
	// Class: edge, saas_hosting or cloud_shared.
	Class string `json:"class" enums:"edge,saas_hosting,cloud_shared"`
	// EntryCount is len(Entries): the entries a move or a keep acts on.
	EntryCount int                              `json:"entry_count"`
	Entries    []ScopeProviderEntryResponse     `json:"entries"`
	Confirmed  []ScopeProviderConfirmedResponse `json:"confirmed"`
}

// ScopeProviderAddressesResponse is the card.
type ScopeProviderAddressesResponse struct {
	// DatasetVersion is the version of the provider range list used.
	DatasetVersion string `json:"dataset_version"`
	// Holding: the organization's hold_provider_entries setting is on, so
	// the listed entries authorize no active check until answered.
	Holding bool                         `json:"holding"`
	Groups  []ScopeProviderGroupResponse `json:"groups"`
}

// ScopeProviderActionRequest names the provider a card action applies to.
type ScopeProviderActionRequest struct {
	Provider string `json:"provider" validate:"required,max=100"`
	// Preview (move only): answer the counts and change nothing.
	Preview bool `json:"preview,omitempty"`
}

// ScopeProviderMoveResponse is what a move did, or would do.
type ScopeProviderMoveResponse struct {
	Provider string `json:"provider"`
	Preview  bool   `json:"preview"`
	// Entries moved; Exclusions created; Existing: entries whose
	// exclusion already existed (only the entry is deactivated).
	Entries      int      `json:"entries"`
	Exclusions   int      `json:"exclusions"`
	Existing     int      `json:"existing"`
	EntryIDs     []string `json:"entry_ids"`
	ExclusionIDs []string `json:"exclusion_ids"`
}

// ScopeProviderKeepResponse is the entries kept.
type ScopeProviderKeepResponse struct {
	Provider string                       `json:"provider"`
	Kept     []ScopeProviderEntryResponse `json:"kept"`
}

func providerEntryResponse(e scope.ProviderEntry) ScopeProviderEntryResponse {
	return ScopeProviderEntryResponse{ID: e.ID, TargetType: e.TargetType, Pattern: e.Pattern, Origin: e.Origin,
		Status: e.Status, CreatedAt: e.CreatedAt}
}

// ListProviderAddresses handles GET /api/v1/scope/provider-addresses
// @Summary      Scope entries on provider shared addresses
// @Description  Per provider, the organization's in-effect address, CIDR and range scope entries that lie wholly inside a range the provider publishes for infrastructure many organizations share, and that nobody answered yet; plus the addresses a person confirmed as the organization's inside such a range (within the caller's data scope). An empty list means there is nothing to decide.
// @Tags         Scope
// @Produce      json
// @Success      200  {object}  ScopeProviderAddressesResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/provider-addresses [get]
func (h *ScopeHandler) ListProviderAddresses(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	card, err := h.service.ProviderAddresses(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, "Provider addresses", err)
		return
	}
	out := ScopeProviderAddressesResponse{DatasetVersion: card.DatasetVersion, Holding: card.Holding,
		Groups: make([]ScopeProviderGroupResponse, 0, len(card.Groups))}
	for _, g := range card.Groups {
		gr := ScopeProviderGroupResponse{Provider: g.Provider, Class: g.Class, EntryCount: len(g.Entries),
			Entries:   make([]ScopeProviderEntryResponse, 0, len(g.Entries)),
			Confirmed: make([]ScopeProviderConfirmedResponse, 0, len(g.Confirmed))}
		for _, e := range g.Entries {
			gr.Entries = append(gr.Entries, providerEntryResponse(e))
		}
		for _, c := range g.Confirmed {
			gr.Confirmed = append(gr.Confirmed, ScopeProviderConfirmedResponse{AssetID: c.AssetID, Name: c.Name, DecidedAt: c.DecidedAt})
		}
		out.Groups = append(out.Groups, gr)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// providerError answers a card action's error: an unknown provider (or one
// with nothing left to answer, another organization's included) is 404 with
// its code; anything else as every scope change.
func (h *ScopeHandler) providerError(w http.ResponseWriter, err error) {
	if errors.Is(err, scope.ErrProviderUnknown) {
		apierror.New(http.StatusNotFound, apierror.Code(scope.CodeProviderNotListed),
			"No scope entry of this provider is waiting for an answer").WriteJSON(w)
		return
	}
	h.handleServiceError(w, "Provider addresses", err)
}

func (h *ScopeHandler) providerActionRequest(w http.ResponseWriter, r *http.Request) (ScopeProviderActionRequest, bool) {
	var req ScopeProviderActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return req, false
	}
	req.Provider = strings.TrimSpace(req.Provider)
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return req, false
	}
	return req, true
}

// MoveProviderAddresses handles POST /api/v1/scope/provider-addresses/move
// @Summary      Move a provider's shared addresses out of scope
// @Description  Every listed scope entry of the provider becomes a do_not_scan exclusion of the same pattern (its origin kept) and the entry is deactivated, in one transaction. The exclusion stays on the addresses: names that resolve to them stay in scope. Narrowing needs attack_surface:scope:write and no re-authentication. With preview true nothing changes and the counts are answered. Audited (each exclusion and entry, and one summary event with the counts and ids). 404 when no entry of that provider waits for an answer.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      ScopeProviderActionRequest  true  "The provider"
// @Success      200   {object}  ScopeProviderMoveResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/provider-addresses/move [post]
func (h *ScopeHandler) MoveProviderAddresses(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	req, ok := h.providerActionRequest(w, r)
	if !ok {
		return
	}
	res, err := h.service.MoveProviderOutOfScope(r.Context(), scope.ProviderMoveInput{
		TenantID: tenantID, Provider: req.Provider, Actor: middleware.GetUserID(r.Context()), Preview: req.Preview,
	})
	if err != nil {
		h.providerError(w, err)
		return
	}
	out := ScopeProviderMoveResponse{Provider: res.Provider, Preview: res.Preview, Entries: res.Entries,
		Exclusions: res.Exclusions, Existing: res.Existing, EntryIDs: []string{}, ExclusionIDs: []string{}}
	for _, m := range res.Moved {
		out.EntryIDs = append(out.EntryIDs, m.After.ID().String())
		switch {
		case m.Exclusion != nil:
			out.ExclusionIDs = append(out.ExclusionIDs, m.Exclusion.ID().String())
		case m.ExistingID != "":
			out.ExclusionIDs = append(out.ExclusionIDs, m.ExistingID)
		}
		if res.Preview {
			continue
		}
		if m.Exclusion != nil {
			h.auditExclusion(r, audit.ActionScopeExclusionCreated, m.Exclusion.ID().String(), nil, m.Exclusion)
		}
		h.auditTarget(r, audit.ActionScopeTargetDeactivated, m.After.ID().String(), m.Before, m.After)
	}
	if !res.Preview {
		event := auditsvc.NewSuccessEvent(audit.ActionScopeProviderMoved, audit.ResourceTypeTenant, tenantID).
			WithResourceName(res.Provider).
			WithMessage("Scope entries on a provider's shared addresses moved out of scope").
			WithMetadata("provider", res.Provider).
			WithMetadata("entries", res.Entries).
			WithMetadata("exclusions_created", res.Exclusions).
			WithMetadata("exclusions_existing", res.Existing).
			WithMetadata("entry_ids", out.EntryIDs).
			WithMetadata("exclusion_ids", out.ExclusionIDs)
		logRequestChange(h.audit, h.logger, r, event)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// KeepProviderAddresses handles POST /api/v1/scope/provider-addresses/keep
// @Summary      Keep scanning a provider's shared addresses
// @Description  Records the organization's decision to keep the provider's listed scope entries: they leave the card and are never held by the hold_provider_entries setting. Testing a provider's shared infrastructure follows the provider's rules. Needs attack_surface:scope:write and a recent re-authentication (403 STEP_UP_REQUIRED). Audited at high severity with the entry ids. 404 when no entry of that provider waits for an answer.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      ScopeProviderActionRequest  true  "The provider"
// @Success      200   {object}  ScopeProviderKeepResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/provider-addresses/keep [post]
func (h *ScopeHandler) KeepProviderAddresses(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	req, ok := h.providerActionRequest(w, r)
	if !ok {
		return
	}
	res, err := h.service.KeepProviderScanning(r.Context(), scope.ProviderKeepInput{
		TenantID: tenantID, Provider: req.Provider, Actor: scope.Actor{UserID: middleware.GetUserID(r.Context())},
	})
	if err != nil {
		h.providerError(w, err)
		return
	}
	out := ScopeProviderKeepResponse{Provider: res.Provider, Kept: make([]ScopeProviderEntryResponse, 0, len(res.Kept))}
	ids := make([]string, 0, len(res.Kept))
	for _, e := range res.Kept {
		out.Kept = append(out.Kept, providerEntryResponse(e))
		ids = append(ids, e.ID)
	}
	event := auditsvc.NewSuccessEvent(audit.ActionScopeProviderKept, audit.ResourceTypeTenant, tenantID).
		WithResourceName(res.Provider).
		WithMessage("Scope entries on a provider's shared addresses kept in scope").
		WithSeverity(audit.SeverityHigh).
		WithMetadata("provider", res.Provider).
		WithMetadata("entries", len(ids)).
		WithMetadata("entry_ids", ids)
	logRequestChange(h.audit, h.logger, r, event)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
