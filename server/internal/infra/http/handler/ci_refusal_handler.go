package handler

// Why CI tokens were refused, for the organization's administrators, and the
// one-step fixes. Design: docs/architecture/ci-runner-identity.md
// ("Refusal reasons").

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	cirunapp "github.com/openctemio/openctem/server/internal/app/cirun"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// CIRefusalActions lists the refusals before verification and adds a refused
// value to a trust configuration.
type CIRefusalActions interface {
	UnverifiedRefusals(ctx context.Context, tenantID shared.ID) ([]cirun.UnverifiedRefusal, []cirun.TrustConfig, error)
	AllowInTrustConfig(ctx context.Context, tenantID, id, refusalID shared.ID, a cirunapp.Actor) (*cirun.TrustConfig, cirunapp.Allowed, bool, error)
}

// SetRefusalActions wires the unverified refusals and the allow action (nil
// answers 503).
func (h *CIAdminHandler) SetRefusalActions(svc CIRefusalActions) { h.refusalActions = svc }

// CIConfiguredIssuer is one trust configuration's issuer.
type CIConfiguredIssuer struct {
	ConfigID string `json:"config_id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Issuer   string `json:"issuer"`
	Enabled  bool   `json:"enabled"`
}

// CIUnverifiedRefusalResponse is one record of exchanges refused before the
// token verified.
type CIUnverifiedRefusalResponse struct {
	// Issuer the token claimed (empty when it was not a plain https address).
	Issuer string `json:"issuer"`
	// Reason: no_configuration (no enabled trust configuration has this
	// issuer), keys_unavailable (the issuer's signing keys could not be
	// fetched; cause says why), not_verified (signature, audience or expiry).
	Reason string `json:"reason"`
	// Cause (keys_unavailable): blocked_address, dns, tls, timeout,
	// issuer_mismatch, http_status, key_not_found, unreachable. Never an
	// address.
	Cause     string    `json:"cause,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
	// NearestIssuer is the configured issuer closest to the token's, and
	// Difference how they differ (trailing_slash, case, scheme, host, path),
	// for no_configuration.
	NearestIssuer string `json:"nearest_issuer,omitempty"`
	Difference    string `json:"difference,omitempty"`
}

// CIUnverifiedRefusalsResponse lists the records with the configured
// issuers to compare against.
type CIUnverifiedRefusalsResponse struct {
	Data              []CIUnverifiedRefusalResponse `json:"data"`
	ConfiguredIssuers []CIConfiguredIssuer          `json:"configured_issuers"`
}

// ListUnverifiedRefusals handles GET /api/v1/ci/trust-refusals/unverified
// @Summary      List CI tokens refused before verification
// @Description  Per issuer and reason, the CI token exchanges refused before the token verified (no enabled trust configuration for its issuer, the issuer's keys unavailable with the cause class, a token that did not verify): issuer, reason, cause, first and last time, count. No token contents. At most 20, newest first, with the organization's configured issuers and, for an unknown issuer, the nearest configured one and how they differ.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  CIUnverifiedRefusalsResponse
// @Router       /ci/trust-refusals/unverified [get]
func (h *CIAdminHandler) ListUnverifiedRefusals(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.refusalActions == nil {
		apierror.ServiceUnavailable("CI refusals are not available").WriteJSON(w)
		return
	}
	list, configs, err := h.refusalActions.UnverifiedRefusals(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "list unverified CI refusals", "CI refusals")
		return
	}
	resp := CIUnverifiedRefusalsResponse{Data: make([]CIUnverifiedRefusalResponse, 0, len(list)),
		ConfiguredIssuers: make([]CIConfiguredIssuer, 0, len(configs))}
	issuers := make([]string, 0, len(configs))
	for _, c := range configs {
		resp.ConfiguredIssuers = append(resp.ConfiguredIssuers, CIConfiguredIssuer{ConfigID: c.ID.String(), Name: c.Name,
			Provider: string(c.Provider), Issuer: c.Issuer, Enabled: c.Enabled})
		issuers = append(issuers, c.Issuer)
	}
	for _, u := range list {
		item := CIUnverifiedRefusalResponse{Issuer: u.Issuer, Reason: u.Reason, Cause: u.Cause, FirstSeen: u.FirstSeen,
			LastSeen: u.LastSeen, Count: u.Count}
		if u.Issuer != "" {
			item.NearestIssuer, item.Difference = cirunapp.NearestIssuer(u.Issuer, issuers)
		}
		resp.Data = append(resp.Data, item)
	}
	ciWriteJSON(w, http.StatusOK, resp)
}

// CIAllowRequest names the refusal whose value is added.
type CIAllowRequest struct {
	// RefusalID is the id of a refused exchange (GET /ci/trust-refusals,
	// data[].id) that this configuration refused with workflow_not_allowed
	// or ref_not_allowed. The value comes from that record.
	RefusalID string `json:"refusal_id"`
}

// CIAllowResponse is the configuration after the change.
type CIAllowResponse struct {
	// Changed is false when the value was already listed.
	Changed bool `json:"changed"`
	// Kind (workflow_ref or ref) and Value are what was added.
	Kind   string                `json:"kind"`
	Value  string                `json:"value"`
	Config CITrustConfigResponse `json:"config"`
}

// AllowInTrustConfig handles POST /api/v1/ci/trust-configs/{id}/allow
// @Summary      Add a refused value to a CI trust configuration
// @Description  Adds the value a refused token carried to the configuration that refused it: the refusal (refusal_id from GET /ci/trust-refusals) must be this organization's and this configuration's refusal with workflow_not_allowed (its pipeline definition joins Pipeline definitions) or ref_not_allowed (its branch or tag joins Branches and tags). The value is read from the refusal record, never from the request. The same permission (ci:write), recent sign-in and audit (CI trust configuration changed, before and after) as changing the configuration. A value already listed changes nothing.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Trust configuration ID"
// @Param        body body CIAllowRequest true "Value"
// @Success      200  {object}  CIAllowResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /ci/trust-configs/{id}/allow [post]
func (h *CIAdminHandler) AllowInTrustConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.refusalActions == nil {
		apierror.ServiceUnavailable("CI trust configuration changes are not available").WriteJSON(w)
		return
	}
	id, ok := pathID(w, r, "CI trust configuration")
	if !ok {
		return
	}
	limitBody(w, r)
	var req CIAllowRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	refusalID, err := shared.IDFromString(req.RefusalID)
	if err != nil {
		apierror.BadRequest("refusal_id must be the id of a refused CI token exchange").WriteJSON(w)
		return
	}
	c, allowed, changed, err := h.refusalActions.AllowInTrustConfig(r.Context(), tenantID, id, refusalID, h.actor(r))
	if err != nil {
		if errors.Is(err, cirunapp.ErrAllowNotApplicable) {
			apierror.BadRequest("Only a pipeline definition or a branch or tag that this trust configuration refused can be added from a refusal; edit the configuration for anything else").WriteJSON(w)
			return
		}
		h.writeErr(w, err, "change trust configuration", "CI trust configuration")
		return
	}
	resp := toCITrustResponse(c)
	h.withScope(r.Context(), tenantID, &resp)
	ciWriteJSON(w, http.StatusOK, CIAllowResponse{Changed: changed, Kind: allowed.Kind, Value: allowed.Value, Config: resp})
}
