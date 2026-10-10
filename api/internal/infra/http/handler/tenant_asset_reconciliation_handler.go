package handler

// Asset source precedence settings (RFC-069).

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// AssetReconciliationPolicyResponse is a complete policy: per attribute the
// trusted source kinds, most trusted first (manual, a person's lock, is
// always first), and per kind the TTL in days (0 = never stale).
type AssetReconciliationPolicyResponse struct {
	Precedence map[string][]string `json:"precedence"`
	TTLDays    map[string]int      `json:"ttl_days"`
}

// AssetReconciliationSettingsResponse is the organization's settings and
// the policy in effect (the settings over the defaults).
type AssetReconciliationSettingsResponse struct {
	Precedence map[string][]string               `json:"precedence"`
	TTLDays    map[string]int                    `json:"ttl_days"`
	Effective  AssetReconciliationPolicyResponse `json:"effective"`
	Defaults   AssetReconciliationPolicyResponse `json:"defaults"`
}

// UpdateAssetReconciliationRequest replaces the settings. An attribute or
// kind left out keeps the default.
type UpdateAssetReconciliationRequest struct {
	Precedence map[string][]string `json:"precedence"`
	TTLDays    map[string]int      `json:"ttl_days"`
}

func toPolicyResponse(p asset.ReconciliationPolicy) AssetReconciliationPolicyResponse {
	out := AssetReconciliationPolicyResponse{Precedence: map[string][]string{}, TTLDays: map[string]int{}}
	for _, attr := range asset.AllTrackedAttributes() {
		kinds := make([]string, 0, len(p.Precedence[attr]))
		for _, k := range p.Precedence[attr] {
			kinds = append(kinds, string(k))
		}
		out.Precedence[string(attr)] = kinds
	}
	for _, k := range asset.AllSourceKinds() {
		if k == asset.SourceKindManual {
			continue
		}
		out.TTLDays[string(k)] = int(p.TTL[k].Hours() / 24)
	}
	return out
}

func toAssetReconciliationResponse(s tenant.AssetReconciliationSettings) AssetReconciliationSettingsResponse {
	eff, err := s.Policy()
	if err != nil {
		eff = asset.DefaultReconciliationPolicy()
	}
	out := AssetReconciliationSettingsResponse{
		Precedence: s.Precedence, TTLDays: s.TTLDays,
		Effective: toPolicyResponse(eff), Defaults: toPolicyResponse(asset.DefaultReconciliationPolicy()),
	}
	if out.Precedence == nil {
		out.Precedence = map[string][]string{}
	}
	if out.TTLDays == nil {
		out.TTLDays = map[string]int{}
	}
	return out
}

// GetAssetReconciliationSettings handles GET /api/v1/organization/settings/asset-reconciliation
// @Summary      Asset source precedence
// @Description  Which sources decide each reconciled asset attribute, and how long a source's value counts after it last reported it.
// @Tags         Tenants
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AssetReconciliationSettingsResponse
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /organization/settings/asset-reconciliation [get]
func (h *TenantHandler) GetAssetReconciliationSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, terr := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if terr != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	s, err := h.service.GetAssetReconciliationSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetReconciliation)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAssetReconciliationResponse(*s))
}

// UpdateAssetReconciliationSettings handles PUT /api/v1/organization/settings/asset-reconciliation
// @Summary      Update asset source precedence
// @Description  Replaces the settings. Kinds are integration, import and scan; a kind left out of an attribute's list is not trusted for it; a person's lock always wins. TTL days 0-3650, 0 = never stale.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      UpdateAssetReconciliationRequest  true  "Settings"
// @Success      200  {object}  AssetReconciliationSettingsResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /organization/settings/asset-reconciliation [put]
func (h *TenantHandler) UpdateAssetReconciliationSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, terr := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if terr != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	var req UpdateAssetReconciliationRequest
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	saved, err := h.service.UpdateAssetReconciliationSettings(settingsWriteCtx(r), tenantID.String(),
		tenant.AssetReconciliationSettings{Precedence: req.Precedence, TTLDays: req.TTLDays}, h.buildAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetReconciliation)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAssetReconciliationResponse(*saved))
}
