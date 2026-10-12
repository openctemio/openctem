package handler

// Asset source precedence settings (RFC-069 §12): a ranked list of sources
// per attribute class, a default list the classes inherit, the sources the
// organization has, and a preview of what a change would do.

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// SourceRuleDTO is one row of a ranked list.
type SourceRuleDTO struct {
	// Source is a kind (integration, import, scan, feed) or one source of a
	// kind ("scan:nmap"). A person's lock always wins and is never listed.
	Source string `json:"source" example:"integration"`
	// TTLDays: how long the source's value counts after it saw it; 0 = never stale.
	TTLDays int `json:"ttl_days" example:"30"`
	// Trusted: the source may decide the class.
	Trusted bool `json:"trusted" example:"true"`
}

// AssetSourcePolicyDTO is a complete policy: the default list and the
// classes with their own list.
type AssetSourcePolicyDTO struct {
	Default []SourceRuleDTO            `json:"default"`
	Classes map[string][]SourceRuleDTO `json:"classes"`
}

// AssetSourceSummaryDTO is a source that reported the organization's assets.
type AssetSourceSummaryDTO struct {
	Kind     string    `json:"kind" example:"scan"`
	Name     string    `json:"name" example:"nmap"`
	LastSeen time.Time `json:"last_seen"`
	Assets   int       `json:"assets" example:"12"`
}

// AssetAttributeClassDTO is an attribute class and the reconciled
// attributes in it (empty when none is reconciled yet).
type AssetAttributeClassDTO struct {
	Class      string   `json:"class" example:"ownership"`
	Attributes []string `json:"attributes"`
}

// AssetReconciliationSettingsResponse is the organization's settings, the
// policy in effect, the built-in defaults, the classes and the sources seen.
type AssetReconciliationSettingsResponse struct {
	// Saved is what the organization stored (empty lists: the defaults).
	Saved     AssetSourcePolicyDTO     `json:"saved"`
	Effective AssetSourcePolicyDTO     `json:"effective"`
	Defaults  AssetSourcePolicyDTO     `json:"defaults"`
	Classes   []AssetAttributeClassDTO `json:"classes"`
	Sources   []AssetSourceSummaryDTO  `json:"sources"`
}

// UpdateAssetReconciliationRequest replaces the settings. A class left out
// of classes inherits default. Demoting a connector source needs step-up
// re-authentication (403 STEP_UP_REQUIRED, then retry).
type UpdateAssetReconciliationRequest struct {
	Default []SourceRuleDTO            `json:"default"`
	Classes map[string][]SourceRuleDTO `json:"classes"`
}

// PreviewAssetReconciliationRequest is a policy to try, on one asset or on
// the organization's assets.
type PreviewAssetReconciliationRequest struct {
	Default []SourceRuleDTO            `json:"default"`
	Classes map[string][]SourceRuleDTO `json:"classes"`
	AssetID string                     `json:"asset_id,omitempty"`
}

// AssetPreviewChangeDTO is a value the policy would change.
type AssetPreviewChangeDTO struct {
	AssetID    string `json:"asset_id"`
	AssetName  string `json:"asset_name"`
	Attribute  string `json:"attribute" example:"criticality"`
	Current    string `json:"current" example:"high"`
	Next       string `json:"next" example:"medium"`
	NextSource string `json:"next_source" example:"import:cmdb-export"`
	Conflict   bool   `json:"conflict"`
}

// AssetReconciliationPreviewResponse is what the policy would change.
type AssetReconciliationPreviewResponse struct {
	ScannedAssets int                     `json:"scanned_assets"`
	Truncated     bool                    `json:"truncated"`
	ChangedAssets int                     `json:"changed_assets"`
	ChangedValues int                     `json:"changed_values"`
	Conflicts     int                     `json:"conflicts"`
	Samples       []AssetPreviewChangeDTO `json:"samples"`
}

func rulesToDTO(rules []asset.SourceRuleSetting) []SourceRuleDTO {
	out := make([]SourceRuleDTO, 0, len(rules))
	for _, r := range rules {
		out = append(out, SourceRuleDTO(r))
	}
	return out
}

func rulesFromDTO(rules []SourceRuleDTO) []asset.SourceRuleSetting {
	out := make([]asset.SourceRuleSetting, 0, len(rules))
	for _, r := range rules {
		out = append(out, asset.SourceRuleSetting(r))
	}
	return out
}

func settingsFromDTO(def []SourceRuleDTO, classes map[string][]SourceRuleDTO) tenant.AssetReconciliationSettings {
	s := tenant.AssetReconciliationSettings{}
	if len(def) > 0 {
		s.Default = rulesFromDTO(def)
	}
	if len(classes) > 0 {
		s.Classes = map[string][]asset.SourceRuleSetting{}
		for c, list := range classes {
			s.Classes[c] = rulesFromDTO(list)
		}
	}
	return s
}

func savedToDTO(s tenant.AssetReconciliationSettings) AssetSourcePolicyDTO {
	out := AssetSourcePolicyDTO{Default: rulesToDTO(s.Default), Classes: map[string][]SourceRuleDTO{}}
	for c, list := range s.Classes {
		out.Classes[c] = rulesToDTO(list)
	}
	return out
}

func policyToDTO(p asset.ReconciliationPolicy) AssetSourcePolicyDTO {
	out := AssetSourcePolicyDTO{Default: rulesToDTO(asset.SettingsFromRules(p.Default)), Classes: map[string][]SourceRuleDTO{}}
	for c, rules := range p.Classes {
		out.Classes[string(c)] = rulesToDTO(asset.SettingsFromRules(rules))
	}
	return out
}

func (h *TenantHandler) toAssetReconciliationResponse(r *http.Request, tenantID shared.ID, s tenant.AssetReconciliationSettings) AssetReconciliationSettingsResponse {
	eff, err := s.Policy()
	if err != nil {
		eff = asset.DefaultReconciliationPolicy()
	}
	out := AssetReconciliationSettingsResponse{
		Saved: savedToDTO(s), Effective: policyToDTO(eff), Defaults: policyToDTO(asset.DefaultReconciliationPolicy()),
		Classes: []AssetAttributeClassDTO{}, Sources: []AssetSourceSummaryDTO{},
	}
	for _, c := range asset.AllAttributeClasses() {
		attrs := []string{}
		for _, a := range c.Attributes() {
			attrs = append(attrs, string(a))
		}
		out.Classes = append(out.Classes, AssetAttributeClassDTO{Class: string(c), Attributes: attrs})
	}
	if h.assetService != nil {
		sums, err := h.assetService.AttributeSourceSummaries(r.Context(), tenantID)
		if err != nil {
			h.logger.Warn("asset source summaries unavailable", "error", err)
		}
		for _, s := range sums {
			out.Sources = append(out.Sources, AssetSourceSummaryDTO{Kind: string(s.Kind), Name: s.Name, LastSeen: s.LastSeen, Assets: s.Assets})
		}
	}
	return out
}

// GetAssetReconciliationSettings handles GET /api/v1/organization/settings/asset-reconciliation
// @Summary      Asset source precedence
// @Description  The ranked sources per attribute class (identity, network, software, ownership, cloud_tags, lifecycle), the default list classes inherit, each source's TTL and trust, the built-in defaults, and the sources that reported the organization's assets with when they last did.
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
	_ = json.NewEncoder(w).Encode(h.toAssetReconciliationResponse(r, tenantID, *s))
}

// UpdateAssetReconciliationSettings handles PUT /api/v1/organization/settings/asset-reconciliation
// @Summary      Update asset source precedence
// @Description  Replaces the settings. Sources are integration, import, scan, feed, or kind:name for one source; a source without a row, or not trusted, does not decide the class; a person's lock always wins. TTL days 0-3650, 0 = never stale. Demoting a connector (integration) source needs step-up re-authentication. The organization's assets are re-resolved in the background; changed values get a timeline event.
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
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	var req UpdateAssetReconciliationRequest
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	saved, err := h.service.UpdateAssetReconciliationSettings(settingsWriteCtx(r), tenantID.String(),
		settingsFromDTO(req.Default, req.Classes), h.buildAuditContext(r))
	if err != nil {
		if writeStepUpError(w, err) {
			return
		}
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetReconciliation)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.toAssetReconciliationResponse(r, tenantID, *saved))
}

// PreviewAssetReconciliationSettings handles POST /api/v1/organization/settings/asset-reconciliation/preview
// @Summary      Preview asset source precedence
// @Description  What a policy would change before it is saved: on one asset (asset_id) or on the organization's assets with a recorded source (at most 5000; truncated says more exist). Counts of changed assets and values, conflicts, and up to 25 sample changes. Writes nothing.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      PreviewAssetReconciliationRequest  true  "Policy to try"
// @Success      200  {object}  AssetReconciliationPreviewResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /organization/settings/asset-reconciliation/preview [post]
func (h *TenantHandler) PreviewAssetReconciliationSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, terr := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if terr != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	var req PreviewAssetReconciliationRequest
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	p, err := settingsFromDTO(req.Default, req.Classes).Policy()
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	var assetID *shared.ID
	if req.AssetID != "" {
		id, perr := shared.IDFromString(req.AssetID)
		if perr != nil {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		assetID = &id
	}
	if h.assetService == nil {
		apierror.InternalServerError("preview unavailable").WriteJSON(w)
		return
	}
	pv, err := h.assetService.PreviewReconciliationPolicy(r.Context(), tenantID, p, assetID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	out := AssetReconciliationPreviewResponse{
		ScannedAssets: pv.ScannedAssets, Truncated: pv.Truncated, ChangedAssets: pv.ChangedAssets,
		ChangedValues: pv.ChangedValues, Conflicts: pv.Conflicts, Samples: make([]AssetPreviewChangeDTO, 0, len(pv.Samples)),
	}
	for _, c := range pv.Samples {
		src := string(c.NextSource.Kind)
		if c.NextSource.Name != "" {
			src += ":" + c.NextSource.Name
		}
		out.Samples = append(out.Samples, AssetPreviewChangeDTO{
			AssetID: c.AssetID.String(), AssetName: c.AssetName, Attribute: string(c.Attribute),
			Current: c.Current, Next: c.Next, NextSource: src, Conflict: c.Conflict,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
