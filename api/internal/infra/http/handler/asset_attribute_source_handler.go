package handler

// Asset attribute sources (RFC-069): which source decides each tracked
// attribute of an asset, every source's value, and a person's locks.

import (
	"encoding/json"
	"net/http"
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
)

// AttributeSourceResponse is one source's value of an attribute.
type AttributeSourceResponse struct {
	// Kind is how the value arrived: manual (a person's lock), integration,
	// import or scan.
	Kind string `json:"kind" example:"integration"`
	// Name is the tool, importer, integration or person.
	Name       string    `json:"name" example:"defectdojo"`
	Value      string    `json:"value" example:"high"`
	ObservedAt time.Time `json:"observed_at"`
	IngestedAt time.Time `json:"ingested_at"`
	Confidence int       `json:"confidence" example:"100"`
	// Status: winner, outranked (trusted and fresh, lost on precedence or
	// recency), stale (not reported within its kind's TTL) or untrusted
	// (the organization does not trust this kind for the attribute).
	Status string `json:"status" example:"winner"`
}

// AttributeSourcesResponse is one tracked attribute of an asset.
type AttributeSourcesResponse struct {
	Attribute string `json:"attribute" example:"criticality"`
	// Value is the asset's value.
	Value string `json:"value" example:"high"`
	// Locked: a person set the value and no source changes it until released.
	Locked bool `json:"locked"`
	// Conflict: sources that count report different values.
	Conflict bool `json:"conflict"`
	// DecidedBy is the source whose value the asset shows; null when no
	// source may decide (the value predates source tracking, or every
	// source is stale or untrusted).
	DecidedBy *AttributeSourceResponse  `json:"decided_by"`
	Sources   []AttributeSourceResponse `json:"sources"`
}

// AttributeSourcesListResponse is every tracked attribute of an asset.
type AttributeSourcesListResponse struct {
	Attributes []AttributeSourcesResponse `json:"attributes"`
}

// LockAttributeRequest sets and locks an attribute.
type LockAttributeRequest struct {
	Value string `json:"value" validate:"max=500"`
}

func toAttributeSourcesResponse(v assetapp.AttributeSourcesView) AttributeSourcesResponse {
	out := AttributeSourcesResponse{
		Attribute: string(v.Attribute), Value: v.Value, Locked: v.Locked, Conflict: v.Conflict,
		Sources: make([]AttributeSourceResponse, 0, len(v.Candidates)),
	}
	for _, c := range v.Candidates {
		src := AttributeSourceResponse{
			Kind: string(c.Kind), Name: c.Name, Value: c.Value, ObservedAt: c.ObservedAt,
			IngestedAt: c.IngestedAt, Confidence: c.Confidence, Status: string(c.Status),
		}
		out.Sources = append(out.Sources, src)
		if c.Status == assetdom.CandidateWinner {
			s := src
			out.DecidedBy = &s
		}
	}
	return out
}

// GetAttributeSources handles GET /api/v1/assets/{id}/attribute-sources
// @Summary      Where an asset's values come from
// @Description  For each reconciled attribute (criticality, owner_ref, exposure, data_classification): the asset's value, the source that decides it, every source's value with when it saw it, and whether a person locked it or sources disagree.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AttributeSourcesListResponse
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/attribute-sources [get]
func (h *AssetHandler) GetAttributeSources(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	views, err := h.service.GetAttributeSources(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	out := AttributeSourcesListResponse{Attributes: make([]AttributeSourcesResponse, 0, len(views))}
	for _, v := range views {
		out.Attributes = append(out.Attributes, toAttributeSourcesResponse(v))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// LockAttribute handles PUT /api/v1/assets/{id}/attribute-sources/{attribute}/lock
// @Summary      Set and lock an asset attribute
// @Description  Sets the attribute to the value and locks it: no source changes it until the lock is released. An empty value clears owner_ref or data_classification.
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id         path      string                true  "Asset ID"
// @Param        attribute  path      string                true  "criticality, owner_ref, exposure or data_classification"
// @Param        request    body      LockAttributeRequest  true  "Value"
// @Success      200  {object}  AttributeSourcesResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/attribute-sources/{attribute}/lock [put]
func (h *AssetHandler) LockAttribute(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	var req LockAttributeRequest
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	id, attr := r.PathValue("id"), r.PathValue("attribute")
	v, err := h.service.LockAttribute(r.Context(), tenantID, id, attr, req.Value, middleware.GetUserID(r.Context()))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetUpdated, id, "", "Asset attribute locked",
		map[string]any{"attribute": attr, "changed_fields": []string{attr}})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAttributeSourcesResponse(*v))
}

// ReleaseAttributeLock handles DELETE /api/v1/assets/{id}/attribute-sources/{attribute}/lock
// @Summary      Release an asset attribute lock
// @Description  Removes a person's lock; the attribute is decided by its sources again (the asset keeps its value when no source may decide).
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id         path      string  true  "Asset ID"
// @Param        attribute  path      string  true  "criticality, owner_ref, exposure or data_classification"
// @Success      200  {object}  AttributeSourcesResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/attribute-sources/{attribute}/lock [delete]
func (h *AssetHandler) ReleaseAttributeLock(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id, attr := r.PathValue("id"), r.PathValue("attribute")
	v, err := h.service.ReleaseAttributeLock(r.Context(), tenantID, id, attr, middleware.GetUserID(r.Context()))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetUpdated, id, "", "Asset attribute lock released",
		map[string]any{"attribute": attr, "changed_fields": []string{attr}})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAttributeSourcesResponse(*v))
}
