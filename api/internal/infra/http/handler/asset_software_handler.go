package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/vulnmatch"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetSoftwareLister lists an asset's software with its matched CVEs.
type AssetSoftwareLister interface {
	AssetSoftware(ctx context.Context, tenantID, assetID shared.ID) ([]vulnmatch.SoftwareItem, error)
}

// AssetSoftwareHandler serves GET /api/v1/assets/{id}/software (RFC-066):
// what the asset runs and the CVEs its versions fall in.
type AssetSoftwareHandler struct {
	svc       AssetSoftwareLister
	assets    asset.Repository
	dataScope DataScopeEnforcer
	logger    *logger.Logger
}

// NewAssetSoftwareHandler creates the handler.
func NewAssetSoftwareHandler(svc AssetSoftwareLister, assets asset.Repository, log *logger.Logger) *AssetSoftwareHandler {
	return &AssetSoftwareHandler{svc: svc, assets: assets, logger: log}
}

// SetDataScope wires the Layer 2 data scope. Returns h for chaining.
func (h *AssetSoftwareHandler) SetDataScope(e DataScopeEnforcer) *AssetSoftwareHandler {
	h.dataScope = e
	return h
}

// AssetSoftwareMatchResponse is one CVE matched to a software item.
type AssetSoftwareMatchResponse struct {
	CVEID       string   `json:"cve_id"`
	Severity    string   `json:"severity,omitempty"`
	CVSSScore   *float64 `json:"cvss_score,omitempty"`
	InKEV       bool     `json:"in_kev"`
	EPSS        float64  `json:"epss"`
	Confidence  int      `json:"confidence"`
	Label       string   `json:"label"`
	Range       string   `json:"range"`
	Reasons     []string `json:"reasons"`
	AllVersions bool     `json:"all_versions"`
	InPolicy    bool     `json:"in_policy"`
}

// AssetSoftwareResponse is one product the asset runs.
type AssetSoftwareResponse struct {
	ID         string                       `json:"id"`
	Product    string                       `json:"product"`
	Vendor     string                       `json:"vendor,omitempty"`
	CPE        string                       `json:"cpe,omitempty"`
	Known      bool                         `json:"known"`
	Version    string                       `json:"version"`
	Qualifier  string                       `json:"qualifier,omitempty"`
	Location   string                       `json:"location,omitempty"`
	Port       int                          `json:"port,omitempty"`
	Transport  string                       `json:"transport,omitempty"`
	Source     string                       `json:"source"`
	Evidence   string                       `json:"evidence,omitempty"`
	Confidence int                          `json:"confidence"`
	FirstSeen  time.Time                    `json:"first_seen_at"`
	LastSeen   time.Time                    `json:"last_seen_at"`
	Stale      bool                         `json:"stale"`
	Matches    []AssetSoftwareMatchResponse `json:"matches"`
}

// AssetSoftwareListResponse is the list.
type AssetSoftwareListResponse struct {
	Data []AssetSoftwareResponse `json:"data"`
}

// List handles GET /api/v1/assets/{id}/software.
// @Summary      List the software an asset runs
// @Description  The products and versions scans saw on the asset, each with the CVEs its version falls in (RFC-066): the match confidence, label (likely/potential), the range used and whether the organization's policy makes it a finding. An asset outside the caller's data scope answers 404.
// @Tags         Assets
// @Produce      json
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetSoftwareListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /assets/{id}/software [get]
func (h *AssetSoftwareHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.GetTenantID(ctx))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	assetID, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}
	// The asset must be the tenant's and in the caller's data scope; both
	// misses answer the same 404.
	if _, err := h.assets.GetByID(ctx, tenantID, assetID); err != nil || !assetInDataScope(ctx, h.dataScope, tenantID, assetID) {
		apierror.NotFound("Asset").WriteJSON(w)
		return
	}
	items, err := h.svc.AssetSoftware(ctx, tenantID, assetID)
	if err != nil {
		h.logger.Error("asset software", "error", err)
		apierror.InternalServerError("Failed to list software").WriteJSON(w)
		return
	}
	out := AssetSoftwareListResponse{Data: make([]AssetSoftwareResponse, 0, len(items))}
	for _, it := range items {
		l := it.Link
		resp := AssetSoftwareResponse{
			ID: l.ID.String(), Product: l.Product, Vendor: l.Vendor, CPE: l.CPE, Known: l.Global,
			Version: l.Version, Qualifier: l.Qualifier, Location: l.Location, Port: l.Port, Transport: l.Transport,
			Source: l.Source, Evidence: l.Evidence, Confidence: l.Confidence,
			FirstSeen: l.FirstSeen, LastSeen: l.LastSeen, Stale: it.Stale,
			Matches: make([]AssetSoftwareMatchResponse, 0, len(it.Matches)),
		}
		for _, m := range it.Matches {
			reasons := m.Reasons
			if reasons == nil {
				reasons = []string{}
			}
			resp.Matches = append(resp.Matches, AssetSoftwareMatchResponse{
				CVEID: m.CVEID, Severity: m.Severity, CVSSScore: m.CVSSScore, InKEV: m.InKEV, EPSS: m.EPSS,
				Confidence: m.Confidence, Label: string(m.Label), Range: m.Range, Reasons: reasons,
				AllVersions: m.AllVersions, InPolicy: m.InPolicy,
			})
		}
		out.Data = append(out.Data, resp)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
