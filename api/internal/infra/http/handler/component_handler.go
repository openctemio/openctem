package handler

// Software components inventory API. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/sbomexport"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
	"github.com/openctemio/openctem/api/pkg/version"
)

// ComponentHandler serves the software components inventory.
type ComponentHandler struct {
	service    *asset.ComponentService
	sbomImport *asset.SBOMImportService
	validator  *validator.Validator
	logger     *logger.Logger
}

// NewComponentHandler creates a new component handler.
func NewComponentHandler(svc *asset.ComponentService, sbomImport *asset.SBOMImportService, v *validator.Validator, log *logger.Logger) *ComponentHandler {
	return &ComponentHandler{service: svc, sbomImport: sbomImport, validator: v, logger: log}
}

// ComponentListResponse is a page of packages with optional facets.
type ComponentListResponse struct {
	ListResponse[component.Package]
	Facets component.Facets `json:"facets,omitempty"`
}

func (h *ComponentHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Component").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, pagination.ErrInvalid):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("component service error", "error", strings.NewReplacer("\n", " ", "\r", " ").Replace(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
	}
}

func writeComponentJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func listInputFromRequest(r *http.Request) asset.ListComponentsInput {
	q := r.URL.Query()
	return asset.ListComponentsInput{
		TenantID:     middleware.MustGetTenantID(r.Context()),
		Query:        q.Get("q"),
		Ecosystems:   parseQueryArray(q.Get("ecosystem")),
		Licenses:     parseQueryArray(q.Get("license")),
		Severities:   parseQueryArray(q.Get("severity")),
		KEV:          parseQueryBool(q.Get("kev")),
		HasFix:       parseQueryBool(q.Get("has_fix")),
		HasVulns:     parseQueryBool(q.Get("has_vulnerabilities")),
		Relationship: parseQueryArray(q.Get("relationship")),
		Scopes:       parseQueryArray(q.Get("scope")),
		AssetID:      q.Get("asset_id"),
		OwnerID:      q.Get("owner_id"),
		Sort:         q.Get("sort"),
	}
}

// List handles GET /api/v1/components
// @Summary      List software components
// @Description  Packages used by the caller's in-scope assets, one row per package, with versions in use, assets, open findings by severity, KEV, fix availability, licenses and risk. Optional facets.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        q                    query  string  false  "Search name or namespace"
// @Param        ecosystem            query  string  false  "Ecosystems (comma list)"
// @Param        license              query  string  false  "Licenses (comma list)"
// @Param        severity             query  string  false  "Has open findings of severity (comma list: critical,high,medium,low)"
// @Param        kev                  query  bool    false  "Has a known exploited vulnerability"
// @Param        has_fix              query  bool    false  "A fix is known"
// @Param        has_vulnerabilities  query  bool    false  "Has open findings"
// @Param        relationship         query  string  false  "direct, transitive, unknown (comma list)"
// @Param        scope                query  string  false  "runtime, development, test, optional, build, provided (comma list)"
// @Param        asset_id             query  string  false  "Used by this asset"
// @Param        owner_id             query  string  false  "Used by assets this user owns"
// @Param        sort                 query  string  false  "name, assets, versions, risk, vulns, last_seen; prefix - for descending"
// @Param        facets               query  bool    false  "Include facets"
// @Param        page                 query  int     false  "Page"
// @Param        per_page             query  int     false  "Page size (max 100)"
// @Success      200  {object}  ComponentListResponse
// @Failure      400  {object}  apierror.Error
// @Router       /components [get]
func (h *ComponentHandler) List(w http.ResponseWriter, r *http.Request) {
	page, err := pagination.FromRequest(r.URL.Query(), 25)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	withFacets := r.URL.Query().Get("facets") == "true"
	res, facets, err := h.service.ListComponents(r.Context(), listInputFromRequest(r), page, withFacets)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, ComponentListResponse{
		ListResponse: ListResponse[component.Package]{
			Data: res.Data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
			Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
		},
		Facets: facets,
	})
}

// Summary handles GET /api/v1/components/summary
// @Summary      Software components summary
// @Description  KPI strip of the inventory for the same filters as the list.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  component.Summary
// @Failure      400  {object}  apierror.Error
// @Router       /components/summary [get]
func (h *ComponentHandler) Summary(w http.ResponseWriter, r *http.Request) {
	s, err := h.service.Summary(r.Context(), listInputFromRequest(r))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, s)
}

// Get handles GET /api/v1/components/{id}
// @Summary      Get a software component
// @Description  A package used by an in-scope asset (404 otherwise).
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Component (package) ID"
// @Success      200  {object}  component.PackageDetail
// @Failure      404  {object}  apierror.Error
// @Router       /components/{id} [get]
func (h *ComponentHandler) Get(w http.ResponseWriter, r *http.Request) {
	d, err := h.service.GetComponent(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, d)
}

// ComponentVersionResponse is one package version.
type ComponentVersionResponse struct {
	ID          string `json:"id"`
	ComponentID string `json:"component_id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem"`
	PURL        string `json:"purl"`
}

// GetVersion handles GET /api/v1/components/versions/{version_id}
// @Summary      Get a package version
// @Description  A package version (the id findings carry as component_id) seen through an in-scope asset or finding; 404 otherwise.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        version_id  path  string  true  "Package version ID"
// @Success      200  {object}  ComponentVersionResponse
// @Failure      404  {object}  apierror.Error
// @Router       /components/versions/{version_id} [get]
func (h *ComponentHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	v, err := h.service.GetVersion(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("version_id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, ComponentVersionResponse{ID: v.VersionID, ComponentID: v.ProductID, Name: v.Name,
		Version: v.Version, Ecosystem: v.Ecosystem, PURL: v.PURL})
}

// ComponentVersionsResponse lists versions in use.
type ComponentVersionsResponse struct {
	Data []component.Version `json:"data"`
}

// ListVersions handles GET /api/v1/components/{id}/versions
// @Summary      Versions of a component in use
// @Description  In-scope versions with assets, open findings by severity, KEV, fixed versions and upgrade advice.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Component (package) ID"
// @Success      200  {object}  ComponentVersionsResponse
// @Failure      404  {object}  apierror.Error
// @Router       /components/{id}/versions [get]
func (h *ComponentHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	vs, err := h.service.ListVersions(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, ComponentVersionsResponse{Data: vs})
}

// ListAssets handles GET /api/v1/components/{id}/assets
// @Summary      Where a component is used
// @Description  In-scope assets using the package: version, relationship, scope, location, depth, open findings.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id            path   string  true   "Component (package) ID"
// @Param        version_id    query  string  false  "Only this version"
// @Param        relationship  query  string  false  "direct, transitive, unknown (comma list)"
// @Param        scope         query  string  false  "Dependency scopes (comma list)"
// @Param        page          query  int     false  "Page"
// @Param        per_page      query  int     false  "Page size (max 100)"
// @Success      200  {object}  ListResponse[component.Usage]
// @Failure      404  {object}  apierror.Error
// @Router       /components/{id}/assets [get]
func (h *ComponentHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	page, err := pagination.FromRequest(r.URL.Query(), 25)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	q := r.URL.Query()
	res, err := h.service.ListUsages(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"), asset.UsageInput{
		VersionID: q.Get("version_id"), Relationship: parseQueryArray(q.Get("relationship")), Scopes: parseQueryArray(q.Get("scope")),
	}, page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, ListResponse[component.Usage]{
		Data: res.Data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}

// ListVulnerabilities handles GET /api/v1/components/{id}/vulnerabilities
// @Summary      Vulnerabilities of a component
// @Description  Vulnerabilities of the package's in-scope findings grouped across versions.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id                path   string  true   "Component (package) ID"
// @Param        include_resolved  query  bool    false  "Include closed findings"
// @Param        page              query  int     false  "Page"
// @Param        per_page          query  int     false  "Page size (max 100)"
// @Success      200  {object}  ListResponse[component.Vulnerability]
// @Failure      404  {object}  apierror.Error
// @Router       /components/{id}/vulnerabilities [get]
func (h *ComponentHandler) ListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	page, err := pagination.FromRequest(r.URL.Query(), 25)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	includeResolved := r.URL.Query().Get("include_resolved") == "true"
	res, err := h.service.ListVulnerabilities(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"), includeResolved, page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, ListResponse[component.Vulnerability]{
		Data: res.Data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}

// ListByAsset handles GET /api/v1/assets/{id}/components
// @Summary      Components of an asset
// @Description  The asset's package links (404 when the asset is outside the caller's scope).
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id        path   string  true   "Asset ID"
// @Param        page      query  int     false  "Page"
// @Param        per_page  query  int     false  "Page size (max 100)"
// @Success      200  {object}  ListResponse[component.Usage]
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/components [get]
func (h *ComponentHandler) ListByAsset(w http.ResponseWriter, r *http.Request) {
	page, err := pagination.FromRequest(r.URL.Query(), 50)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	res, err := h.service.ListAssetComponents(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"), page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, ListResponse[component.Usage]{
		Data: res.Data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}

// DependencyPathsResponse lists introduction paths, root first.
type DependencyPathsResponse struct {
	Data []component.Path `json:"data"`
}

func queryInt(r *http.Request, name string) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return 0
	}
	return n
}

// DependencyPaths handles GET /api/v1/assets/{id}/dependency-paths
// @Summary      Dependency paths to a package version
// @Description  Up to 20 shortest paths from a root package to the version on the asset.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id          path   string  true   "Asset ID"
// @Param        version_id  query  string  true   "Package version ID"
// @Param        limit       query  int     false  "At most this many paths (max 20)"
// @Success      200  {object}  DependencyPathsResponse
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/dependency-paths [get]
func (h *ComponentHandler) DependencyPaths(w http.ResponseWriter, r *http.Request) {
	versionID := r.URL.Query().Get("version_id")
	if versionID == "" {
		apierror.BadRequest("version_id is required").WriteJSON(w)
		return
	}
	paths, err := h.service.DependencyPaths(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"), versionID, queryInt(r, "limit"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if paths == nil {
		paths = []component.Path{}
	}
	writeComponentJSON(w, DependencyPathsResponse{Data: paths})
}

// DependencyGraph handles GET /api/v1/assets/{id}/dependency-graph
// @Summary      Dependency graph of an asset
// @Description  A bounded part of the asset's package graph: from the roots, or around a focus version. truncated tells whether the bounds cut it.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id     path   string  true   "Asset ID"
// @Param        focus  query  string  false  "Package version ID to center on"
// @Param        depth  query  int     false  "Hops (max 10)"
// @Param        limit  query  int     false  "Nodes (max 500)"
// @Success      200  {object}  component.Graph
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/dependency-graph [get]
func (h *ComponentHandler) DependencyGraph(w http.ResponseWriter, r *http.Request) {
	g, err := h.service.DependencyGraph(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"),
		r.URL.Query().Get("focus"), queryInt(r, "depth"), queryInt(r, "limit"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, g)
}

// ExportSBOM handles GET /api/v1/components/sbom
// @Summary      Export an SBOM
// @Description  CycloneDX 1.6 or SPDX 2.3 JSON of one asset's packages, or of every in-scope asset's.
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        asset_id  query  string  false  "Asset ID"
// @Param        format    query  string  false  "cyclonedx (default) or spdx"
// @Success      200  {file}  file
// @Failure      400  {object}  apierror.Error
// @Router       /components/sbom [get]
func (h *ComponentHandler) ExportSBOM(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	format, err := sbomexport.ParseFormat(r.URL.Query().Get("format"))
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	export, err := h.service.ListSBOMEntries(r.Context(), tenantID, r.URL.Query().Get("asset_id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	doc := sbomexport.Document{
		Subject:     export.Subject,
		SerialUUID:  uuid.NewString(),
		Created:     time.Now().UTC(),
		ToolVersion: version.Get().Version,
		Components:  make([]sbomexport.Component, 0, len(export.Entries)),
	}
	if doc.Subject == "" {
		doc.Subject = "Organization inventory"
	}
	for _, e := range export.Entries {
		doc.Components = append(doc.Components, sbomexport.Component{
			ID: e.ID, Name: e.Name, Version: e.Version, Ecosystem: e.Ecosystem, PURL: e.PURL,
			Licenses: e.Licenses, VulnerabilityCount: e.VulnerabilityCount,
		})
	}
	body, err := sbomexport.Encode(format, doc)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	filename := "sbom-" + doc.Created.Format("20060102-150405") + format.FileExtension()
	w.Header().Set("Content-Type", format.ContentType())
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// ImportSBOM handles POST /api/v1/components/import
// @Summary      Import an SBOM
// @Description  CycloneDX (1.4-1.6) or SPDX (2.2, 2.3) JSON for one asset, at most 50 MB and 100000 components. With dry_run=true the preview (counts, skipped entries with reasons, diff with the current inventory) is returned and nothing is written; otherwise the asset's packages at the locations the document names are replaced.
// @Tags         Components
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        asset_id  query  string  true   "Asset ID"
// @Param        dry_run   query  bool    false  "Preview only"
// @Success      200  {object}  asset.SBOMImportResult
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /components/import [post]
func (h *ComponentHandler) ImportSBOM(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	assetID := r.URL.Query().Get("asset_id")
	if assetID == "" {
		apierror.BadRequest("asset_id query parameter is required").WriteJSON(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, asset.MaxSBOMBytes+1)
	res, err := h.sbomImport.ImportSBOM(r.Context(), tenantID, assetID, r.Body, r.URL.Query().Get("dry_run") == "true")
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeComponentJSON(w, res)
}
