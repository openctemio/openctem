package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	catalogapp "github.com/openctemio/openctem/api/internal/app/contentcatalog"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentcatalog"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ContentCatalogHandler serves /api/v1/content: the content catalog as one
// organization sees it (RFC-099). The tenant always comes from the
// authenticated context.
type ContentCatalogHandler struct {
	service *catalogapp.Service
	logger  *logger.Logger
}

// NewContentCatalogHandler creates a ContentCatalogHandler.
func NewContentCatalogHandler(svc *catalogapp.Service, log *logger.Logger) *ContentCatalogHandler {
	return &ContentCatalogHandler{service: svc, logger: log.With("handler", "content_catalog")}
}

// ContentPackageVersionResponse is one package version.
type ContentPackageVersionResponse struct {
	ID                string                   `json:"id"`
	PackageID         string                   `json:"package_id"`
	Version           string                   `json:"version"`
	Type              string                   `json:"type"`
	Origin            string                   `json:"origin" enums:"first-party,catalog,instance,organization"`
	Title             string                   `json:"title"`
	Summary           string                   `json:"summary,omitempty"`
	ContentKind       string                   `json:"content_kind,omitempty"`
	Artifact          contentpkg.Artifact      `json:"artifact"`
	ManifestDigest    string                   `json:"manifest_digest"`
	Compatibility     contentpkg.Compatibility `json:"compatibility"`
	Permissions       contentpkg.Permissions   `json:"permissions"`
	License           contentpkg.License       `json:"license"`
	Dependencies      []contentpkg.Dependency  `json:"dependencies"`
	Provenance        contentpkg.Provenance    `json:"provenance"`
	SecurityContact   string                   `json:"security_contact,omitempty"`
	PublisherIdentity string                   `json:"publisher_identity,omitempty"`
	PublisherIssuer   string                   `json:"publisher_issuer,omitempty"`
	PublisherSignedAt *time.Time               `json:"publisher_signed_at,omitempty"`
	Signatures        []string                 `json:"signatures"`
	Revoked           bool                     `json:"revoked"`
	RevokedAt         *time.Time               `json:"revoked_at,omitempty"`
	RevokeReason      string                   `json:"revoke_reason,omitempty"`
	RevokeSeverity    string                   `json:"revoke_severity,omitempty"`
	ImportedAt        time.Time                `json:"imported_at"`
}

func toContentPackageVersion(p *dom.Package) ContentPackageVersionResponse {
	m := p.Manifest
	out := ContentPackageVersionResponse{
		ID: p.ID.String(), PackageID: p.PackageID, Version: p.Version, Type: string(p.Type), Origin: p.Origin,
		Title: p.Title, Summary: m.Summary, ContentKind: m.ContentKind, Artifact: m.Artifact,
		ManifestDigest: p.ManifestDigest, Compatibility: m.Compatibility, Permissions: m.Permissions, License: m.License,
		Dependencies: m.Dependencies, Provenance: m.Provenance, SecurityContact: m.SecurityContact,
		PublisherIdentity: p.PublisherIdentity, PublisherIssuer: p.PublisherIssuer, PublisherSignedAt: p.PublisherSignedAt,
		Revoked: p.Revoked(), RevokedAt: p.RevokedAt, RevokeReason: p.RevokeReason, RevokeSeverity: p.RevokeSeverity,
		ImportedAt: p.CreatedAt,
	}
	if out.Dependencies == nil {
		out.Dependencies = []contentpkg.Dependency{}
	}
	// Which signatures the instance verified for this version.
	switch p.Origin {
	case contentpkg.OriginOrganization:
		out.Signatures = []string{"organization"}
	case contentpkg.OriginInstance:
		out.Signatures = []string{"instance"}
	default:
		out.Signatures = []string{"catalog"}
		if len(p.PublisherSignature) > 0 {
			out.Signatures = append(out.Signatures, "publisher")
		}
	}
	return out
}

// ContentInstallResponse is an organization's installation.
type ContentInstallResponse struct {
	PackageID           string                         `json:"package_id"`
	Status              string                         `json:"status" enums:"active,revoked"`
	Pinned              bool                           `json:"pinned"`
	LicenseAcknowledged bool                           `json:"license_acknowledged"`
	Installed           ContentPackageVersionResponse  `json:"installed"`
	Previous            *ContentPackageVersionResponse `json:"previous,omitempty"`
	InstalledBy         string                         `json:"installed_by,omitempty"`
	UpdatedBy           string                         `json:"updated_by,omitempty"`
	CreatedAt           time.Time                      `json:"created_at"`
	UpdatedAt           time.Time                      `json:"updated_at"`
}

func toContentInstall(in *dom.Install) *ContentInstallResponse {
	if in == nil {
		return nil
	}
	out := &ContentInstallResponse{PackageID: in.PackageID, Status: string(in.Status), Pinned: in.Pinned,
		LicenseAcknowledged: in.LicenseAcknowledged, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
	if in.Package != nil {
		out.Installed = toContentPackageVersion(in.Package)
	}
	if in.Previous != nil {
		prev := toContentPackageVersion(in.Previous)
		out.Previous = &prev
	}
	if in.InstalledBy != nil {
		out.InstalledBy = in.InstalledBy.String()
	}
	if in.UpdatedBy != nil {
		out.UpdatedBy = in.UpdatedBy.String()
	}
	return out
}

// ContentRequestResponse is an approval request.
type ContentRequestResponse struct {
	ID                  string                         `json:"id"`
	PackageID           string                         `json:"package_id"`
	Action              string                         `json:"action" enums:"install,update,rollback,uninstall"`
	Target              *ContentPackageVersionResponse `json:"target,omitempty"`
	Pinned              bool                           `json:"pinned"`
	LicenseAcknowledged bool                           `json:"license_acknowledged"`
	Status              string                         `json:"status" enums:"pending,approved,rejected,canceled,failed"`
	Note                string                         `json:"note,omitempty"`
	DecisionReason      string                         `json:"decision_reason,omitempty"`
	RequestedBy         string                         `json:"requested_by,omitempty"`
	DecidedBy           string                         `json:"decided_by,omitempty"`
	DecidedAt           *time.Time                     `json:"decided_at,omitempty"`
	CreatedAt           time.Time                      `json:"created_at"`
}

func toContentRequest(q *dom.Request) *ContentRequestResponse {
	if q == nil {
		return nil
	}
	out := &ContentRequestResponse{ID: q.ID.String(), PackageID: q.PackageID, Action: string(q.Action), Pinned: q.Pinned,
		LicenseAcknowledged: q.LicenseAcknowledged, Status: string(q.Status), Note: q.Note,
		DecisionReason: q.DecisionReason, DecidedAt: q.DecidedAt, CreatedAt: q.CreatedAt}
	if q.Target != nil {
		t := toContentPackageVersion(q.Target)
		out.Target = &t
	}
	if q.RequestedBy != nil {
		out.RequestedBy = q.RequestedBy.String()
	}
	if q.DecidedBy != nil {
		out.DecidedBy = q.DecidedBy.String()
	}
	return out
}

// ContentPackageListItem is one package of the catalog listing.
type ContentPackageListItem struct {
	Latest   ContentPackageVersionResponse `json:"latest"`
	Versions int                           `json:"versions"`
	Install  *ContentInstallResponse       `json:"install,omitempty"`
}

// ContentPackageListResponse is a page of the catalog.
type ContentPackageListResponse struct {
	Data  []ContentPackageListItem `json:"data"`
	Total int                      `json:"total"`
}

// ContentPackageDetailResponse is one package with its versions.
type ContentPackageDetailResponse struct {
	PackageID string                          `json:"package_id"`
	Versions  []ContentPackageVersionResponse `json:"versions"`
	Install   *ContentInstallResponse         `json:"install,omitempty"`
	Pending   *ContentRequestResponse         `json:"pending_request,omitempty"`
}

// ContentOutcomeResponse is an action done (install) or waiting for
// approval (request).
type ContentOutcomeResponse struct {
	Install *ContentInstallResponse `json:"install,omitempty"`
	Request *ContentRequestResponse `json:"request,omitempty"`
}

// ContentTrustResponse is the applied signed state.
type ContentTrustResponse struct {
	RootsConfigured      int        `json:"roots_configured"`
	KeySetVersion        uint64     `json:"keyset_version"`
	IndexSequence        uint64     `json:"index_sequence"`
	IndexExpiresAt       *time.Time `json:"index_expires_at,omitempty"`
	IndexExpired         bool       `json:"index_expired"`
	RevocationsSequence  uint64     `json:"revocations_sequence"`
	RevocationsExpiresAt *time.Time `json:"revocations_expires_at,omitempty"`
	RevocationsStale     bool       `json:"revocations_stale"`
	ImportedAt           *time.Time `json:"imported_at,omitempty"`
}

func toContentTrust(t *catalogapp.TrustStatus) ContentTrustResponse {
	return ContentTrustResponse{RootsConfigured: t.RootsConfigured, KeySetVersion: t.State.KeySetVersion,
		IndexSequence: t.State.IndexSequence, IndexExpiresAt: t.State.IndexExpiresAt, IndexExpired: t.IndexExpired,
		RevocationsSequence: t.State.RevocationsSequence, RevocationsExpiresAt: t.State.RevocationsExpiresAt,
		RevocationsStale: t.RevocationsStale, ImportedAt: t.State.ImportedAt}
}

// ContentSettingsResponse is the organization's catalog settings.
type ContentSettingsResponse struct {
	RequireApproval bool       `json:"require_approval"`
	UpdatedBy       string     `json:"updated_by,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

func toContentSettings(s *dom.Settings) ContentSettingsResponse {
	out := ContentSettingsResponse{RequireApproval: s.RequireApproval, UpdatedAt: s.UpdatedAt}
	if s.UpdatedBy != nil {
		out.UpdatedBy = s.UpdatedBy.String()
	}
	return out
}

// InstallContentRequest installs a package version.
type InstallContentRequest struct {
	PackageID          string `json:"package_id"`
	Version            string `json:"version"`
	Pinned             bool   `json:"pinned"`
	AcknowledgeLicense bool   `json:"acknowledge_license"`
	Note               string `json:"note"`
}

// ChangeContentRequest updates or rolls back an installation.
type ChangeContentRequest struct {
	Version            string `json:"version"`
	AcknowledgeLicense bool   `json:"acknowledge_license"`
	Note               string `json:"note"`
}

// PinContentRequest pins or unpins an installation.
type PinContentRequest struct {
	Pinned bool `json:"pinned"`
}

// DecideContentRequest approves or rejects a request.
type DecideContentRequest struct {
	Reason string `json:"reason"`
}

// PutContentSettingsRequest changes the approval option.
type PutContentSettingsRequest struct {
	RequireApproval bool `json:"require_approval"`
}

func (h *ContentCatalogHandler) tenant(r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	return id, err == nil && !id.IsZero()
}

func packageIDParam(r *http.Request) string {
	return chi.URLParam(r, "namespace") + "/" + chi.URLParam(r, "name")
}

func decodeContentBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// List handles GET /api/v1/content/packages
// @Summary      List the content catalog
// @Description  The newest version of every package the organization sees (the instance catalog and its own private packages), with its installation.
// @Tags         Content Catalog
// @Produce      json
// @Param        type       query  string  false  "Package type"
// @Param        q          query  string  false  "Search in id and title"
// @Param        installed  query  bool    false  "Only installed (true) or not installed (false)"
// @Param        page       query  int     false  "Page (from 1)"
// @Param        per_page   query  int     false  "Page size (default 50, max 100)"
// @Success      200  {object}  ContentPackageListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/packages [get]
func (h *ContentCatalogHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	page, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := dom.Filter{Type: contentpkg.Type(q.Get("type")), Search: q.Get("q"), Limit: page.Limit(), Offset: page.Offset()}
	if f.Type != "" && !isContentType(f.Type) {
		apierror.BadRequest("unknown package type").WriteJSON(w)
		return
	}
	if v := q.Get("installed"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			apierror.BadRequest("installed must be true or false").WriteJSON(w)
			return
		}
		f.Installed = &b
	}
	if len(f.Search) > 100 {
		apierror.BadRequest("q is over 100 characters").WriteJSON(w)
		return
	}
	items, total, err := h.service.List(r.Context(), tid, f)
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ContentPackageListResponse{Data: make([]ContentPackageListItem, 0, len(items)), Total: total}
	for _, it := range items {
		resp.Data = append(resp.Data, ContentPackageListItem{Latest: toContentPackageVersion(it.Latest),
			Versions: it.Versions, Install: toContentInstall(it.Install)})
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

func isContentType(t contentpkg.Type) bool {
	for _, x := range contentpkg.Types() {
		if x == t {
			return true
		}
	}
	return false
}

// Get handles GET /api/v1/content/packages/{namespace}/{name}
// @Summary      Get a content package
// @Description  Every version the organization sees, newest first, with the installation and the pending request.
// @Tags         Content Catalog
// @Produce      json
// @Param        namespace  path  string  true  "Namespace"
// @Param        name       path  string  true  "Name"
// @Success      200  {object}  ContentPackageDetailResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/packages/{namespace}/{name} [get]
func (h *ContentCatalogHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	v, err := h.service.Get(r.Context(), tid, packageIDParam(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ContentPackageDetailResponse{PackageID: packageIDParam(r), Install: toContentInstall(v.Install),
		Pending: toContentRequest(v.Pending), Versions: make([]ContentPackageVersionResponse, 0, len(v.Versions))}
	for _, p := range v.Versions {
		resp.Versions = append(resp.Versions, toContentPackageVersion(p))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// Installs handles GET /api/v1/content/installs
// @Summary      List installed content
// @Tags         Content Catalog
// @Produce      json
// @Success      200  {array}   ContentInstallResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/installs [get]
func (h *ContentCatalogHandler) Installs(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	ins, err := h.service.Installs(r.Context(), tid)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := make([]*ContentInstallResponse, 0, len(ins))
	for _, in := range ins {
		out = append(out, toContentInstall(in))
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

func (h *ContentCatalogHandler) writeOutcome(w http.ResponseWriter, o *catalogapp.Outcome, created bool) {
	status := http.StatusOK
	switch {
	case o.Request != nil:
		status = http.StatusAccepted
	case created:
		status = http.StatusCreated
	}
	writeScanZoneJSON(w, status, ContentOutcomeResponse{Install: toContentInstall(o.Install), Request: toContentRequest(o.Request)})
}

// Install handles POST /api/v1/content/installs
// @Summary      Install a content package
// @Description  Installs a version for the organization (201), or files a request for a second person when the organization requires approval (202). Refused for a revoked or incompatible version, missing dependencies, a license without service use unless acknowledged, and executables while the revocation list is out of date.
// @Tags         Content Catalog
// @Accept       json
// @Produce      json
// @Param        body  body      InstallContentRequest  true  "Package and version"
// @Success      201   {object}  ContentOutcomeResponse
// @Success      202   {object}  ContentOutcomeResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/installs [post]
func (h *ContentCatalogHandler) Install(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req InstallContentRequest
	if !decodeContentBody(w, r, &req) {
		return
	}
	o, err := h.service.Install(r.Context(), tid, catalogapp.Change{PackageID: req.PackageID, Version: req.Version,
		Pinned: req.Pinned, AcknowledgeLicense: req.AcknowledgeLicense, Note: req.Note}, buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeOutcome(w, o, true)
}

// Update handles POST /api/v1/content/installs/{namespace}/{name}/update
// @Summary      Update installed content
// @Tags         Content Catalog
// @Accept       json
// @Produce      json
// @Param        namespace  path      string                true  "Namespace"
// @Param        name       path      string                true  "Name"
// @Param        body       body      ChangeContentRequest  true  "Newer version"
// @Success      200        {object}  ContentOutcomeResponse
// @Success      202        {object}  ContentOutcomeResponse
// @Failure      400        {object}  apierror.Error
// @Failure      401        {object}  apierror.Error
// @Failure      403        {object}  apierror.Error
// @Failure      404        {object}  apierror.Error
// @Failure      409        {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/installs/{namespace}/{name}/update [post]
func (h *ContentCatalogHandler) Update(w http.ResponseWriter, r *http.Request) {
	h.change(w, r, h.service.Update)
}

// Rollback handles POST /api/v1/content/installs/{namespace}/{name}/rollback
// @Summary      Roll installed content back
// @Description  Moves to an older version (the previous one when no version is given) and pins the installation.
// @Tags         Content Catalog
// @Accept       json
// @Produce      json
// @Param        namespace  path      string                true  "Namespace"
// @Param        name       path      string                true  "Name"
// @Param        body       body      ChangeContentRequest  true  "Older version (optional)"
// @Success      200        {object}  ContentOutcomeResponse
// @Success      202        {object}  ContentOutcomeResponse
// @Failure      400        {object}  apierror.Error
// @Failure      401        {object}  apierror.Error
// @Failure      403        {object}  apierror.Error
// @Failure      404        {object}  apierror.Error
// @Failure      409        {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/installs/{namespace}/{name}/rollback [post]
func (h *ContentCatalogHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	h.change(w, r, h.service.Rollback)
}

type changeFunc func(ctx context.Context, tenantID shared.ID, c catalogapp.Change, actx auditapp.AuditContext) (*catalogapp.Outcome, error)

func (h *ContentCatalogHandler) change(w http.ResponseWriter, r *http.Request, fn changeFunc) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req ChangeContentRequest
	if !decodeContentBody(w, r, &req) {
		return
	}
	o, err := fn(r.Context(), tid, catalogapp.Change{PackageID: packageIDParam(r), Version: req.Version,
		AcknowledgeLicense: req.AcknowledgeLicense, Note: req.Note}, buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeOutcome(w, o, false)
}

// Uninstall handles DELETE /api/v1/content/installs/{namespace}/{name}
// @Summary      Uninstall content
// @Tags         Content Catalog
// @Produce      json
// @Param        namespace  path  string  true  "Namespace"
// @Param        name       path  string  true  "Name"
// @Success      202  {object}  ContentOutcomeResponse
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/installs/{namespace}/{name} [delete]
func (h *ContentCatalogHandler) Uninstall(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	o, err := h.service.Uninstall(r.Context(), tid, packageIDParam(r), "", buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	if o.Request != nil {
		h.writeOutcome(w, o, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Pin handles PUT /api/v1/content/installs/{namespace}/{name}/pin
// @Summary      Pin or unpin installed content
// @Description  A pinned installation never moves to a newer version by itself.
// @Tags         Content Catalog
// @Accept       json
// @Produce      json
// @Param        namespace  path      string             true  "Namespace"
// @Param        name       path      string             true  "Name"
// @Param        body       body      PinContentRequest  true  "Pinned"
// @Success      200        {object}  ContentInstallResponse
// @Failure      400        {object}  apierror.Error
// @Failure      401        {object}  apierror.Error
// @Failure      403        {object}  apierror.Error
// @Failure      404        {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/installs/{namespace}/{name}/pin [put]
func (h *ContentCatalogHandler) Pin(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req PinContentRequest
	if !decodeContentBody(w, r, &req) {
		return
	}
	in, err := h.service.Pin(r.Context(), tid, packageIDParam(r), req.Pinned, buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentInstall(in))
}

// Requests handles GET /api/v1/content/requests
// @Summary      List content requests
// @Tags         Content Catalog
// @Produce      json
// @Param        status  query  string  false  "Status"  Enums(pending,approved,rejected,canceled,failed)
// @Success      200  {array}   ContentRequestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/requests [get]
func (h *ContentCatalogHandler) Requests(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	qs, err := h.service.Requests(r.Context(), tid, dom.RequestStatus(r.URL.Query().Get("status")))
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := make([]*ContentRequestResponse, 0, len(qs))
	for _, q := range qs {
		out = append(out, toContentRequest(q))
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

func (h *ContentCatalogHandler) requestID(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Request").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tid, id, true
}

// Approve handles POST /api/v1/content/requests/{id}/approve
// @Summary      Approve a content request
// @Description  Carries out another member's pending request after checking it again. Nobody approves their own request.
// @Tags         Content Catalog
// @Accept       json
// @Produce      json
// @Param        id    path      string                true  "Request ID"
// @Param        body  body      DecideContentRequest  true  "Reason (optional)"
// @Success      200   {object}  ContentOutcomeResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/requests/{id}/approve [post]
func (h *ContentCatalogHandler) Approve(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	var req DecideContentRequest
	if !decodeContentBody(w, r, &req) {
		return
	}
	q, in, err := h.service.Approve(r.Context(), tid, id, req.Reason, buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, ContentOutcomeResponse{Install: toContentInstall(in), Request: toContentRequest(q)})
}

// Reject handles POST /api/v1/content/requests/{id}/reject
// @Summary      Reject a content request
// @Tags         Content Catalog
// @Accept       json
// @Produce      json
// @Param        id    path      string                true  "Request ID"
// @Param        body  body      DecideContentRequest  true  "Reason"
// @Success      200   {object}  ContentRequestResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/requests/{id}/reject [post]
func (h *ContentCatalogHandler) Reject(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	var req DecideContentRequest
	if !decodeContentBody(w, r, &req) {
		return
	}
	q, err := h.service.Reject(r.Context(), tid, id, req.Reason, buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentRequest(q))
}

// Cancel handles POST /api/v1/content/requests/{id}/cancel
// @Summary      Cancel your content request
// @Tags         Content Catalog
// @Produce      json
// @Param        id  path  string  true  "Request ID"
// @Success      200  {object}  ContentRequestResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/requests/{id}/cancel [post]
func (h *ContentCatalogHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	q, err := h.service.Cancel(r.Context(), tid, id, buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentRequest(q))
}

// Settings handles GET /api/v1/content/settings
// @Summary      Get content catalog settings
// @Tags         Content Catalog
// @Produce      json
// @Success      200  {object}  ContentSettingsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/settings [get]
func (h *ContentCatalogHandler) Settings(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	s, err := h.service.GetSettings(r.Context(), tid)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentSettings(s))
}

// PutSettings handles PUT /api/v1/content/settings
// @Summary      Change content catalog settings
// @Description  require_approval: every install, update, rollback and uninstall needs a second person. Organization settings permission and a recent sign-in; audited.
// @Tags         Content Catalog
// @Accept       json
// @Produce      json
// @Param        body  body      PutContentSettingsRequest  true  "Settings"
// @Success      200   {object}  ContentSettingsResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/settings [put]
func (h *ContentCatalogHandler) PutSettings(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req PutContentSettingsRequest
	if !decodeContentBody(w, r, &req) {
		return
	}
	s, err := h.service.PutSettings(r.Context(), tid, req.RequireApproval, buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentSettings(s))
}

// Trust handles GET /api/v1/content/trust
// @Summary      Content catalog trust status
// @Description  The signed state the instance applied: key set version, index and revocation list sequences and expiries.
// @Tags         Content Catalog
// @Produce      json
// @Success      200  {object}  ContentTrustResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content/trust [get]
func (h *ContentCatalogHandler) Trust(w http.ResponseWriter, r *http.Request) {
	t, err := h.service.Trust(r.Context())
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentTrust(t))
}

// contentMessage strips the sentinel prefixes from a service error.
func contentMessage(err error) string {
	msg := err.Error()
	for _, p := range []string{"validation error: ", "conflict: ", "forbidden: ", "not found: ", "refused: "} {
		msg = strings.ReplaceAll(msg, p, "")
	}
	return msg
}

func (h *ContentCatalogHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, dom.ErrInstallNotFound):
		apierror.NotFound("Installation").WriteJSON(w)
	case errors.Is(err, dom.ErrRequestNotFound):
		apierror.NotFound("Request").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Content package").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(contentMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(contentMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.New(http.StatusUnprocessableEntity, apierror.Code("CONTENT_REFUSED"), contentMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("content catalog error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
