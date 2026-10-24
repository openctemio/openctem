package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	contentsourceapp "github.com/openctemio/openctem/api/internal/app/contentsource"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	cs "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ContentSourceHandler serves /api/v1/content-sources (rule sources,
// docs/architecture/content-sources.md) and the public webhook. The tenant
// comes from the JWT. An organization sees its own sources in full (never
// the credential) and offered platform sources as a projection without URL,
// credential, CA, schedule, webhook or error text; anything else is 404.
type ContentSourceHandler struct {
	service *contentsourceapp.Service
	logger  *logger.Logger
}

// NewContentSourceHandler creates a ContentSourceHandler.
func NewContentSourceHandler(svc *contentsourceapp.Service, log *logger.Logger) *ContentSourceHandler {
	return &ContentSourceHandler{service: svc, logger: log.With("handler", "content_source")}
}

// ContentSourceCredential says whether a credential is stored. The token
// itself is never returned.
type ContentSourceCredential struct {
	Set       bool       `json:"set"`
	Username  string     `json:"username,omitempty"`
	Hint      string     `json:"hint,omitempty"` // last four characters
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// ContentSourceWebhook is the webhook state; the secret is shown once when
// it is set.
type ContentSourceWebhook struct {
	Enabled bool       `json:"enabled"`
	Path    string     `json:"path,omitempty"`
	SetAt   *time.Time `json:"set_at,omitempty"`
}

// ContentSourceResponse is a rule source. For a platform source only the
// projection fields are set (editable false).
type ContentSourceResponse struct {
	ID                 string                   `json:"id"`
	Scope              string                   `json:"scope" enums:"platform,tenant"`
	Slug               string                   `json:"slug"`
	Namespace          string                   `json:"namespace"`
	Name               string                   `json:"name"`
	Description        string                   `json:"description"`
	Kind               string                   `json:"kind"`
	Editable           bool                     `json:"editable"`
	Enabled            bool                     `json:"enabled"`
	LicenseSPDX        string                   `json:"license_spdx,omitempty"`
	LicenseServiceUse  bool                     `json:"license_service_use"`
	Availability       string                   `json:"availability,omitempty" enums:"default_on,opt_in,hidden"`
	Official           bool                     `json:"official,omitempty"`
	CurrentSnapshotID  string                   `json:"current_snapshot_id,omitempty"`
	PreviousSnapshotID string                   `json:"previous_snapshot_id,omitempty"`
	SyncHealth         string                   `json:"sync_health" enums:"ok,degraded,pending"`
	Origin             string                   `json:"origin,omitempty"`
	URL                string                   `json:"url,omitempty"`
	Ref                string                   `json:"ref,omitempty"`
	Path               string                   `json:"path,omitempty"`
	CAPEM              string                   `json:"ca_pem,omitempty"`
	Credential         *ContentSourceCredential `json:"credential,omitempty"`
	PromotionPolicy    string                   `json:"promotion_policy,omitempty" enums:"auto,review"`
	SyncIntervalMin    *int                     `json:"sync_interval_minutes,omitempty"`
	NextSyncAt         *time.Time               `json:"next_sync_at,omitempty"`
	SyncRequestedAt    *time.Time               `json:"sync_requested_at,omitempty"`
	Webhook            *ContentSourceWebhook    `json:"webhook,omitempty"`
	StorageMode        string                   `json:"storage_mode,omitempty"`
	LastSyncAt         *time.Time               `json:"last_sync_at,omitempty"`
	LastSyncStatus     string                   `json:"last_sync_status,omitempty"`
	LastSyncError      string                   `json:"last_sync_error,omitempty"`
	LastSyncCommit     string                   `json:"last_sync_commit,omitempty"`
	LastSyncReport     json.RawMessage          `json:"last_sync_report,omitempty" swaggertype:"object"`
	ConfigChangedBy    string                   `json:"config_changed_by,omitempty"`
	ConfigChangedAt    *time.Time               `json:"config_changed_at,omitempty"`
	CreatedAt          *time.Time               `json:"created_at,omitempty"`
	UpdatedAt          *time.Time               `json:"updated_at,omitempty"`
}

func csIDString(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func syncHealth(s *cs.Source) string {
	switch {
	case s.LastSyncStatus == cs.SyncFailed:
		return "degraded"
	case s.LastSyncAt == nil:
		return string(cs.SyncPending)
	}
	return "ok"
}

// toContentSourceResponse renders a source for tenantID: its own in full
// (no secret), a platform source as the projection.
func toContentSourceResponse(s *cs.Source, tenantID shared.ID) ContentSourceResponse {
	out := ContentSourceResponse{
		ID: s.ID.String(), Scope: string(s.Scope), Slug: s.Slug, Namespace: s.Namespace(), Name: s.Name,
		Description: s.Description, Kind: string(s.Kind), Enabled: s.Enabled, LicenseSPDX: s.LicenseSPDX,
		LicenseServiceUse: s.LicenseServiceUse, CurrentSnapshotID: csIDString(s.CurrentSnapshotID),
		PreviousSnapshotID: csIDString(s.PreviousSnapshotID), SyncHealth: syncHealth(s),
	}
	if s.IsPlatform() || !s.BelongsTo(tenantID) {
		out.Availability, out.Official = string(s.Availability), s.Official
		return out
	}
	interval := s.SyncIntervalMin
	created, updated := s.CreatedAt, s.UpdatedAt
	out.Editable = true
	out.Origin, out.URL, out.Ref, out.Path, out.CAPEM = string(s.Origin), s.URL, s.Ref, s.Path, s.CAPEM
	out.Credential = &ContentSourceCredential{Set: s.HasCredential(), Username: s.AuthUsername, Hint: s.CredentialHint, UpdatedAt: s.CredentialUpdatedAt}
	out.PromotionPolicy, out.SyncIntervalMin = string(s.Policy), &interval
	out.NextSyncAt, out.SyncRequestedAt, out.StorageMode = s.NextSyncAt, s.SyncRequestedAt, s.StorageMode
	out.Webhook = &ContentSourceWebhook{Enabled: s.WebhookSecretHash != "", SetAt: s.WebhookSecretAt}
	if out.Webhook.Enabled {
		out.Webhook.Path = "/hooks/content-sources/" + s.ID.String()
	}
	out.LastSyncAt, out.LastSyncStatus, out.LastSyncError, out.LastSyncCommit = s.LastSyncAt, string(s.LastSyncStatus), s.LastSyncError, s.LastSyncCommit
	if len(s.LastSyncReport) > 0 {
		out.LastSyncReport = json.RawMessage(s.LastSyncReport)
	}
	out.ConfigChangedBy, out.ConfigChangedAt = csIDString(s.ConfigChangedBy), s.ConfigChangedAt
	out.CreatedAt, out.UpdatedAt = &created, &updated
	return out
}

// ContentSourceListResponse lists rule sources: platform sources first.
type ContentSourceListResponse struct {
	Data []ContentSourceResponse `json:"data"`
}

// ContentSnapshotResponse is a snapshot. Rules, files and lint are in the
// single-snapshot answer only.
type ContentSnapshotResponse struct {
	ID               string                  `json:"id"`
	SourceID         string                  `json:"source_id"`
	UpstreamRevision string                  `json:"upstream_revision"`
	Ref              string                  `json:"ref,omitempty"`
	Digest           string                  `json:"digest"`
	SizeBytes        int64                   `json:"size_bytes"`
	FileCount        int                     `json:"file_count"`
	RuleCount        int                     `json:"rule_count"`
	Tier             string                  `json:"tier" enums:"T0,T1,T2"`
	LicenseSPDX      string                  `json:"license_spdx,omitempty"`
	ServiceUse       bool                    `json:"service_use"`
	Redistribution   *bool                   `json:"redistribution,omitempty"`
	State            string                  `json:"state" enums:"candidate,promoted,superseded,rejected"`
	Current          bool                    `json:"current"`
	Previous         bool                    `json:"previous"`
	ReviewRequired   bool                    `json:"review_required"`
	Checks           cs.Checks               `json:"checks"`
	Diff             cs.Diff                 `json:"diff"`
	SyncedBy         string                  `json:"synced_by,omitempty"`
	PromotedBy       string                  `json:"promoted_by,omitempty"`
	PromotedAt       *time.Time              `json:"promoted_at,omitempty"`
	RejectedBy       string                  `json:"rejected_by,omitempty"`
	RejectedAt       *time.Time              `json:"rejected_at,omitempty"`
	RejectReason     string                  `json:"reject_reason,omitempty"`
	CreatedAt        time.Time               `json:"created_at"`
	Rules            []cs.Rule               `json:"rules,omitempty"`
	Files            []cs.FileEntry          `json:"files,omitempty"`
	Lint             *contentpack.LintReport `json:"lint,omitempty"`
}

// ContentSnapshotListResponse is a page of snapshots.
type ContentSnapshotListResponse struct {
	Data  []ContentSnapshotResponse `json:"data"`
	Total int                       `json:"total"`
}

func toContentSnapshotResponse(sn *cs.Snapshot, src *cs.Source, full bool) ContentSnapshotResponse {
	out := ContentSnapshotResponse{
		ID: sn.ID.String(), SourceID: sn.SourceID.String(), UpstreamRevision: sn.UpstreamRevision, Ref: sn.Ref, Digest: sn.Digest,
		SizeBytes: sn.SizeBytes, FileCount: sn.FileCount, RuleCount: sn.RuleCount, Tier: string(sn.Tier),
		LicenseSPDX: sn.LicenseSPDX, ServiceUse: sn.ServiceUse, Redistribution: sn.Redistribution, State: string(sn.State), ReviewRequired: sn.ReviewRequired,
		Checks: sn.Checks, Diff: sn.Diff, SyncedBy: csIDString(sn.SyncedBy), PromotedBy: csIDString(sn.PromotedBy),
		PromotedAt: sn.PromotedAt, RejectedBy: csIDString(sn.RejectedBy), RejectedAt: sn.RejectedAt,
		RejectReason: sn.RejectReason, CreatedAt: sn.CreatedAt,
	}
	if src != nil {
		out.Current = src.CurrentSnapshotID != nil && src.CurrentSnapshotID.Equals(sn.ID)
		out.Previous = src.PreviousSnapshotID != nil && src.PreviousSnapshotID.Equals(sn.ID)
	}
	if full {
		out.Rules, out.Files = sn.Rules, sn.FileIndex
		lint := sn.Lint
		out.Lint = &lint
	}
	return out
}

// CreateContentSourceRequest adds a rule source (git over https).
type CreateContentSourceRequest struct {
	Slug                string `json:"slug"`
	Name                string `json:"name"`
	Description         string `json:"description"`
	Kind                string `json:"kind" enums:"semgrep-rules,nuclei-templates,wordlist"`
	URL                 string `json:"url"`
	Ref                 string `json:"ref"`
	Path                string `json:"path"`
	CAPEM               string `json:"ca_pem"`
	LicenseSPDX         string `json:"license_spdx"`
	LicenseServiceUse   *bool  `json:"license_service_use"`
	PromotionPolicy     string `json:"promotion_policy" enums:"auto,review"`
	SyncIntervalMinutes *int   `json:"sync_interval_minutes"`
	Enabled             *bool  `json:"enabled"`
}

// UpdateContentSourceRequest changes a rule source; absent fields stay.
type UpdateContentSourceRequest struct {
	Name                *string `json:"name"`
	Description         *string `json:"description"`
	URL                 *string `json:"url"`
	Ref                 *string `json:"ref"`
	Path                *string `json:"path"`
	CAPEM               *string `json:"ca_pem"`
	LicenseSPDX         *string `json:"license_spdx"`
	LicenseServiceUse   *bool   `json:"license_service_use"`
	PromotionPolicy     *string `json:"promotion_policy" enums:"auto,review"`
	SyncIntervalMinutes *int    `json:"sync_interval_minutes"`
	Enabled             *bool   `json:"enabled"`
}

// SetContentSourceCredentialRequest stores the fetch credential
// (write-only). username defaults by token type; a deploy token needs its
// own.
type SetContentSourceCredentialRequest struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

// TestContentSourceRequest is a configuration to try without saving.
type TestContentSourceRequest struct {
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	Ref      string `json:"ref"`
	Path     string `json:"path"`
	Username string `json:"username"`
	Token    string `json:"token"`
	CAPEM    string `json:"ca_pem"`
}

// ContentSourceTestResponse is what a Test found.
type ContentSourceTestResponse struct {
	OK     bool                     `json:"ok"`
	Code   string                   `json:"code,omitempty"`
	Error  string                   `json:"error,omitempty"`
	Report *contentsourceapp.Report `json:"report,omitempty"`
}

// RejectContentSnapshotRequest rejects a candidate.
type RejectContentSnapshotRequest struct {
	Reason string `json:"reason"`
}

// ContentSourceWebhookSecretResponse is the new webhook secret, shown once.
type ContentSourceWebhookSecretResponse struct {
	Path   string `json:"path"`
	Secret string `json:"secret"`
	Header string `json:"header"`
}

func (h *ContentSourceHandler) actor(r *http.Request) (contentsourceapp.Actor, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tid.IsZero() {
		return contentsourceapp.Actor{}, false
	}
	a := contentsourceapp.Actor{TenantID: tid, Audit: configAuditContext(r)}
	if uid := middleware.GetLocalUserID(r.Context()); !uid.IsZero() {
		a.UserID = &uid
	}
	return a, true
}

func decodeContentSource(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func contentSourcePathID(w http.ResponseWriter, r *http.Request, name string) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, name))
	if err != nil || id.IsZero() {
		apierror.NotFound("Rule source").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *ContentSourceHandler) handleError(w http.ResponseWriter, err error) {
	var se *contentsourceapp.SyncError
	var de *shared.DomainError
	switch {
	case WriteLimitError(w, err), WriteFeatureDenied(w, err):
	case errors.As(err, &se):
		e := apierror.New(http.StatusUnprocessableEntity, apierror.Code("CONTENT_SOURCE_"+se.Code), se.Message)
		if se.Report != nil {
			e = e.WithDetails(se.Report)
		}
		e.WriteJSON(w)
	case errors.Is(err, contentpack.ErrSigningKey):
		apierror.New(http.StatusServiceUnavailable, apierror.Code("CONTENT_SIGNING_UNAVAILABLE"),
			"Content signing is not configured on this platform").WriteJSON(w)
	case errors.Is(err, cs.ErrTooManyRequests):
		apierror.TooManyRequests("Too many requests for this rule source; try again later").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Rule source").WriteJSON(w)
	case errors.As(err, &de) && errors.Is(err, shared.ErrForbidden):
		apierror.New(http.StatusForbidden, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists), errors.Is(err, shared.ErrConflict):
		apierror.Conflict(cleanErrorMessage(err, "Conflict")).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(cleanErrorMessage(err, "Invalid rule source")).WriteJSON(w)
	default:
		h.logger.Error("rule source error", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/content-sources
// @Summary      List rule sources
// @Description  The organization's own rule sources and the platform sources offered to it (platform first).
// @Tags         Rule Sources
// @Produce      json
// @Param        kind   query     string  false  "Kind"  Enums(semgrep-rules,nuclei-templates,wordlist)
// @Param        scope  query     string  false  "Scope"  Enums(platform,tenant)
// @Success      200  {object}  ContentSourceListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources [get]
func (h *ContentSourceHandler) List(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	scope := cs.Scope(q.Get("scope"))
	if scope != "" && scope != cs.ScopePlatform && scope != cs.ScopeTenant {
		apierror.BadRequest("scope must be platform or tenant").WriteJSON(w)
		return
	}
	list, err := h.service.List(r.Context(), a.TenantID, cs.ListFilter{Kind: cs.Kind(q.Get("kind")), Scope: scope})
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ContentSourceListResponse{Data: make([]ContentSourceResponse, 0, len(list))}
	for _, s := range list {
		resp.Data = append(resp.Data, toContentSourceResponse(s, a.TenantID))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/content-sources/{id}
// @Summary      Get rule source
// @Tags         Rule Sources
// @Produce      json
// @Param        id   path      string  true  "Rule source ID"
// @Success      200  {object}  ContentSourceResponse
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id} [get]
func (h *ContentSourceHandler) Get(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	src, err := h.service.Get(r.Context(), a.TenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentSourceResponse(src, a.TenantID))
}

// Create handles POST /api/v1/content-sources
// @Summary      Create rule source
// @Description  Adds a git repository (https) the platform syncs rules from. The first sync is queued at once. Refused over the content_sources limit.
// @Tags         Rule Sources
// @Accept       json
// @Produce      json
// @Param        body  body      CreateContentSourceRequest  true  "Rule source"
// @Success      201  {object}  ContentSourceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources [post]
func (h *ContentSourceHandler) Create(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	var req CreateContentSourceRequest
	if !decodeContentSource(w, r, &req) {
		return
	}
	src, err := h.service.Create(r.Context(), a, contentsourceapp.CreateInput{
		Slug: req.Slug, Name: req.Name, Description: req.Description, Kind: req.Kind, URL: req.URL, Ref: req.Ref,
		Path: req.Path, CAPEM: req.CAPEM, LicenseSPDX: req.LicenseSPDX, LicenseService: req.LicenseServiceUse,
		Policy: req.PromotionPolicy, SyncIntervalMin: req.SyncIntervalMinutes, Enabled: req.Enabled,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toContentSourceResponse(src, a.TenantID))
}

// Update handles PUT /api/v1/content-sources/{id}
// @Summary      Update rule source
// @Description  Changes the organization's own rule source; absent fields stay. A new host clears the stored credential. Platform sources are read-only (403).
// @Tags         Rule Sources
// @Accept       json
// @Produce      json
// @Param        id    path      string                      true  "Rule source ID"
// @Param        body  body      UpdateContentSourceRequest  true  "Changes"
// @Success      200  {object}  ContentSourceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id} [put]
func (h *ContentSourceHandler) Update(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	var req UpdateContentSourceRequest
	if !decodeContentSource(w, r, &req) {
		return
	}
	src, err := h.service.Update(r.Context(), a, id, contentsourceapp.UpdateInput{
		Name: req.Name, Description: req.Description, URL: req.URL, Ref: req.Ref, Path: req.Path, CAPEM: req.CAPEM,
		LicenseSPDX: req.LicenseSPDX, LicenseService: req.LicenseServiceUse, Policy: req.PromotionPolicy,
		SyncIntervalMin: req.SyncIntervalMinutes, Enabled: req.Enabled,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentSourceResponse(src, a.TenantID))
}

// Delete handles DELETE /api/v1/content-sources/{id}
// @Summary      Delete rule source
// @Tags         Rule Sources
// @Param        id   path  string  true  "Rule source ID"
// @Success      204
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id} [delete]
func (h *ContentSourceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	if err := h.service.Delete(r.Context(), a, id); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetCredential handles PUT /api/v1/content-sources/{id}/credential
// @Summary      Set rule source credential
// @Description  Stores the fetch credential, encrypted and bound to the source's host. Write-only: it is never returned.
// @Tags         Rule Sources
// @Accept       json
// @Produce      json
// @Param        id    path      string                             true  "Rule source ID"
// @Param        body  body      SetContentSourceCredentialRequest  true  "Credential"
// @Success      200  {object}  ContentSourceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/credential [put]
func (h *ContentSourceHandler) SetCredential(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	var req SetContentSourceCredentialRequest
	if !decodeContentSource(w, r, &req) {
		return
	}
	src, err := h.service.SetCredential(r.Context(), a, id, req.Username, req.Token)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentSourceResponse(src, a.TenantID))
}

// ClearCredential handles DELETE /api/v1/content-sources/{id}/credential
// @Summary      Remove rule source credential
// @Tags         Rule Sources
// @Produce      json
// @Param        id   path      string  true  "Rule source ID"
// @Success      200  {object}  ContentSourceResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/credential [delete]
func (h *ContentSourceHandler) ClearCredential(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	src, err := h.service.ClearCredential(r.Context(), a, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentSourceResponse(src, a.TenantID))
}

// RotateWebhook handles POST /api/v1/content-sources/{id}/webhook
// @Summary      Set rule source webhook secret
// @Description  Turns the webhook on or rotates its secret. The secret is returned once; send it in X-OpenCTEM-Webhook-Token (or X-Gitlab-Token) to POST the path. A call only queues a sync.
// @Tags         Rule Sources
// @Produce      json
// @Param        id   path      string  true  "Rule source ID"
// @Success      200  {object}  ContentSourceWebhookSecretResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/webhook [post]
func (h *ContentSourceHandler) RotateWebhook(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	secret, err := h.service.RotateWebhookSecret(r.Context(), a, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeScanZoneJSON(w, http.StatusOK, ContentSourceWebhookSecretResponse{
		Path: "/hooks/content-sources/" + id.String(), Secret: secret, Header: contentSourceWebhookHeader,
	})
}

// DisableWebhook handles DELETE /api/v1/content-sources/{id}/webhook
// @Summary      Turn off rule source webhook
// @Tags         Rule Sources
// @Param        id   path  string  true  "Rule source ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/webhook [delete]
func (h *ContentSourceHandler) DisableWebhook(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	if err := h.service.DisableWebhook(r.Context(), a, id); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Sync handles POST /api/v1/content-sources/{id}/sync
// @Summary      Sync rule source now
// @Description  Queues a sync; the sync worker runs it within a minute.
// @Tags         Rule Sources
// @Param        id   path  string  true  "Rule source ID"
// @Success      202
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/sync [post]
func (h *ContentSourceHandler) Sync(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	if err := h.service.RequestSync(r.Context(), a, id); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *ContentSourceHandler) writeTest(w http.ResponseWriter, rep *contentsourceapp.Report, err error) {
	if err != nil {
		var se *contentsourceapp.SyncError
		if errors.As(err, &se) {
			writeScanZoneJSON(w, http.StatusOK, ContentSourceTestResponse{OK: false, Code: se.Code, Error: se.Message, Report: rep})
			return
		}
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, ContentSourceTestResponse{OK: true, Report: rep})
}

// Test handles POST /api/v1/content-sources/test
// @Summary      Test a rule source configuration
// @Description  Fetches, lints and counts the rules of a configuration without saving anything. 10 calls an hour.
// @Tags         Rule Sources
// @Accept       json
// @Produce      json
// @Param        body  body      TestContentSourceRequest  true  "Configuration"
// @Success      200  {object}  ContentSourceTestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/test [post]
func (h *ContentSourceHandler) Test(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	var req TestContentSourceRequest
	if !decodeContentSource(w, r, &req) {
		return
	}
	rep, err := h.service.Test(r.Context(), a, contentsourceapp.TestInput{
		Kind: req.Kind, URL: req.URL, Ref: req.Ref, Path: req.Path, Username: req.Username, Token: req.Token, CAPEM: req.CAPEM,
	})
	h.writeTest(w, rep, err)
}

// TestExisting handles POST /api/v1/content-sources/{id}/test
// @Summary      Test a saved rule source
// @Description  Like Test, starting from the saved source (its stored credential is used only while the host stays the same). Nothing is saved.
// @Tags         Rule Sources
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Rule source ID"
// @Param        body  body      TestContentSourceRequest  false "Overrides"
// @Success      200  {object}  ContentSourceTestResponse
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/test [post]
func (h *ContentSourceHandler) TestExisting(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	var req TestContentSourceRequest
	if r.ContentLength != 0 && !decodeContentSource(w, r, &req) {
		return
	}
	rep, err := h.service.Test(r.Context(), a, contentsourceapp.TestInput{
		SourceID: &id, URL: req.URL, Ref: req.Ref, Path: req.Path, Username: req.Username, Token: req.Token, CAPEM: req.CAPEM,
	})
	h.writeTest(w, rep, err)
}

// ListSnapshots handles GET /api/v1/content-sources/{id}/snapshots
// @Summary      List rule source snapshots
// @Tags         Rule Sources
// @Produce      json
// @Param        id        path      string  true   "Rule source ID"
// @Param        page      query     int     false  "Page (from 1)"
// @Param        per_page  query     int     false  "Page size (default 20, max 100)"
// @Success      200  {object}  ContentSnapshotListResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/snapshots [get]
func (h *ContentSourceHandler) ListSnapshots(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	page, ok := listPageMax(w, r, 20, 100)
	if !ok {
		return
	}
	src, err := h.service.Get(r.Context(), a.TenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	list, total, err := h.service.ListSnapshots(r.Context(), a.TenantID, id, page.Limit(), page.Offset())
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ContentSnapshotListResponse{Data: make([]ContentSnapshotResponse, 0, len(list)), Total: total}
	for _, sn := range list {
		resp.Data = append(resp.Data, toContentSnapshotResponse(sn, src, false))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// GetSnapshot handles GET /api/v1/content-sources/{id}/snapshots/{snapshot_id}
// @Summary      Get rule source snapshot
// @Description  One snapshot with its rule ids, file index, lint report and diff.
// @Tags         Rule Sources
// @Produce      json
// @Param        id           path      string  true  "Rule source ID"
// @Param        snapshot_id  path      string  true  "Snapshot ID"
// @Success      200  {object}  ContentSnapshotResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/snapshots/{snapshot_id} [get]
func (h *ContentSourceHandler) GetSnapshot(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	sid, ok := contentSourcePathID(w, r, "snapshot_id")
	if !ok {
		return
	}
	src, err := h.service.Get(r.Context(), a.TenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	sn, err := h.service.GetSnapshot(r.Context(), a.TenantID, id, sid)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentSnapshotResponse(sn, src, true))
}

// Promote handles POST /api/v1/content-sources/{id}/snapshots/{snapshot_id}/approve
// @Summary      Approve (promote) rule source snapshot
// @Description  Makes a candidate current (the current one becomes previous). A snapshot that needs review cannot be promoted by the member who last changed the source (four-eyes).
// @Tags         Rule Sources
// @Param        id           path  string  true  "Rule source ID"
// @Param        snapshot_id  path  string  true  "Snapshot ID"
// @Success      204
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/snapshots/{snapshot_id}/approve [post]
func (h *ContentSourceHandler) Promote(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	sid, ok := contentSourcePathID(w, r, "snapshot_id")
	if !ok {
		return
	}
	if err := h.service.Promote(r.Context(), a, id, sid); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Reject handles POST /api/v1/content-sources/{id}/snapshots/{snapshot_id}/reject
// @Summary      Reject rule source snapshot
// @Tags         Rule Sources
// @Accept       json
// @Param        id           path  string                        true   "Rule source ID"
// @Param        snapshot_id  path  string                        true   "Snapshot ID"
// @Param        body         body  RejectContentSnapshotRequest  false  "Reason"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/snapshots/{snapshot_id}/reject [post]
func (h *ContentSourceHandler) Reject(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	sid, ok := contentSourcePathID(w, r, "snapshot_id")
	if !ok {
		return
	}
	var req RejectContentSnapshotRequest
	if r.ContentLength != 0 && !decodeContentSource(w, r, &req) {
		return
	}
	if err := h.service.Reject(r.Context(), a, id, sid, req.Reason); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Rollback handles POST /api/v1/content-sources/{id}/rollback
// @Summary      Roll back rule source
// @Description  Makes the previous snapshot current again (and the current one previous).
// @Tags         Rule Sources
// @Produce      json
// @Param        id   path      string  true  "Rule source ID"
// @Success      200  {object}  ContentSourceResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-sources/{id}/rollback [post]
func (h *ContentSourceHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("Organization required").WriteJSON(w)
		return
	}
	id, ok := contentSourcePathID(w, r, "id")
	if !ok {
		return
	}
	src, err := h.service.Rollback(r.Context(), a, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentSourceResponse(src, a.TenantID))
}

// contentSourceWebhookHeader carries the webhook secret. A GitLab webhook's
// "secret token" arrives as X-Gitlab-Token, which is accepted too.
const contentSourceWebhookHeader = "X-OpenCTEM-Webhook-Token"

// Webhook handles POST /hooks/content-sources/{id} (public). The secret in
// the header is the credential; the body is ignored. Every refusal is the
// same 401, so the call reveals nothing about the source.
func (h *ContentSourceHandler) Webhook(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	secret := strings.TrimSpace(r.Header.Get(contentSourceWebhookHeader))
	if secret == "" {
		secret = strings.TrimSpace(r.Header.Get("X-Gitlab-Token"))
	}
	if err != nil || len(secret) > 256 {
		apierror.Unauthorized("Webhook rejected").WriteJSON(w)
		return
	}
	switch err := h.service.HandleWebhook(r.Context(), id, secret); {
	case err == nil:
		w.WriteHeader(http.StatusAccepted)
	case errors.Is(err, contentsourceapp.ErrWebhookRejected):
		apierror.Unauthorized("Webhook rejected").WriteJSON(w)
	case errors.Is(err, cs.ErrTooManyRequests):
		apierror.TooManyRequests("Too many webhook calls for this source").WriteJSON(w)
	default:
		h.logger.Error("rule source webhook error", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
	}
}
