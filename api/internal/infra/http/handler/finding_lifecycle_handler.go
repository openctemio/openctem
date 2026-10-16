package handler

// Finding lifecycles (docs/rfcs/RFC-110-tenant-lifecycles.md): the
// organization's sub-status catalog and its lifecycle schemes with their
// versions. The tenant comes from the token; every object of another
// organization is 404. Reads need findings:read; changes need
// findings:lifecycles:write; publishing also needs a recent sign-in.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	lcapp "github.com/openctemio/openctem/api/internal/app/findinglifecycle"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FindingLifecycleHandler serves the lifecycle catalog and schemes.
type FindingLifecycleHandler struct {
	service *lcapp.Service
	logger  *logger.Logger
}

// NewFindingLifecycleHandler creates the handler.
func NewFindingLifecycleHandler(svc *lcapp.Service, log *logger.Logger) *FindingLifecycleHandler {
	return &FindingLifecycleHandler{service: svc, logger: log.With("handler", "finding_lifecycle")}
}

// LifecycleSubStatusRequest creates a sub-status; on PATCH only the
// presentation fields apply (the key, canonical status and closure reason
// never change).
type LifecycleSubStatusRequest struct {
	Key             string            `json:"key,omitempty"`
	CanonicalStatus string            `json:"canonical_status,omitempty" enums:"new,confirmed,in_progress,fix_applied,resolved,false_positive,accepted,duplicate"`
	ClosureReason   string            `json:"closure_reason,omitempty"`
	Name            *string           `json:"name,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Description     *string           `json:"description,omitempty"`
	Color           *string           `json:"color,omitempty"`
	SortOrder       *int              `json:"sort_order,omitempty"`
}

// LifecycleSubStatusResponse is a sub-status.
type LifecycleSubStatusResponse struct {
	ID              string            `json:"id"`
	Key             string            `json:"key"`
	CanonicalStatus string            `json:"canonical_status"`
	ClosureReason   string            `json:"closure_reason,omitempty"`
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	Description     string            `json:"description"`
	Color           string            `json:"color"`
	SortOrder       int               `json:"sort_order"`
	Archived        bool              `json:"archived"`
	ArchivedAt      *time.Time        `json:"archived_at,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// LifecycleSubStatusListResponse lists the catalog.
type LifecycleSubStatusListResponse struct {
	Data []LifecycleSubStatusResponse `json:"data"`
	// Colors is the palette a sub-status picks from.
	Colors []string `json:"colors"`
}

func toSubStatusResponse(s *lc.SubStatus) LifecycleSubStatusResponse {
	return LifecycleSubStatusResponse{
		ID: s.ID().String(), Key: s.Key(), CanonicalStatus: string(s.CanonicalStatus()),
		ClosureReason: string(s.ClosureReason()), Name: s.Name(), Labels: s.Labels(), Description: s.Description(),
		Color: s.Color(), SortOrder: s.SortOrder(), Archived: s.IsArchived(), ArchivedAt: s.ArchivedAt(),
		CreatedAt: s.CreatedAt(), UpdatedAt: s.UpdatedAt(),
	}
}

// LifecycleRequest creates or changes a lifecycle scheme. An empty context
// makes it the default scheme; otherwise it applies to the findings its
// conditions select, the lowest priority first.
type LifecycleRequest struct {
	Key         string          `json:"key,omitempty"`
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Priority    *int            `json:"priority,omitempty"`
	Context     *[]lc.Condition `json:"context,omitempty"`
}

// LifecycleVersionResponse is one version of a scheme.
type LifecycleVersionResponse struct {
	Version     int        `json:"version"`
	State       string     `json:"state" enums:"draft,published,superseded"`
	Spec        lc.Spec    `json:"spec"`
	SpecHash    string     `json:"spec_hash"`
	Note        string     `json:"note"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	PublishedBy string     `json:"published_by,omitempty"`
}

// LifecycleResponse is a scheme with its published and draft versions.
type LifecycleResponse struct {
	ID          string                    `json:"id"`
	Key         string                    `json:"key"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Priority    int                       `json:"priority"`
	Default     bool                      `json:"default"`
	Context     []lc.Condition            `json:"context"`
	Archived    bool                      `json:"archived"`
	Published   *LifecycleVersionResponse `json:"published,omitempty"`
	Draft       *LifecycleVersionResponse `json:"draft,omitempty"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
}

// LifecycleListResponse lists the schemes.
type LifecycleListResponse struct {
	Data []LifecycleResponse `json:"data"`
}

// LifecycleVersionListResponse lists a scheme's versions, newest first.
type LifecycleVersionListResponse struct {
	Data []LifecycleVersionResponse `json:"data"`
}

// LifecycleDraftRequest starts a draft from a version (0 or absent: the
// published one).
type LifecycleDraftRequest struct {
	From int `json:"from,omitempty"`
}

// LifecycleDraftUpdateRequest replaces a draft's spec. Send the spec_hash you
// read in the If-Match header.
type LifecycleDraftUpdateRequest struct {
	Spec json.RawMessage `json:"spec" swaggertype:"object"`
	Note string          `json:"note,omitempty"`
}

// LifecycleValidationResponse is a version's validation against the
// current catalog.
type LifecycleValidationResponse struct {
	Valid      bool          `json:"valid"`
	Validation lc.Validation `json:"validation"`
	// Version is set when the request changed a draft.
	Version *LifecycleVersionResponse `json:"version,omitempty"`
}

// LifecyclePublishRequest publishes a version: a draft is put in force; an
// older version is published again as a new version copied from it.
type LifecyclePublishRequest struct {
	Note string `json:"note,omitempty"`
}

func toVersionResponse(v *lc.Version) *LifecycleVersionResponse {
	if v == nil {
		return nil
	}
	spec := v.Spec
	if spec.SubStatuses == nil {
		spec.SubStatuses = []string{}
	}
	if spec.Transitions == nil {
		spec.Transitions = []lc.TransitionSpec{}
	}
	out := &LifecycleVersionResponse{
		Version: v.Number, State: string(v.State), Spec: spec, SpecHash: v.SpecHash, Note: v.Note,
		CreatedAt: v.CreatedAt, PublishedAt: v.PublishedAt,
	}
	if v.CreatedBy != nil {
		out.CreatedBy = v.CreatedBy.String()
	}
	if v.PublishedBy != nil {
		out.PublishedBy = v.PublishedBy.String()
	}
	return out
}

func toLifecycleResponse(v lcapp.SchemeView) LifecycleResponse {
	s := v.Scheme
	ctxConds := s.Context()
	if ctxConds == nil {
		ctxConds = []lc.Condition{}
	}
	return LifecycleResponse{
		ID: s.ID().String(), Key: s.Key(), Name: s.Name(), Description: s.Description(), Priority: s.Priority(),
		Default: s.IsDefault(), Context: ctxConds, Archived: s.IsArchived(),
		Published: toVersionResponse(v.Published), Draft: toVersionResponse(v.Draft),
		CreatedAt: s.CreatedAt(), UpdatedAt: s.UpdatedAt(),
	}
}

// ---- helpers ----

func (h *FindingLifecycleHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}

func (h *FindingLifecycleHandler) actor(r *http.Request) lcapp.Actor {
	a := lcapp.Actor{Audit: auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
		SessionID:  middleware.GetSessionID(r.Context()),
	}}
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil && !uid.IsZero() {
		a.UserID = &uid
	}
	return a
}

func lifecyclePathID(w http.ResponseWriter, r *http.Request, name string) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, name))
	if err != nil {
		apierror.NotFound("Lifecycle").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func lifecyclePathVersion(w http.ResponseWriter, r *http.Request) (int, bool) {
	n, err := strconv.Atoi(chi.URLParam(r, "version_id"))
	if err != nil || n < 1 {
		apierror.NotFound("Lifecycle version").WriteJSON(w)
		return 0, false
	}
	return n, true
}

// decodeLifecycleBody reads a JSON body of at most the spec limit plus room
// for the envelope; an empty body decodes to the zero value.
func decodeLifecycleBody(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, lc.MaxSpecBytes+(8<<10)))
	if err != nil {
		apierror.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "The request body is too large").WriteJSON(w)
		return false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return true
	}
	if err := json.Unmarshal(body, v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func (h *FindingLifecycleHandler) writeError(w http.ResponseWriter, err error) {
	var invalid *lcapp.ErrInvalidLifecycle
	switch {
	case WriteLimitError(w, err):
	case errors.As(err, &invalid):
		apierror.ValidationFailed("The lifecycle is not valid", LifecycleValidationResponse{Validation: invalid.Validation}).WriteJSON(w)
	case errors.Is(err, lc.ErrSubStatusNotFound):
		apierror.NotFound("Sub-status").WriteJSON(w)
	case errors.Is(err, lc.ErrVersionNotFound):
		apierror.NotFound("Lifecycle version").WriteJSON(w)
	case errors.Is(err, lc.ErrSchemeNotFound), errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Lifecycle").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(validationText(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(validationText(err)).WriteJSON(w)
	default:
		h.logger.Error("finding lifecycle request failed", "error", err)
		apierror.InternalServerError("The lifecycle request failed").WriteJSON(w)
	}
}

// validationText is the sentence of a validation or conflict error without
// its kind prefix.
func validationText(err error) string {
	msg := err.Error()
	for _, kind := range []error{shared.ErrValidation, shared.ErrConflict} {
		msg = strings.TrimPrefix(msg, kind.Error()+": ")
	}
	return msg
}

func writeLifecycleJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- sub-statuses ----

// ListSubStatuses handles GET /api/v1/lifecycle-sub-statuses
// @Summary      List finding sub-statuses
// @Description  The organization's sub-statuses in lifecycle order. Archived ones only with include_archived=true.
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        include_archived query bool false "Include archived sub-statuses"
// @Success      200 {object} LifecycleSubStatusListResponse
// @Failure      401 {object} apierror.Error
// @Failure      403 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycle-sub-statuses [get]
func (h *FindingLifecycleHandler) ListSubStatuses(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	subs, err := h.service.ListSubStatuses(r.Context(), tid, r.URL.Query().Get("include_archived") == "true")
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := LifecycleSubStatusListResponse{Data: make([]LifecycleSubStatusResponse, 0, len(subs)), Colors: lc.Colors}
	for _, s := range subs {
		out.Data = append(out.Data, toSubStatusResponse(s))
	}
	writeLifecycleJSON(w, http.StatusOK, out)
}

// CreateSubStatus handles POST /api/v1/lifecycle-sub-statuses
// @Summary      Create a finding sub-status
// @Description  A label bound for ever to one canonical status (and, under a closed status, to one of its closure reasons). Counts against the plan's sub-status limit.
// @Tags         Finding Lifecycles
// @Accept       json
// @Produce      json
// @Param        body body LifecycleSubStatusRequest true "Sub-status"
// @Success      201 {object} LifecycleSubStatusResponse
// @Failure      400 {object} apierror.Error
// @Failure      403 {object} apierror.Error
// @Failure      409 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycle-sub-statuses [post]
func (h *FindingLifecycleHandler) CreateSubStatus(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req LifecycleSubStatusRequest
	if !decodeLifecycleBody(w, r, &req) {
		return
	}
	in := lc.SubStatusInput{Key: req.Key, CanonicalStatus: req.CanonicalStatus, ClosureReason: req.ClosureReason, Labels: req.Labels}
	if req.Name != nil {
		in.Name = *req.Name
	}
	if req.Description != nil {
		in.Description = *req.Description
	}
	if req.Color != nil {
		in.Color = *req.Color
	}
	if req.SortOrder != nil {
		in.SortOrder = *req.SortOrder
	}
	sub, err := h.service.CreateSubStatus(r.Context(), tid, in, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusCreated, toSubStatusResponse(sub))
}

// UpdateSubStatus handles PATCH /api/v1/lifecycle-sub-statuses/{id}
// @Summary      Change a finding sub-status
// @Description  Name, per-language labels, description, color and order. The key, canonical status and closure reason never change.
// @Tags         Finding Lifecycles
// @Accept       json
// @Produce      json
// @Param        id   path string true "Sub-status ID"
// @Param        body body LifecycleSubStatusRequest true "Changes"
// @Success      200 {object} LifecycleSubStatusResponse
// @Failure      400 {object} apierror.Error
// @Failure      404 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycle-sub-statuses/{id} [patch]
func (h *FindingLifecycleHandler) UpdateSubStatus(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	var req LifecycleSubStatusRequest
	if !decodeLifecycleBody(w, r, &req) {
		return
	}
	if req.Key != "" || req.CanonicalStatus != "" || req.ClosureReason != "" {
		h.writeError(w, lc.ErrCategoryImmutable)
		return
	}
	sub, err := h.service.UpdateSubStatus(r.Context(), tid, id, lc.SubStatusUpdate{
		Name: req.Name, Labels: req.Labels, Description: req.Description, Color: req.Color, SortOrder: req.SortOrder,
	}, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, toSubStatusResponse(sub))
}

// ArchiveSubStatus handles DELETE /api/v1/lifecycle-sub-statuses/{id}
// @Summary      Archive a finding sub-status
// @Description  A sub-status is never deleted: archived, it is no longer offered; findings that carry it keep it until they move. Refused while a published lifecycle uses it.
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        id path string true "Sub-status ID"
// @Success      200 {object} LifecycleSubStatusResponse
// @Failure      404 {object} apierror.Error
// @Failure      409 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycle-sub-statuses/{id} [delete]
func (h *FindingLifecycleHandler) ArchiveSubStatus(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	sub, err := h.service.ArchiveSubStatus(r.Context(), tid, id, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, toSubStatusResponse(sub))
}

// ReactivateSubStatus handles POST /api/v1/lifecycle-sub-statuses/{id}/reactivate
// @Summary      Bring an archived finding sub-status back
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        id path string true "Sub-status ID"
// @Success      200 {object} LifecycleSubStatusResponse
// @Failure      403 {object} apierror.Error
// @Failure      404 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycle-sub-statuses/{id}/reactivate [post]
func (h *FindingLifecycleHandler) ReactivateSubStatus(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	sub, err := h.service.RestoreSubStatus(r.Context(), tid, id, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, toSubStatusResponse(sub))
}

// ---- schemes ----

// ListLifecycles handles GET /api/v1/lifecycles
// @Summary      List finding lifecycles
// @Description  The default lifecycle first, then the context lifecycles by priority, each with its published and draft versions.
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        include_archived query bool false "Include archived lifecycles"
// @Success      200 {object} LifecycleListResponse
// @Security     BearerAuth
// @Router       /lifecycles [get]
func (h *FindingLifecycleHandler) ListLifecycles(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	views, err := h.service.ListSchemes(r.Context(), tid, r.URL.Query().Get("include_archived") == "true")
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := LifecycleListResponse{Data: make([]LifecycleResponse, 0, len(views))}
	for _, v := range views {
		out.Data = append(out.Data, toLifecycleResponse(v))
	}
	writeLifecycleJSON(w, http.StatusOK, out)
}

// GetLifecycle handles GET /api/v1/lifecycles/{id}
// @Summary      Get a finding lifecycle
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        id path string true "Lifecycle ID"
// @Success      200 {object} LifecycleResponse
// @Failure      404 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id} [get]
func (h *FindingLifecycleHandler) GetLifecycle(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	v, err := h.service.GetScheme(r.Context(), tid, id)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, toLifecycleResponse(v))
}

// CreateLifecycle handles POST /api/v1/lifecycles
// @Summary      Create a finding lifecycle
// @Description  Creates the lifecycle with an empty first draft. Without a context it is the organization's default lifecycle (one at most). Counts against the plan's lifecycle limit.
// @Tags         Finding Lifecycles
// @Accept       json
// @Produce      json
// @Param        body body LifecycleRequest true "Lifecycle"
// @Success      201 {object} LifecycleResponse
// @Failure      400 {object} apierror.Error
// @Failure      403 {object} apierror.Error
// @Failure      409 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles [post]
func (h *FindingLifecycleHandler) CreateLifecycle(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req LifecycleRequest
	if !decodeLifecycleBody(w, r, &req) {
		return
	}
	in := lc.SchemeInput{Key: req.Key}
	if req.Name != nil {
		in.Name = *req.Name
	}
	if req.Description != nil {
		in.Description = *req.Description
	}
	if req.Priority != nil {
		in.Priority = *req.Priority
	}
	if req.Context != nil {
		in.Context = *req.Context
	}
	v, err := h.service.CreateScheme(r.Context(), tid, in, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusCreated, toLifecycleResponse(v))
}

// UpdateLifecycle handles PATCH /api/v1/lifecycles/{id}
// @Summary      Change a finding lifecycle
// @Description  Name, description, priority and context (an empty context makes it the default lifecycle). The rules live in its versions.
// @Tags         Finding Lifecycles
// @Accept       json
// @Produce      json
// @Param        id   path string true "Lifecycle ID"
// @Param        body body LifecycleRequest true "Changes"
// @Success      200 {object} LifecycleResponse
// @Failure      400 {object} apierror.Error
// @Failure      404 {object} apierror.Error
// @Failure      409 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id} [patch]
func (h *FindingLifecycleHandler) UpdateLifecycle(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	var req LifecycleRequest
	if !decodeLifecycleBody(w, r, &req) {
		return
	}
	if req.Key != "" {
		apierror.BadRequest("the key of a lifecycle cannot change").WriteJSON(w)
		return
	}
	v, err := h.service.UpdateScheme(r.Context(), tid, id, lc.SchemeUpdate{
		Name: req.Name, Description: req.Description, Priority: req.Priority, Context: req.Context,
	}, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, toLifecycleResponse(v))
}

// ArchiveLifecycle handles DELETE /api/v1/lifecycles/{id}
// @Summary      Archive a finding lifecycle
// @Description  The lifecycle stops applying to findings; its versions stay as history.
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        id path string true "Lifecycle ID"
// @Success      200 {object} LifecycleResponse
// @Failure      404 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id} [delete]
func (h *FindingLifecycleHandler) ArchiveLifecycle(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	v, err := h.service.ArchiveScheme(r.Context(), tid, id, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, toLifecycleResponse(v))
}

// ---- versions ----

// ListLifecycleVersions handles GET /api/v1/lifecycles/{id}/versions
// @Summary      List a finding lifecycle's versions
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        id path string true "Lifecycle ID"
// @Success      200 {object} LifecycleVersionListResponse
// @Failure      404 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id}/versions [get]
func (h *FindingLifecycleHandler) ListLifecycleVersions(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	versions, err := h.service.ListVersions(r.Context(), tid, id)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := LifecycleVersionListResponse{Data: make([]LifecycleVersionResponse, 0, len(versions))}
	for _, v := range versions {
		out.Data = append(out.Data, *toVersionResponse(v))
	}
	writeLifecycleJSON(w, http.StatusOK, out)
}

// GetLifecycleVersion handles GET /api/v1/lifecycles/{id}/versions/{version_id}
// @Summary      Get a finding lifecycle version
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        id      path string true "Lifecycle ID"
// @Param        version_id path int    true "Version number"
// @Success      200 {object} LifecycleVersionResponse
// @Failure      404 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id}/versions/{version_id} [get]
func (h *FindingLifecycleHandler) GetLifecycleVersion(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	n, ok := lifecyclePathVersion(w, r)
	if !ok {
		return
	}
	v, err := h.service.GetVersion(r.Context(), tid, id, n)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, toVersionResponse(v))
}

// CreateLifecycleDraft handles POST /api/v1/lifecycles/{id}/versions
// @Summary      Start a draft of a finding lifecycle
// @Description  Copies a version (from; absent: the published one) into a new draft. A lifecycle has one draft at a time.
// @Tags         Finding Lifecycles
// @Accept       json
// @Produce      json
// @Param        id   path string true "Lifecycle ID"
// @Param        body body LifecycleDraftRequest false "Source version"
// @Success      201 {object} LifecycleVersionResponse
// @Failure      404 {object} apierror.Error
// @Failure      409 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id}/versions [post]
func (h *FindingLifecycleHandler) CreateLifecycleDraft(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	var req LifecycleDraftRequest
	if !decodeLifecycleBody(w, r, &req) {
		return
	}
	v, err := h.service.CreateDraft(r.Context(), tid, id, req.From, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusCreated, toVersionResponse(v))
}

// UpdateLifecycleDraft handles PUT /api/v1/lifecycles/{id}/versions/{version_id}
// @Summary      Change a finding lifecycle draft
// @Description  Replaces the draft's spec. If-Match must carry the spec_hash you read: a draft changed since answers 409. The answer includes the validation against the current catalog.
// @Tags         Finding Lifecycles
// @Accept       json
// @Produce      json
// @Param        id       path   string true "Lifecycle ID"
// @Param        version_id path int true "Version number"
// @Param        If-Match header string true "spec_hash of the draft as read"
// @Param        body     body   LifecycleDraftUpdateRequest true "Spec"
// @Success      200 {object} LifecycleValidationResponse
// @Failure      400 {object} apierror.Error
// @Failure      404 {object} apierror.Error
// @Failure      409 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id}/versions/{version_id} [put]
func (h *FindingLifecycleHandler) UpdateLifecycleDraft(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	n, ok := lifecyclePathVersion(w, r)
	if !ok {
		return
	}
	var req LifecycleDraftUpdateRequest
	if !decodeLifecycleBody(w, r, &req) {
		return
	}
	if len(req.Spec) == 0 {
		apierror.BadRequest("spec is required").WriteJSON(w)
		return
	}
	ifMatch := strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`)
	v, validation, err := h.service.UpdateDraft(r.Context(), tid, id, n, req.Spec, req.Note, ifMatch)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, LifecycleValidationResponse{Valid: validation.OK(), Validation: normalizeValidation(validation), Version: toVersionResponse(v)})
}

func normalizeValidation(v lc.Validation) lc.Validation {
	if v.Errors == nil {
		v.Errors = []lc.Issue{}
	}
	if v.Warnings == nil {
		v.Warnings = []lc.Issue{}
	}
	return v
}

// TestLifecycleVersion handles POST /api/v1/lifecycles/{id}/versions/{version_id}/test
// @Summary      Validate a finding lifecycle version
// @Description  Compiles the version against the current catalog: errors block publishing, warnings do not.
// @Tags         Finding Lifecycles
// @Produce      json
// @Param        id      path string true "Lifecycle ID"
// @Param        version_id path int    true "Version number"
// @Success      200 {object} LifecycleValidationResponse
// @Failure      404 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id}/versions/{version_id}/test [post]
func (h *FindingLifecycleHandler) TestLifecycleVersion(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	n, ok := lifecyclePathVersion(w, r)
	if !ok {
		return
	}
	validation, err := h.service.ValidateVersion(r.Context(), tid, id, n)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, LifecycleValidationResponse{Valid: validation.OK(), Validation: normalizeValidation(validation)})
}

// PublishLifecycleVersion handles POST /api/v1/lifecycles/{id}/versions/{version_id}/publish
// @Summary      Publish a finding lifecycle version
// @Description  A draft is put in force; an older version is published again as a new version copied from it (a roll back). Needs a recent sign-in (403 STEP_UP_REQUIRED otherwise). Audited.
// @Tags         Finding Lifecycles
// @Accept       json
// @Produce      json
// @Param        id      path string true "Lifecycle ID"
// @Param        version_id path int    true "Version number"
// @Param        body    body LifecyclePublishRequest false "Note"
// @Success      200 {object} LifecycleVersionResponse
// @Failure      403 {object} apierror.Error
// @Failure      404 {object} apierror.Error
// @Failure      409 {object} apierror.Error
// @Failure      422 {object} apierror.Error
// @Security     BearerAuth
// @Router       /lifecycles/{id}/versions/{version_id}/publish [post]
func (h *FindingLifecycleHandler) PublishLifecycleVersion(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := lifecyclePathID(w, r, "id")
	if !ok {
		return
	}
	n, ok := lifecyclePathVersion(w, r)
	if !ok {
		return
	}
	var req LifecyclePublishRequest
	if !decodeLifecycleBody(w, r, &req) {
		return
	}
	v, err := h.service.Publish(r.Context(), tid, id, n, req.Note, h.actor(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeLifecycleJSON(w, http.StatusOK, toVersionResponse(v))
}
