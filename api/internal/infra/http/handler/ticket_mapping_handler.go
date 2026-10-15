package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	appticketmap "github.com/openctemio/openctem/api/internal/app/ticketmap"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TicketMappingHandler serves the ticket field and status mapping editor
// (docs/rfcs/RFC-097-ticket-field-mapping.md).
type TicketMappingHandler struct {
	svc    *appticketmap.Service
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// NewTicketMappingHandler builds the handler.
func NewTicketMappingHandler(svc *appticketmap.Service, audit *auditapp.AuditService, log *logger.Logger) *TicketMappingHandler {
	return &TicketMappingHandler{svc: svc, audit: audit, logger: log}
}

// maxMappingBody bounds every request body (a spec is at most 256 KiB).
const maxMappingBody = ticketmap.MaxDocumentBytes + 16*1024

func (h *TicketMappingHandler) tenant(r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	return tid, err == nil
}

func mappingActor(r *http.Request) *shared.ID {
	if id := middleware.GetLocalUserID(r.Context()); !id.IsZero() {
		return &id
	}
	return nil
}

func (h *TicketMappingHandler) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxMappingBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func (h *TicketMappingHandler) fail(w http.ResponseWriter, err error) {
	var ve *appticketmap.ValidationError
	switch {
	case errors.As(err, &ve):
		apierror.ValidationFailed("the mapping has errors", map[string]any{"issues": ve.Issues}).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("mapping or object").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.SafeConflict(err).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.SafeBadRequest(err).WriteJSON(w)
	default:
		h.logger.Error("ticket mapping request failed", "error", logger.SanitizeValue(err.Error()))
		apierror.BadGateway("the tracker request failed").WriteJSON(w)
	}
}

func (h *TicketMappingHandler) auditMapping(r *http.Request, action auditdom.Action, p *ticketmap.Profile, before, after any, msg string) {
	if p == nil {
		return
	}
	ev := auditapp.NewChangeEvent(action, auditdom.ResourceTypeTicketMapping, p.ID.String(), before, after).
		WithResourceName(p.Name).
		WithSeverity(auditdom.SeverityMedium).
		WithMessage(msg).
		WithMetadata("integration_id", p.IntegrationID.String()).
		WithMetadata("project_key", p.ProjectKey).
		WithMetadata("object_kind", string(p.ObjectKind))
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r), ev)
}

func mappingID(r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "mapping_id"))
	return id, err == nil
}

func versionParam(r *http.Request, key string) int { return max(0, queryInt(r, key)) }

// Catalog handles GET /api/v1/integrations/ticket-mappings/catalog?object_kind=.
//
//	@Summary		Ticket mapping editor catalog
//	@Description	Attributes, template filters, states, intents and presets for one object kind (finding or task).
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			object_kind	query	string	true	"finding or task"
//	@Success		200	{object}	appticketmap.CatalogView
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/catalog [get]
func (h *TicketMappingHandler) Catalog(w http.ResponseWriter, r *http.Request) {
	c, err := h.svc.Catalog(ticketmap.ObjectKind(r.URL.Query().Get("object_kind")))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// List handles GET /api/v1/integrations/ticket-mappings.
//
//	@Summary		List ticket mapping profiles
//	@Description	The organization's field and status mapping profiles.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			integration_id	query	string	false	"Integration ID"
//	@Param			object_kind	query	string	false	"finding or task"
//	@Param			project_key	query	string	false	"Project key"
//	@Param			page	query	int	false	"Page"
//	@Param			per_page	query	int	false	"Page size"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings [get]
func (h *TicketMappingHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	page, err := pagination.FromRequestMax(r.URL.Query(), 50, 200)
	if err != nil {
		apierror.BadRequest("invalid pagination").WriteJSON(w)
		return
	}
	f := ticketmap.ProfileFilter{ObjectKind: ticketmap.ObjectKind(r.URL.Query().Get("object_kind")), ProjectKey: strings.ToUpper(r.URL.Query().Get("project_key"))}
	if s := r.URL.Query().Get("integration_id"); s != "" {
		iid, err := shared.IDFromString(s)
		if err != nil {
			apierror.BadRequest("invalid integration_id").WriteJSON(w)
			return
		}
		f.IntegrationID = &iid
	}
	res, err := h.svc.ListProfiles(r.Context(), tid, f, page)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type CreateTicketMappingRequest struct {
	IntegrationID string `json:"integration_id"`
	ObjectKind    string `json:"object_kind"`
	ProjectKey    string `json:"project_key"`
	ProjectID     string `json:"project_id"`
	IssueTypeID   string `json:"issue_type_id"`
	IssueType     string `json:"issue_type"`
	Name          string `json:"name"`
	Preset        string `json:"preset"`
}

func (req CreateTicketMappingRequest) input(tid shared.ID, by *shared.ID) (appticketmap.CreateProfileInput, error) {
	iid, err := shared.IDFromString(req.IntegrationID)
	if err != nil {
		return appticketmap.CreateProfileInput{}, fmt.Errorf("%w: invalid integration_id", shared.ErrValidation)
	}
	return appticketmap.CreateProfileInput{
		TenantID: tid, IntegrationID: iid, ObjectKind: ticketmap.ObjectKind(req.ObjectKind),
		ProjectKey: req.ProjectKey, ProjectID: req.ProjectID, IssueTypeID: req.IssueTypeID, IssueType: req.IssueType,
		Name: req.Name, Preset: req.Preset, By: by,
	}, nil
}

// Create handles POST /api/v1/integrations/ticket-mappings.
//
//	@Summary		Create a ticket mapping profile
//	@Description	Creates the profile of one destination (integration, project, issue type, object kind) with a first draft, from a preset when given. integrations:manage.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			body	body	CreateTicketMappingRequest	true	"Request"
//	@Success		201	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings [post]
func (h *TicketMappingHandler) Create(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	var req CreateTicketMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	in, err := req.input(tid, mappingActor(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	view, issues, err := h.svc.CreateProfile(r.Context(), in)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.auditMapping(r, auditdom.ActionTicketMappingCreated, view.Profile, nil, view.Profile, fmt.Sprintf("Ticket mapping %q created", view.Profile.Name))
	writeJSON(w, http.StatusCreated, map[string]any{"mapping": view, "issues": issues})
}

// Get handles GET /api/v1/integrations/ticket-mappings/{mapping_id}.
//
//	@Summary		Get a ticket mapping profile
//	@Description	The profile with its published and draft versions.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Success		200	{object}	appticketmap.ProfileView
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id} [get]
func (h *TicketMappingHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	view, err := h.svc.GetProfile(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// Delete handles DELETE /api/v1/integrations/ticket-mappings/{mapping_id}.
//
//	@Summary		Delete a ticket mapping profile
//	@Description	The destination falls back to the built-in mapping.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Success		204
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id} [delete]
func (h *TicketMappingHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	view, err := h.svc.GetProfile(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if err := h.svc.DeleteProfile(r.Context(), tid, id); err != nil {
		h.fail(w, err)
		return
	}
	h.auditMapping(r, auditdom.ActionTicketMappingDeleted, view.Profile, view.Profile, nil, fmt.Sprintf("Ticket mapping %q deleted", view.Profile.Name))
	w.WriteHeader(http.StatusNoContent)
}

type SaveTicketMappingDraftRequest struct {
	Spec          ticketmap.Spec `json:"spec"`
	Note          string         `json:"note"`
	ExpectedDraft int            `json:"expected_draft"`
}

// SaveDraft handles PUT /api/v1/integrations/ticket-mappings/{mapping_id}/draft.
//
//	@Summary		Save the draft of a ticket mapping
//	@Description	Creates or replaces the open draft; returns the validation issues against the live tracker. expected_draft guards concurrent editors.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	SaveTicketMappingDraftRequest	true	"Request"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/draft [put]
func (h *TicketMappingHandler) SaveDraft(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req SaveTicketMappingDraftRequest
	if !h.decode(w, r, &req) {
		return
	}
	before, err := h.svc.GetProfile(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	v, issues, err := h.svc.SaveDraft(r.Context(), tid, id, req.Spec, req.Note, req.ExpectedDraft, mappingActor(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	var prev any
	if before.Draft != nil {
		prev = before.Draft.Spec
	} else if before.Published != nil {
		prev = before.Published.Spec
	}
	h.auditMapping(r, auditdom.ActionTicketMappingUpdated, before.Profile, prev, v.Spec, fmt.Sprintf("Ticket mapping %q draft v%d saved", before.Profile.Name, v.Version))
	writeJSON(w, http.StatusOK, map[string]any{"version": v, "issues": issues})
}

// DiscardDraft handles DELETE /api/v1/integrations/ticket-mappings/{mapping_id}/draft.
//
//	@Summary		Discard the draft of a ticket mapping
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Success		204
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/draft [delete]
func (h *TicketMappingHandler) DiscardDraft(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	if err := h.svc.DiscardDraft(r.Context(), tid, id); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type PublishTicketMappingRequest struct {
	Draft int `json:"draft"`
}

// Publish handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/publish.
//
//	@Summary		Publish a ticket mapping draft
//	@Description	Publishes the open draft when it has no validation errors (422 with the issues otherwise). Needs a recent step-up.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	PublishTicketMappingRequest	true	"Request"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/publish [post]
func (h *TicketMappingHandler) Publish(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req PublishTicketMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	before, err := h.svc.GetProfile(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	v, issues, err := h.svc.Publish(r.Context(), tid, id, req.Draft, mappingActor(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	var prev any
	if before.Published != nil {
		prev = before.Published.Spec
	}
	h.auditMapping(r, auditdom.ActionTicketMappingPublished, before.Profile, prev, v.Spec, fmt.Sprintf("Ticket mapping %q version %d published", before.Profile.Name, v.Version))
	writeJSON(w, http.StatusOK, map[string]any{"version": v, "issues": issues})
}

type TicketMappingVersionRequest struct {
	Version int `json:"version"`
}

// Rollback handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/rollback.
//
//	@Summary		Copy an earlier version into the draft
//	@Description	History is never rewritten: the version becomes the draft, to review and publish.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	TicketMappingVersionRequest	true	"Request"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/rollback [post]
func (h *TicketMappingHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req TicketMappingVersionRequest
	if !h.decode(w, r, &req) {
		return
	}
	v, issues, err := h.svc.Rollback(r.Context(), tid, id, req.Version, mappingActor(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	if view, gerr := h.svc.GetProfile(r.Context(), tid, id); gerr == nil {
		h.auditMapping(r, auditdom.ActionTicketMappingUpdated, view.Profile, nil, v.Spec, fmt.Sprintf("Ticket mapping %q: version %d copied to the draft", view.Profile.Name, req.Version))
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": v, "issues": issues})
}

type TicketMappingDryRunRequest struct {
	DryRun bool `json:"dry_run"`
}

// SetDryRun handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/dry-run.
//
//	@Summary		Switch a ticket mapping to dry run
//	@Description	In dry run the published version renders and logs only. Needs a recent step-up.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	TicketMappingDryRunRequest	true	"Request"
//	@Success		204
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/dry-run [post]
func (h *TicketMappingHandler) SetDryRun(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req TicketMappingDryRunRequest
	if !h.decode(w, r, &req) {
		return
	}
	view, err := h.svc.GetProfile(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if err := h.svc.UpdateDryRun(r.Context(), tid, id, req.DryRun); err != nil {
		h.fail(w, err)
		return
	}
	h.auditMapping(r, auditdom.ActionTicketMappingUpdated, view.Profile, map[string]bool{"dry_run": view.Profile.DryRun}, map[string]bool{"dry_run": req.DryRun}, "Ticket mapping dry run changed")
	w.WriteHeader(http.StatusNoContent)
}

// Versions handles GET /api/v1/integrations/ticket-mappings/{mapping_id}/versions.
//
//	@Summary		List the versions of a ticket mapping
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/versions [get]
func (h *TicketMappingHandler) Versions(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	vs, err := h.svc.ListVersions(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if vs == nil {
		vs = []*ticketmap.Version{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": vs})
}

// Diff handles GET /api/v1/integrations/ticket-mappings/{mapping_id}/diff?from=&to=.
//
//	@Summary		Compare two versions of a ticket mapping
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			from	query	int	true	"From version"
//	@Param			to	query	int	true	"To version"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/diff [get]
func (h *TicketMappingHandler) Diff(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	changes, err := h.svc.Diff(r.Context(), tid, id, versionParam(r, "from"), versionParam(r, "to"))
	if err != nil {
		h.fail(w, err)
		return
	}
	if changes == nil {
		changes = []ticketmap.Change{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": changes})
}

// Validate handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/verify?version=.
//
//	@Summary		Check a ticket mapping against the tracker
//	@Description	Validation issues of a version (0 = the draft) against the live fields and workflow.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			version	query	int	false	"Version"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/verify [post]
func (h *TicketMappingHandler) Validate(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	issues, err := h.svc.Validate(r.Context(), tid, id, versionParam(r, "version"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issues": nonNilIssues(issues)})
}

func nonNilIssues(i []ticketmap.Issue) []ticketmap.Issue {
	if i == nil {
		return []ticketmap.Issue{}
	}
	return i
}

// Drift handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/drift.
//
//	@Summary		Check a ticket mapping for drift
//	@Description	Compares the published version's tracker snapshot with the tracker now and marks the profile drifted.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/drift [post]
func (h *TicketMappingHandler) Drift(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	issues, err := h.svc.CheckDrift(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issues": nonNilIssues(issues), "drifted": ticketmap.HasErrors(issues)})
}

// Export handles GET /api/v1/integrations/ticket-mappings/{mapping_id}/export?version=&format=json|yaml.
//
//	@Summary		Export a ticket mapping
//	@Description	JSON or YAML document of a version.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			version	query	int	false	"Version"
//	@Param			format	query	string	false	"json or yaml"
//	@Success		200	{object}	string
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/export [get]
func (h *TicketMappingHandler) Export(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	format := r.URL.Query().Get("format")
	if format != "yaml" {
		format = "json"
	}
	b, err := h.svc.Export(r.Context(), tid, id, versionParam(r, "version"), format)
	if err != nil {
		h.fail(w, err)
		return
	}
	ct := "application/json"
	if format == "yaml" {
		ct = "application/yaml"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ticket-mapping-%s.%s"`, id.String(), format))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}

type ImportTicketMappingRequest struct {
	Document      string `json:"document"`
	ExpectedDraft int    `json:"expected_draft"`
}

// Import handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/import.
//
//	@Summary		Import a ticket mapping into the draft
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	ImportTicketMappingRequest	true	"Request"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/import [post]
func (h *TicketMappingHandler) Import(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req ImportTicketMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	v, issues, err := h.svc.Import(r.Context(), tid, id, []byte(req.Document), req.ExpectedDraft, mappingActor(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	if view, gerr := h.svc.GetProfile(r.Context(), tid, id); gerr == nil {
		h.auditMapping(r, auditdom.ActionTicketMappingUpdated, view.Profile, nil, v.Spec, fmt.Sprintf("Ticket mapping %q imported into the draft", view.Profile.Name))
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": v, "issues": issues})
}

type CopyTicketMappingRequest struct {
	Version int                        `json:"version"`
	Target  CreateTicketMappingRequest `json:"target"`
}

// Copy handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/copy.
//
//	@Summary		Copy a ticket mapping to another destination
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	CopyTicketMappingRequest	true	"Request"
//	@Success		201	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/copy [post]
func (h *TicketMappingHandler) Copy(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req CopyTicketMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	if req.Target.IntegrationID == "" {
		req.Target.IntegrationID = shared.ID{}.String()
	}
	in, err := req.Target.input(tid, mappingActor(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	view, issues, err := h.svc.CopyTo(r.Context(), tid, id, req.Version, in)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.auditMapping(r, auditdom.ActionTicketMappingCreated, view.Profile, nil, view.Profile, fmt.Sprintf("Ticket mapping %q created by copy", view.Profile.Name))
	writeJSON(w, http.StatusCreated, map[string]any{"mapping": view, "issues": issues})
}

// Suggest handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/suggest.
//
//	@Summary		Suggest mapping rows for unmapped fields
//	@Description	By field name and type; never applied without the admin.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/suggest [post]
func (h *TicketMappingHandler) Suggest(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	rows, err := h.svc.Suggest(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if rows == nil {
		rows = []ticketmap.Row{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows})
}

type PreviewTicketMappingRequest struct {
	Version  int    `json:"version"`
	ObjectID string `json:"object_id"`
	Creating *bool  `json:"creating"`
}

// Preview handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/preview:
// the exact fields a version would send for one finding or task the caller
// can see (out of scope = 404).
//
//	@Summary		Preview the issue a mapping would create
//	@Description	The exact fields for one finding or task the caller can see (404 outside the caller's data scope).
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	PreviewTicketMappingRequest	true	"Request"
//	@Success		200	{object}	appticketmap.OutboundPreview
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/preview [post]
func (h *TicketMappingHandler) Preview(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req PreviewTicketMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	oid, err := shared.IDFromString(req.ObjectID)
	if err != nil {
		apierror.NotFound("object").WriteJSON(w)
		return
	}
	creating := true
	if req.Creating != nil {
		creating = *req.Creating
	}
	p, err := h.svc.PreviewOutbound(r.Context(), tid, id, req.Version, oid, creating)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

type PreviewTicketMappingInboundRequest struct {
	Version      int    `json:"version"`
	IssueKey     string `json:"issue_key"`
	CurrentState string `json:"current_state"`
}

// PreviewInbound handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/inbound-preview.
//
//	@Summary		Preview what a tracker issue would change
//	@Description	Reads one issue and shows the intent and the commands it would produce. Changes nothing.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	PreviewTicketMappingInboundRequest	true	"Request"
//	@Success		200	{object}	appticketmap.InboundPreview
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/inbound-preview [post]
func (h *TicketMappingHandler) PreviewInbound(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req PreviewTicketMappingInboundRequest
	if !h.decode(w, r, &req) {
		return
	}
	p, err := h.svc.PreviewInbound(r.Context(), tid, id, req.Version, req.IssueKey, req.CurrentState)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

type SimulateTicketMappingRequest struct {
	Version int `json:"version"`
	appticketmap.SimulateInput
}

// Simulate handles POST /api/v1/integrations/ticket-mappings/{mapping_id}/simulate.
//
//	@Summary		Simulate a status move
//	@Description	An outbound transition path for an OpenCTEM state, or the inbound intent of a tracker status. Changes nothing.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping_id	path	string	true	"Mapping profile ID"
//	@Param			body	body	SimulateTicketMappingRequest	true	"Request"
//	@Success		200	{object}	appticketmap.Simulation
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/ticket-mappings/{mapping_id}/simulate [post]
func (h *TicketMappingHandler) Simulate(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	id, ok2 := mappingID(r)
	if !ok || !ok2 {
		apierror.NotFound("mapping").WriteJSON(w)
		return
	}
	var req SimulateTicketMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	s, err := h.svc.Simulate(r.Context(), tid, id, req.Version, req.SimulateInput)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// IssueTypes handles GET /api/v1/integrations/{id}/jira/issue-types?project_key=.
//
//	@Summary		List a Jira project's issue types
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path	string	true	"Integration ID"
//	@Param			project_key	query	string	true	"Project key"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/{id}/jira/issue-types [get]
func (h *TicketMappingHandler) IssueTypes(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	iid, err := shared.IDFromString(chi.URLParam(r, "id"))
	if !ok || err != nil {
		apierror.NotFound("integration").WriteJSON(w)
		return
	}
	types, err := h.svc.IssueTypes(r.Context(), tid, iid, r.URL.Query().Get("project_key"))
	if err != nil {
		h.fail(w, err)
		return
	}
	if types == nil {
		types = []appticketmap.IssueTypeRef{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"issue_types": types})
}

// Metadata handles GET /api/v1/integrations/{id}/jira/metadata?project_key=&project_id=&issue_type_id=.
//
//	@Summary		Read a Jira destination's fields and workflow
//	@Description	Create fields with schema and allowed values, workflow statuses, transitions and resolutions.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path	string	true	"Integration ID"
//	@Param			project_key	query	string	true	"Project key"
//	@Param			project_id	query	string	false	"Project ID"
//	@Param			issue_type_id	query	string	true	"Issue type ID"
//	@Success		200	{object}	map[string]any
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/{id}/jira/metadata [get]
func (h *TicketMappingHandler) Metadata(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(r)
	iid, err := shared.IDFromString(chi.URLParam(r, "id"))
	if !ok || err != nil {
		apierror.NotFound("integration").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	meta, err := h.svc.ProjectMeta(r.Context(), tid, iid, q.Get("project_key"), q.Get("project_id"), q.Get("issue_type_id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}
