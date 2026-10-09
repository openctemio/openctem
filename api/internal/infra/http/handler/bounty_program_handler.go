package handler

// Bug-bounty programs (RFC-065 §6): preview, import, re-import, pause,
// resume and end. Import, re-import and resume are the attestation that puts
// a program's entries into effect: the routes require step-up, and each is
// audited with the accepted terms hash.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	bpapp "github.com/openctemio/openctem/api/internal/app/bountyprogram"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxProgramBody bounds a program request (the paste is at most 256 KiB).
const maxProgramBody = bp.MaxScopeTextBytes + 64*1024

// BountyProgramHandler serves /api/v1/programs.
type BountyProgramHandler struct {
	svc    *bpapp.Service
	audit  *auditsvc.AuditService
	logger *logger.Logger
}

// NewBountyProgramHandler creates the handler.
func NewBountyProgramHandler(svc *bpapp.Service, audit *auditsvc.AuditService, log *logger.Logger) *BountyProgramHandler {
	return &BountyProgramHandler{svc: svc, audit: audit, logger: log}
}

// ProgramRequest is the body of a preview, an import and a re-import.
type ProgramRequest struct {
	Name       string   `json:"name"`
	Platform   string   `json:"platform"`
	Handle     string   `json:"handle"`
	ProgramURL string   `json:"program_url"`
	ScopeText  string   `json:"scope_text"`
	Rules      bp.Rules `json:"rules"`
	// AcceptTermsSHA256 is the attestation: the terms_sha256 of the preview
	// the person accepted.
	AcceptTermsSHA256 string `json:"accept_terms_sha256"`
}

// ProgramResumeRequest is the body of a resume.
type ProgramResumeRequest struct {
	AcceptTermsSHA256 string `json:"accept_terms_sha256"`
}

// ProgramResponse is one program.
type ProgramResponse struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Platform      string     `json:"platform"`
	Handle        string     `json:"handle"`
	ProgramURL    string     `json:"program_url"`
	Status        string     `json:"status"`
	ScopeSource   string     `json:"scope_source"`
	Authoritative bool       `json:"authoritative"`
	Rules         bp.Rules   `json:"rules"`
	MaxTier       string     `json:"max_tier"`
	TermsSHA256   string     `json:"terms_sha256"`
	AcceptedBy    *ActorRef  `json:"accepted_by,omitempty"`
	AcceptedAt    *time.Time `json:"accepted_at,omitempty"`
	GroupID       *string    `json:"group_id,omitempty"`
	CreatedBy     *ActorRef  `json:"created_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ProgramDetailResponse is a program with its scope.
type ProgramDetailResponse struct {
	ProgramResponse
	Items      []bp.Item                `json:"items"`
	Entries    []ScopeTargetResponse    `json:"entries"`
	Exclusions []bpapp.PlannedExclusion `json:"exclusions"`
}

// ProgramChangeResponse answers an import or re-import: the program and
// what the import did.
type ProgramChangeResponse struct {
	Program ProgramResponse `json:"program"`
	Preview *bpapp.Preview  `json:"preview"`
}

func idRef(id *shared.ID) *ActorRef {
	if id == nil {
		return nil
	}
	return actorRef(id.String())
}

func toProgramResponse(p *bp.Program) ProgramResponse {
	out := ProgramResponse{
		ID: p.ID.String(), Name: p.Name, Platform: p.Platform, Handle: p.Handle, ProgramURL: p.ProgramURL,
		Status: string(p.Status), ScopeSource: p.ScopeSource, Authoritative: p.Authoritative, Rules: p.Rules,
		MaxTier: p.Rules.MaxTier().String(), TermsSHA256: p.TermsSHA256, AcceptedBy: idRef(p.AcceptedBy),
		AcceptedAt: p.AcceptedAt, CreatedBy: idRef(p.CreatedBy), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	if p.GroupID != nil {
		g := p.GroupID.String()
		out.GroupID = &g
	}
	return out
}

func (h *BountyProgramHandler) caller(r *http.Request) (tenantID, actor shared.ID, ok bool) {
	t, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		return shared.ID{}, shared.ID{}, false
	}
	a, _ := shared.IDFromString(middleware.GetUserID(r.Context()))
	return t, a, true
}

func (h *BountyProgramHandler) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxProgramBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func (h *BountyProgramHandler) input(req ProgramRequest) bpapp.Input {
	return bpapp.Input{Name: req.Name, Platform: req.Platform, Handle: req.Handle, ProgramURL: req.ProgramURL,
		ScopeText: req.ScopeText, Rules: req.Rules, AcceptTermsSHA256: req.AcceptTermsSHA256}
}

func (h *BountyProgramHandler) writeError(w http.ResponseWriter, err error) {
	if writeScopeEntryError(w, err) {
		return
	}
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Program").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Not allowed").WriteJSON(w)
	default:
		h.logger.Error("bounty program request failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Program request failed").WriteJSON(w)
	}
}

func (h *BountyProgramHandler) auditProgram(r *http.Request, action audit.Action, p *bp.Program, msg string, meta map[string]any) {
	event := auditsvc.NewSuccessEvent(action, audit.ResourceTypeBountyProgram, p.ID.String()).
		WithResourceName(p.Name).WithMessage(msg).
		WithMetadata("program_url", p.ProgramURL).
		WithMetadata("terms_sha256", p.TermsSHA256)
	for k, v := range meta {
		event = event.WithMetadata(k, v)
	}
	logRequestChange(h.audit, h.logger, r, event)
}

func planCounts(pv *bpapp.Preview) map[string]any {
	n := map[string]int{}
	for _, e := range pv.Entries {
		n[e.Status]++
	}
	return map[string]any{"entries_created": n[bpapp.PlanCreate], "entries_kept": n[bpapp.PlanKeep],
		"entries_refused": n[bpapp.PlanRefused], "entries_already_covered": n[bpapp.PlanAlreadyCovered],
		"program_exclusions": len(pv.Exclusions)}
}

// List handles GET /api/v1/programs
// @Summary      List programs
// @Description  The bug-bounty programs the caller may see: every program for owners, admins and full-data roles; only the programs whose group has the caller otherwise (RFC-065).
// @Tags         Programs
// @Produce      json
// @Success      200  {object}  map[string][]ProgramResponse
// @Security     BearerAuth
// @Router       /programs [get]
func (h *BountyProgramHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	list, err := h.svc.List(r.Context(), tenantID, actor)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := make([]ProgramResponse, 0, len(list))
	for _, p := range list {
		out = append(out, toProgramResponse(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// Preview handles POST /api/v1/programs/preview
// @Summary      Preview program import
// @Description  Parse a pasted scope or CSV export and answer what an import would create: entries (create, already_covered, refused with the guardrail code), program exclusions with any overlap with the organization's own scope, items no scan can target, the tier ceiling and terms_sha256 to accept. Writes nothing.
// @Tags         Programs
// @Accept       json
// @Produce      json
// @Param        body  body      ProgramRequest  true  "Program"
// @Success      200   {object}  bpapp.Preview
// @Failure      400   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/preview [post]
func (h *BountyProgramHandler) Preview(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req ProgramRequest
	if !h.decode(w, r, &req) {
		return
	}
	pv, err := h.svc.Preview(r.Context(), tenantID, h.input(req), nil)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pv)
}

// Import handles POST /api/v1/programs
// @Summary      Import program
// @Description  Create a program from a pasted scope, with the caller's attestation of its terms (accept_terms_sha256 from the preview; 409 PROGRAM_TERMS_CHANGED when they differ). Its entries take effect at once, with no approver; they authorize at most t1 and never reach platform sensors. Needs a recent re-authentication. Audited; administrators are notified.
// @Tags         Programs
// @Accept       json
// @Produce      json
// @Param        body  body      ProgramRequest  true  "Program"
// @Success      201   {object}  ProgramChangeResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs [post]
func (h *BountyProgramHandler) Import(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req ProgramRequest
	if !h.decode(w, r, &req) {
		return
	}
	p, pv, err := h.svc.Import(r.Context(), tenantID, actor, h.input(req))
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.auditProgram(r, audit.ActionBountyProgramImported, p, "Program imported", planCounts(pv))
	h.auditProgram(r, audit.ActionBountyProgramTermsAccepted, p, "Program terms accepted", nil)
	writeJSON(w, http.StatusCreated, ProgramChangeResponse{Program: toProgramResponse(p), Preview: pv})
}

func (h *BountyProgramHandler) programID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Program").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// Get handles GET /api/v1/programs/{id}
// @Summary      Get program
// @Description  A program the caller may see, with its parsed items, scope entries and program exclusions (each with the organization's own entry that also covers it, if any). Another program answers 404.
// @Tags         Programs
// @Produce      json
// @Param        id   path      string  true  "Program ID"
// @Success      200  {object}  ProgramDetailResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id} [get]
func (h *BountyProgramHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, ok := h.programID(w, r)
	if !ok {
		return
	}
	d, err := h.svc.Get(r.Context(), tenantID, actor, id)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := ProgramDetailResponse{ProgramResponse: toProgramResponse(d.Program), Items: d.Program.ScopeItems,
		Entries: make([]ScopeTargetResponse, 0, len(d.Entries)), Exclusions: d.Exclusions}
	if out.Items == nil {
		out.Items = []bp.Item{}
	}
	for _, e := range d.Entries {
		out.Entries = append(out.Entries, toScopeTargetResponse(e))
	}
	writeJSON(w, http.StatusOK, out)
}

// Reimport handles PUT /api/v1/programs/{id}/scope
// @Summary      Re-import program scope
// @Description  Replace a program's scope and rules with a new attested paste: entries of items no longer listed stop at once, new ones are created, program exclusions are replaced. Needs a recent re-authentication. Audited.
// @Tags         Programs
// @Accept       json
// @Produce      json
// @Param        id    path      string          true  "Program ID"
// @Param        body  body      ProgramRequest  true  "Program"
// @Success      200   {object}  ProgramChangeResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/scope [put]
func (h *BountyProgramHandler) Reimport(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, ok := h.programID(w, r)
	if !ok {
		return
	}
	var req ProgramRequest
	if !h.decode(w, r, &req) {
		return
	}
	p, pv, err := h.svc.Reimport(r.Context(), tenantID, actor, id, h.input(req))
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.auditProgram(r, audit.ActionBountyProgramScopeReplaced, p, "Program scope re-imported", planCounts(pv))
	h.auditProgram(r, audit.ActionBountyProgramTermsAccepted, p, "Program terms accepted", nil)
	writeJSON(w, http.StatusOK, ProgramChangeResponse{Program: toProgramResponse(p), Preview: pv})
}

// Pause handles POST /api/v1/programs/{id}/suspend
// @Summary      Pause program
// @Description  Every entry of the program stops authorizing at once. Audited.
// @Tags         Programs
// @Produce      json
// @Param        id   path      string  true  "Program ID"
// @Success      200  {object}  ProgramResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/suspend [post]
func (h *BountyProgramHandler) Pause(w http.ResponseWriter, r *http.Request) {
	h.lifecycle(w, r, audit.ActionBountyProgramPaused, "Program paused", h.svc.Pause)
}

// End handles POST /api/v1/programs/{id}/end
// @Summary      End program
// @Description  Every entry of the program stops authorizing for good; the program stays for its history. Audited.
// @Tags         Programs
// @Produce      json
// @Param        id   path      string  true  "Program ID"
// @Success      200  {object}  ProgramResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/end [post]
func (h *BountyProgramHandler) End(w http.ResponseWriter, r *http.Request) {
	h.lifecycle(w, r, audit.ActionBountyProgramEnded, "Program ended", h.svc.End)
}

func (h *BountyProgramHandler) lifecycle(w http.ResponseWriter, r *http.Request, action audit.Action, msg string,
	fn func(ctx context.Context, tenantID, actor, id shared.ID) (*bp.Program, error)) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, ok := h.programID(w, r)
	if !ok {
		return
	}
	p, err := fn(r.Context(), tenantID, actor, id)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.auditProgram(r, action, p, msg, nil)
	writeJSON(w, http.StatusOK, toProgramResponse(p))
}

// Resume handles POST /api/v1/programs/{id}/reactivate
// @Summary      Resume program
// @Description  Put a paused program's entries back into effect on a new attestation of its current terms (accept_terms_sha256). Needs a recent re-authentication. Audited; administrators are notified.
// @Tags         Programs
// @Accept       json
// @Produce      json
// @Param        id    path      string                true  "Program ID"
// @Param        body  body      ProgramResumeRequest  true  "Attestation"
// @Success      200   {object}  ProgramResponse
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/reactivate [post]
func (h *BountyProgramHandler) Resume(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, ok := h.programID(w, r)
	if !ok {
		return
	}
	var req ProgramResumeRequest
	if !h.decode(w, r, &req) {
		return
	}
	p, err := h.svc.Resume(r.Context(), tenantID, actor, id, req.AcceptTermsSHA256)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.auditProgram(r, audit.ActionBountyProgramResumed, p, "Program resumed", nil)
	h.auditProgram(r, audit.ActionBountyProgramTermsAccepted, p, "Program terms accepted", nil)
	writeJSON(w, http.StatusOK, toProgramResponse(p))
}
