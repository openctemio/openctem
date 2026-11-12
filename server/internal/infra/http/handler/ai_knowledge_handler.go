package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aiknowledge"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	kdom "github.com/openctemio/openctem/api/pkg/domain/aiknowledge"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AIKnowledgeHandler serves the knowledge organizations give their AI agents
// (docs/architecture/ai-knowledge.md).
type AIKnowledgeHandler struct {
	svc    *aiknowledge.Service
	logger *logger.Logger
}

// NewAIKnowledgeHandler creates the handler.
func NewAIKnowledgeHandler(svc *aiknowledge.Service, log *logger.Logger) *AIKnowledgeHandler {
	return &AIKnowledgeHandler{svc: svc, logger: log.With("handler", "ai-knowledge")}
}

const (
	aiKnowledgeSecretCode       apierror.Code = "AI_KNOWLEDGE_SECRET"
	aiKnowledgeSelfApprovalCode apierror.Code = "AI_KNOWLEDGE_SELF_APPROVAL"
	aiKnowledgeQuarantineCode   apierror.Code = "AI_KNOWLEDGE_QUARANTINE"
	aiKnowledgeQuotaCode        apierror.Code = "AI_KNOWLEDGE_QUOTA"
	aiKnowledgeTooLargeCode     apierror.Code = "AI_KNOWLEDGE_TOO_LARGE"
)

// AIKnowledgeSourceResponse is a knowledge source.
type AIKnowledgeSourceResponse struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Origin           string     `json:"origin"`
	Visibility       string     `json:"visibility"`
	DataClass        string     `json:"data_class"`
	Status           string     `json:"status"`
	TeamIDs          []string   `json:"team_ids"`
	CreatedBy        string     `json:"created_by,omitempty"`
	DecidedBy        string     `json:"decided_by,omitempty"`
	DecidedAt        *time.Time `json:"decided_at,omitempty"`
	SelfApproved     bool       `json:"self_approved"`
	RejectedReason   string     `json:"rejected_reason,omitempty"`
	Documents        int        `json:"documents"`
	PendingDocuments int        `json:"pending_documents"`
	Bytes            int64      `json:"bytes"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// AIKnowledgeDocumentResponse is one document version.
type AIKnowledgeDocumentResponse struct {
	ID               string     `json:"id"`
	LineageID        string     `json:"lineage_id"`
	Version          int        `json:"version"`
	Title            string     `json:"title"`
	Status           string     `json:"status"`
	Quarantined      bool       `json:"quarantined"`
	QuarantineReason string     `json:"quarantine_reason,omitempty"`
	ContentSHA256    string     `json:"content_sha256"`
	Bytes            int        `json:"bytes"`
	Chunks           int        `json:"chunks"`
	CreatedBy        string     `json:"created_by,omitempty"`
	DecidedAt        *time.Time `json:"decided_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// AIKnowledgeSourceDetailResponse is a source with its document versions.
type AIKnowledgeSourceDetailResponse struct {
	AIKnowledgeSourceResponse
	DocumentVersions []AIKnowledgeDocumentResponse `json:"document_versions"`
}

// AIKnowledgeSourceListResponse lists sources.
type AIKnowledgeSourceListResponse struct {
	Data []AIKnowledgeSourceResponse `json:"data"`
}

// AIKnowledgeHitResponse is one excerpt an AI agent would retrieve.
type AIKnowledgeHitResponse struct {
	DocumentID    string    `json:"document_id"`
	SourceID      string    `json:"source_id"`
	SourceName    string    `json:"source_name"`
	DocumentTitle string    `json:"document_title"`
	Section       string    `json:"section"`
	Excerpt       string    `json:"excerpt"`
	Score         float64   `json:"score"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// AIKnowledgePreviewResponse lists what an AI agent would retrieve.
type AIKnowledgePreviewResponse struct {
	Data []AIKnowledgeHitResponse `json:"data"`
}

// CreateAIKnowledgeSourceRequest creates a source.
type CreateAIKnowledgeSourceRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Visibility  string   `json:"visibility"`
	DataClass   string   `json:"data_class"`
	TeamIDs     []string `json:"team_ids"`
}

// UpdateAIKnowledgeSourceRequest renames or describes a source.
type UpdateAIKnowledgeSourceRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// AddAIKnowledgeDocumentRequest adds a document or a new version of one.
type AddAIKnowledgeDocumentRequest struct {
	Title string `json:"title"`
	Text  string `json:"text"`
	// Replaces is any version of an existing document of the source.
	Replaces string `json:"replaces,omitempty"`
}

// ApproveAIKnowledgeSourceRequest approves a source.
type ApproveAIKnowledgeSourceRequest struct {
	// AcknowledgeQuarantine approves quarantined versions too.
	AcknowledgeQuarantine bool `json:"acknowledge_quarantine"`
}

// RejectAIKnowledgeSourceRequest rejects a source or its pending versions.
type RejectAIKnowledgeSourceRequest struct {
	Reason string `json:"reason"`
}

// PreviewAIKnowledgeRequest asks what an AI agent would retrieve.
type PreviewAIKnowledgeRequest struct {
	AIAgentID string `json:"ai_agent_id"`
	Query     string `json:"query"`
}

func toKnowledgeSource(s *kdom.Source) AIKnowledgeSourceResponse {
	teams := make([]string, 0, len(s.TeamIDs))
	for _, t := range s.TeamIDs {
		teams = append(teams, t.String())
	}
	return AIKnowledgeSourceResponse{ID: s.ID.String(), Name: s.Name, Description: s.Description, Origin: string(s.Origin),
		Visibility: string(s.Visibility), DataClass: string(s.Class), Status: string(s.Status), TeamIDs: teams,
		CreatedBy: idStr(s.CreatedBy), DecidedBy: idStr(s.DecidedBy), DecidedAt: s.DecidedAt, SelfApproved: s.SelfApproved,
		RejectedReason: s.RejectedReason, Documents: s.Documents, PendingDocuments: s.PendingDocuments, Bytes: s.Bytes,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}
}

func toKnowledgeDocument(d *kdom.Document) AIKnowledgeDocumentResponse {
	return AIKnowledgeDocumentResponse{ID: d.ID.String(), LineageID: d.LineageID.String(), Version: d.Version, Title: d.Title,
		Status: string(d.Status), Quarantined: d.Quarantined, QuarantineReason: d.QuarantineReason,
		ContentSHA256: d.ContentSHA256, Bytes: d.Bytes, Chunks: d.Chunks, CreatedBy: idStr(d.CreatedBy),
		DecidedAt: d.DecidedAt, CreatedAt: d.CreatedAt}
}

func (h *AIKnowledgeHandler) actor(w http.ResponseWriter, r *http.Request) (aiknowledge.Actor, auditapp.AuditContext, bool) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return aiknowledge.Actor{}, auditapp.AuditContext{}, false
	}
	userID, ok := aiViewerOf(w, r)
	if !ok {
		return aiknowledge.Actor{}, auditapp.AuditContext{}, false
	}
	ctx := r.Context()
	actx := auditapp.AuditContext{
		TenantID: tenantID.String(), ActorID: userID.String(), ActorIP: getClientIP(r),
		UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx),
	}
	if lu := middleware.GetLocalUser(ctx); lu != nil {
		actx.ActorEmail = lu.Email()
	}
	return aiknowledge.Actor{TenantID: tenantID, UserID: userID, Owner: middleware.IsOwner(ctx)}, actx, true
}

func (h *AIKnowledgeHandler) fail(w http.ResponseWriter, err error) {
	var se *aiknowledge.SecretError
	switch {
	case errors.As(err, &se):
		apierror.New(http.StatusBadRequest, aiKnowledgeSecretCode,
			"The document holds a credential on line "+strconv.Itoa(se.Line)+"; remove it and try again.").WriteJSON(w)
	case errors.Is(err, aiknowledge.ErrSelfApproval):
		apierror.New(http.StatusForbidden, aiKnowledgeSelfApprovalCode,
			"Another person must approve knowledge you added.").WriteJSON(w)
	case errors.Is(err, aiknowledge.ErrQuarantineAck):
		apierror.New(http.StatusConflict, aiKnowledgeQuarantineCode,
			"Some text looks like instructions to an AI model; review it and confirm to approve.").WriteJSON(w)
	case errors.Is(err, aiknowledge.ErrQuota):
		apierror.New(http.StatusBadRequest, aiKnowledgeQuotaCode, "The organization's knowledge limit is reached.").WriteJSON(w)
	case errors.Is(err, aiknowledge.ErrTooLarge):
		apierror.New(http.StatusBadRequest, aiKnowledgeTooLargeCode, "The document is too large (at most 256 KB).").WriteJSON(w)
	case errors.Is(err, kdom.ErrNameTaken):
		apierror.Conflict("A knowledge source with this name exists.").WriteJSON(w)
	case errors.Is(err, kdom.ErrNotPending):
		apierror.Conflict("Nothing is waiting for approval.").WriteJSON(w)
	case errors.Is(err, aiknowledge.ErrSourceInactive):
		apierror.Conflict("The knowledge source is rejected or disabled.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Knowledge").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("You may not do this.").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("The knowledge source changed; reload and try again.").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("ai knowledge failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to process the knowledge request").WriteJSON(w)
	}
}

// decodeKnowledgeBody reads a body of at most limit bytes.
func decodeKnowledgeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// ListSources handles GET /api/v1/ai/knowledge/sources.
//
// @Summary      List AI knowledge sources
// @Description  The organization's knowledge sources for AI agents, with approval state and counts.
// @Tags         AI
// @Produce      json
// @Success      200  {object}  AIKnowledgeSourceListResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/sources [get]
func (h *AIKnowledgeHandler) ListSources(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	list, err := h.svc.ListSources(r.Context(), tenantID)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AIKnowledgeSourceListResponse{Data: make([]AIKnowledgeSourceResponse, 0, len(list))}
	for _, s := range list {
		out.Data = append(out.Data, toKnowledgeSource(s))
	}
	writeAIJSON(w, http.StatusOK, out)
}

// GetSource handles GET /api/v1/ai/knowledge/sources/{id}.
//
// @Summary      Get an AI knowledge source
// @Tags         AI
// @Produce      json
// @Param        id path string true "Source ID"
// @Success      200  {object}  AIKnowledgeSourceDetailResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/sources/{id} [get]
func (h *AIKnowledgeHandler) GetSource(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	h.writeDetail(w, r, tenantID, id, http.StatusOK)
}

func (h *AIKnowledgeHandler) writeDetail(w http.ResponseWriter, r *http.Request, tenantID, id shared.ID, status int) {
	src, docs, err := h.svc.GetSource(r.Context(), tenantID, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AIKnowledgeSourceDetailResponse{AIKnowledgeSourceResponse: toKnowledgeSource(src),
		DocumentVersions: make([]AIKnowledgeDocumentResponse, 0, len(docs))}
	for _, d := range docs {
		out.DocumentVersions = append(out.DocumentVersions, toKnowledgeDocument(d))
	}
	writeAIJSON(w, status, out)
}

// CreateSource handles POST /api/v1/ai/knowledge/sources.
//
// @Summary      Create an AI knowledge source
// @Description  A pending source: nothing in it reaches an AI agent until another person approves it.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        body body CreateAIKnowledgeSourceRequest true "Source"
// @Success      201  {object}  AIKnowledgeSourceDetailResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/sources [post]
func (h *AIKnowledgeHandler) CreateSource(w http.ResponseWriter, r *http.Request) {
	a, actx, ok := h.actor(w, r)
	if !ok {
		return
	}
	var req CreateAIKnowledgeSourceRequest
	if !decodeKnowledgeBody(w, r, 16<<10, &req) {
		return
	}
	teams := make([]shared.ID, 0, len(req.TeamIDs))
	for _, t := range req.TeamIDs {
		id, err := shared.IDFromString(t)
		if err != nil {
			apierror.BadRequest("Invalid team id").WriteJSON(w)
			return
		}
		teams = append(teams, id)
	}
	src, err := h.svc.CreateSource(r.Context(), a, aiknowledge.CreateSourceInput{Name: req.Name, Description: req.Description,
		Visibility: kdom.Visibility(req.Visibility), Class: kdom.Class(req.DataClass), TeamIDs: teams}, actx)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.writeDetail(w, r, a.TenantID, src.ID, http.StatusCreated)
}

// UpdateSource handles PATCH /api/v1/ai/knowledge/sources/{id}.
//
// @Summary      Rename or describe an AI knowledge source
// @Description  Visibility, data class and teams are fixed when the source is created.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        id path string true "Source ID"
// @Param        body body UpdateAIKnowledgeSourceRequest true "Name and description"
// @Success      200  {object}  AIKnowledgeSourceDetailResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/sources/{id} [patch]
func (h *AIKnowledgeHandler) UpdateSource(w http.ResponseWriter, r *http.Request) {
	a, actx, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	var req UpdateAIKnowledgeSourceRequest
	if !decodeKnowledgeBody(w, r, 16<<10, &req) {
		return
	}
	if _, err := h.svc.UpdateSource(r.Context(), a, id, req.Name, req.Description, actx); err != nil {
		h.fail(w, err)
		return
	}
	h.writeDetail(w, r, a.TenantID, id, http.StatusOK)
}

// DeleteSource handles DELETE /api/v1/ai/knowledge/sources/{id}.
//
// @Summary      Delete an AI knowledge source
// @Description  Deletes the source and every document; runs keep only the ids and digests of what they cited.
// @Tags         AI
// @Param        id path string true "Source ID"
// @Success      204
// @Security     BearerAuth
// @Router       /ai/knowledge/sources/{id} [delete]
func (h *AIKnowledgeHandler) DeleteSource(w http.ResponseWriter, r *http.Request) {
	a, actx, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteSource(r.Context(), a, id, actx); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ApproveSource handles POST /api/v1/ai/knowledge/sources/{id}/approve.
//
// @Summary      Approve an AI knowledge source
// @Description  Approves the source and its pending document versions. The person who added them cannot approve them (the organization owner may, recorded as a self-approval); quarantined text needs acknowledge_quarantine.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        id path string true "Source ID"
// @Param        body body ApproveAIKnowledgeSourceRequest false "Acknowledgement"
// @Success      200  {object}  AIKnowledgeSourceDetailResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/sources/{id}/approve [post]
func (h *AIKnowledgeHandler) ApproveSource(w http.ResponseWriter, r *http.Request) {
	a, actx, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	var req ApproveAIKnowledgeSourceRequest
	if r.ContentLength != 0 && !decodeKnowledgeBody(w, r, 4<<10, &req) {
		return
	}
	if _, err := h.svc.Approve(r.Context(), a, id, req.AcknowledgeQuarantine, actx); err != nil {
		h.fail(w, err)
		return
	}
	h.writeDetail(w, r, a.TenantID, id, http.StatusOK)
}

// RejectSource handles POST /api/v1/ai/knowledge/sources/{id}/reject.
//
// @Summary      Reject an AI knowledge source
// @Description  Rejects a pending source, or the pending versions of an approved one.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        id path string true "Source ID"
// @Param        body body RejectAIKnowledgeSourceRequest false "Reason"
// @Success      200  {object}  AIKnowledgeSourceDetailResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/sources/{id}/reject [post]
func (h *AIKnowledgeHandler) RejectSource(w http.ResponseWriter, r *http.Request) {
	a, actx, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	var req RejectAIKnowledgeSourceRequest
	if r.ContentLength != 0 && !decodeKnowledgeBody(w, r, 4<<10, &req) {
		return
	}
	if _, err := h.svc.Reject(r.Context(), a, id, req.Reason, actx); err != nil {
		h.fail(w, err)
		return
	}
	h.writeDetail(w, r, a.TenantID, id, http.StatusOK)
}

// DisableSource handles POST /api/v1/ai/knowledge/sources/{id}/disable.
//
// @Summary      Disable an AI knowledge source
// @Description  AI agents stop retrieving it at once.
// @Tags         AI
// @Produce      json
// @Param        id path string true "Source ID"
// @Success      200  {object}  AIKnowledgeSourceDetailResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/sources/{id}/disable [post]
func (h *AIKnowledgeHandler) DisableSource(w http.ResponseWriter, r *http.Request) {
	a, actx, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	if _, err := h.svc.Disable(r.Context(), a, id, actx); err != nil {
		h.fail(w, err)
		return
	}
	h.writeDetail(w, r, a.TenantID, id, http.StatusOK)
}

// AddDocument handles POST /api/v1/ai/knowledge/sources/{id}/documents.
//
// @Summary      Add a document to an AI knowledge source
// @Description  Plain text or Markdown, at most 256 KB. A document holding a credential is refused; text that looks like instructions to a model is quarantined. The version waits for approval; with replaces, it becomes the next version of that document and the approved version keeps serving until then.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        id path string true "Source ID"
// @Param        body body AddAIKnowledgeDocumentRequest true "Document"
// @Success      201  {object}  AIKnowledgeDocumentResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/sources/{id}/documents [post]
func (h *AIKnowledgeHandler) AddDocument(w http.ResponseWriter, r *http.Request) {
	a, actx, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	var req AddAIKnowledgeDocumentRequest
	// JSON escaping can grow text; the service enforces the real limit.
	if !decodeKnowledgeBody(w, r, 3*kdom.MaxDocumentBytes, &req) {
		return
	}
	in := aiknowledge.AddDocumentInput{Title: req.Title, Text: req.Text}
	if req.Replaces != "" {
		rid, err := shared.IDFromString(req.Replaces)
		if err != nil {
			apierror.BadRequest("Invalid document id").WriteJSON(w)
			return
		}
		in.Replaces = &rid
	}
	d, err := h.svc.AddDocument(r.Context(), a, id, in, actx)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusCreated, toKnowledgeDocument(d))
}

// DeleteDocument handles DELETE /api/v1/ai/knowledge/documents/{id}.
//
// @Summary      Delete an AI knowledge document
// @Description  Deletes every version of the document.
// @Tags         AI
// @Param        id path string true "Document ID"
// @Success      204
// @Security     BearerAuth
// @Router       /ai/knowledge/documents/{id} [delete]
func (h *AIKnowledgeHandler) DeleteDocument(w http.ResponseWriter, r *http.Request) {
	a, actx, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteDocument(r.Context(), a, id, actx); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Preview handles POST /api/v1/ai/knowledge/preview.
//
// @Summary      Preview what an AI agent would retrieve
// @Description  Runs a search as one of the organization's AI agents: its team visibility and data class ceiling apply.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        body body PreviewAIKnowledgeRequest true "AI agent and query"
// @Success      200  {object}  AIKnowledgePreviewResponse
// @Security     BearerAuth
// @Router       /ai/knowledge/preview [post]
func (h *AIKnowledgeHandler) Preview(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	var req PreviewAIKnowledgeRequest
	if !decodeKnowledgeBody(w, r, 8<<10, &req) {
		return
	}
	aiAgentID, err := shared.IDFromString(req.AIAgentID)
	if err != nil {
		apierror.BadRequest("Invalid AI agent id").WriteJSON(w)
		return
	}
	hits, err := h.svc.Preview(r.Context(), tenantID, aiAgentID, req.Query)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AIKnowledgePreviewResponse{Data: make([]AIKnowledgeHitResponse, 0, len(hits))}
	for _, x := range hits {
		out.Data = append(out.Data, AIKnowledgeHitResponse{DocumentID: x.DocumentID.String(), SourceID: x.SourceID.String(),
			SourceName: x.SourceName, DocumentTitle: x.DocumentTitle, Section: x.ChunkTitle, Excerpt: x.Body,
			Score: x.Score, UpdatedAt: x.UpdatedAt})
	}
	writeAIJSON(w, http.StatusOK, out)
}
