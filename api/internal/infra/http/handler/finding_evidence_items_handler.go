package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// revealTTL is how long the web client shows a revealed value before it
// masks it again. The server keeps nothing; this is advice to the client.
const revealTTL = 60 * time.Second

// FindingEvidenceItemsHandler serves a finding's typed evidence (masked) and
// the audited reveal of its masked values (docs/architecture/finding-evidence.md).
type FindingEvidenceItemsHandler struct {
	service *evidenceapp.Service
	logger  *logger.Logger
	pentest PentestEvidenceGate
}

// PentestEvidenceGate applies a campaign's rules to evidence changes on a
// pentest finding (role, membership, ownership, campaign state).
type PentestEvidenceGate interface {
	CheckFindingEvidenceWrite(ctx context.Context, tenantID, findingID, userID string, isAdmin bool) error
}

// SetPentestGate wires the campaign rules for pentest findings. Without it a
// pentest finding's evidence cannot be changed here.
func (h *FindingEvidenceItemsHandler) SetPentestGate(g PentestEvidenceGate) { h.pentest = g }

// NewFindingEvidenceItemsHandler creates the handler.
func NewFindingEvidenceItemsHandler(svc *evidenceapp.Service, log *logger.Logger) *FindingEvidenceItemsHandler {
	return &FindingEvidenceItemsHandler{service: svc, logger: log}
}

// FindingEvidenceItemResponse is one masked evidence item of a finding. Its
// content is untrusted tool output: clients render it as text, never HTML.
type FindingEvidenceItemResponse struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
	RetestID  string `json:"retest_id,omitempty"`
	Origin    string `json:"origin"`
	Kind      string `json:"kind"`
	// Role is what the item shows: baseline, proof, verification or
	// supporting. Position is its reader order, ascending.
	Role           string           `json:"role"`
	Position       int              `json:"position"`
	ToolName       string           `json:"tool_name,omitempty"`
	RuleID         string           `json:"rule_id,omitempty"`
	TemplateDigest string           `json:"template_digest,omitempty"`
	Item           evidencedom.Item `json:"item"`
	// Curl reproduces an HTTP exchange's request, with masked values as
	// placeholders.
	Curl string `json:"curl,omitempty"`
	// ContentSHA256 is the platform's hash of the item as the tool sent it
	// (before masking, within the caps).
	ContentSHA256 string `json:"content_sha256"`
	SizeBytes     int    `json:"size_bytes"`
	Truncated     bool   `json:"truncated"`
	// Revealable lists the placeholders whose values can be revealed (with
	// findings:evidence:reveal and a recent sign-in) until SecretsExpireAt.
	Revealable       []string   `json:"revealable"`
	SecretsAvailable bool       `json:"secrets_available"`
	SecretsExpireAt  *time.Time `json:"secrets_expire_at,omitempty"`
	CapturedAt       time.Time  `json:"captured_at"`
	CreatedAt        time.Time  `json:"created_at"`
}

// FindingEvidenceItemListResponse is a finding's evidence, newest first.
type FindingEvidenceItemListResponse struct {
	Data []FindingEvidenceItemResponse `json:"data"`
	// EvidenceVersion counts every change to the finding's evidence; a
	// write-up records the version it was written against.
	EvidenceVersion int64 `json:"evidence_version"`
	// ProofCount is how many of the finding's items have the proof role.
	ProofCount int `json:"proof_count"`
}

// UpdateEvidenceItemRequest changes an item's role and/or position.
type UpdateEvidenceItemRequest struct {
	Role     *string `json:"role" validate:"omitempty,oneof=baseline proof verification supporting"`
	Position *int    `json:"position" validate:"omitempty,min=0,max=1000"`
}

// ReorderEvidenceRequest lists the items in the order they should show.
type ReorderEvidenceRequest struct {
	ItemIDs []string `json:"item_ids"`
}

// RevealEvidenceRequest names the placeholders to reveal and why.
type RevealEvidenceRequest struct {
	Placeholders []string `json:"placeholders"`
	// Purpose is view, copy or copy_curl (recorded in the audit log).
	Purpose string `json:"purpose"`
}

// RevealEvidenceResponse maps each revealed placeholder to its value.
type RevealEvidenceResponse struct {
	Values map[string]string `json:"values"`
	// MaskAfterSeconds is how long the client may show the values.
	MaskAfterSeconds int `json:"mask_after_seconds"`
}

func toEvidenceItemResponse(rec *evidencedom.Record, now time.Time) FindingEvidenceItemResponse {
	out := FindingEvidenceItemResponse{
		ID: rec.ID.String(), FindingID: rec.FindingID.String(), Origin: string(rec.Origin), Kind: rec.Kind,
		Role: string(rec.Role), Position: rec.Position,
		ToolName: rec.ToolName, RuleID: rec.RuleID, TemplateDigest: rec.TemplateDigest, Item: rec.Item,
		ContentSHA256: rec.ContentSHA256, SizeBytes: rec.SizeBytes, Truncated: rec.Truncated,
		Revealable: rec.Placeholders, SecretsAvailable: rec.SecretsAvailable(now), SecretsExpireAt: rec.SecretsExpireAt,
		CapturedAt: rec.CapturedAt, CreatedAt: rec.CreatedAt,
	}
	if out.Revealable == nil || !out.SecretsAvailable {
		out.Revealable = []string{}
	}
	if rec.RetestID != nil {
		out.RetestID = rec.RetestID.String()
	}
	if rec.Kind == evidencedom.KindHTTPExchange {
		out.Curl = evidencedom.Curl(rec.Item)
	}
	return out
}

// List handles GET /api/v1/findings/{id}/evidence-items.
// @Summary      List a finding's evidence
// @Description  The typed proof tools attached to the finding's detections and retest attempts (HTTP exchanges, text, file excerpts, ...), newest first, at most 25. Secret values (auth headers, cookies, tokens) are masked as «secret:kind#n» placeholders. Requires findings:read; out-of-scope findings are 404.
// @Tags         Findings
// @Produce      json
// @Param        id         path      string  true   "Finding ID"
// @Param        retest_id  query     string  false  "Only this retest attempt's evidence"
// @Success      200  {object}  FindingEvidenceItemListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/evidence-items [get]
func (h *FindingEvidenceItemsHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	var retestID *shared.ID
	if v := r.URL.Query().Get("retest_id"); v != "" {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("Invalid retest_id").WriteJSON(w)
			return
		}
		retestID = &id
	}
	recs, err := h.service.List(r.Context(), tenantID, findingID, retestID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	state, err := h.service.State(r.Context(), tenantID, findingID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	now := time.Now()
	out := FindingEvidenceItemListResponse{
		Data: make([]FindingEvidenceItemResponse, 0, len(recs)), EvidenceVersion: state.Version, ProofCount: state.ProofCount,
	}
	for _, rec := range recs {
		out.Data = append(out.Data, toEvidenceItemResponse(rec, now))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// Reveal handles POST /api/v1/findings/{id}/evidence-items/{item_id}/reveal.
// @Summary      Reveal masked evidence values
// @Description  Returns the plaintext of the requested placeholders of one evidence item. Requires findings:evidence:reveal, the finding in the caller's data scope, and a recent sign-in (step-up; API keys cannot). Rate limited; every reveal is audited (finding.evidence_revealed) and shown on the finding's timeline. The response is never cached.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Param        id      path      string                 true  "Finding ID"
// @Param        item_id path      string                 true  "Evidence item ID"
// @Param        body    body      RevealEvidenceRequest  true  "Placeholders to reveal"
// @Success      200  {object}  RevealEvidenceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      410  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Failure      503  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/evidence-items/{item_id}/reveal [post]
func (h *FindingEvidenceItemsHandler) Reveal(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	itemID, err := shared.IDFromString(r.PathValue("item_id"))
	if err != nil {
		apierror.NotFound("Evidence").WriteJSON(w)
		return
	}
	var req RevealEvidenceRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	in := evidenceapp.RevealInput{
		TenantID: tenantID, FindingID: findingID, EvidenceID: itemID,
		Placeholders: req.Placeholders, Purpose: req.Purpose, Audit: h.auditContext(r),
	}
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		in.ActorID = &uid
	}
	values, err := h.service.Reveal(r.Context(), in)
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(RevealEvidenceResponse{Values: values, MaskAfterSeconds: int(revealTTL.Seconds())})
}

// authorizeChange applies the campaign's rules when the finding is a pentest
// finding; any other finding needs only the route's findings:write.
func (h *FindingEvidenceItemsHandler) authorizeChange(w http.ResponseWriter, r *http.Request, tenantID, findingID shared.ID) bool {
	isPentest, err := h.service.IsPentestFinding(r.Context(), tenantID, findingID)
	if err != nil {
		h.writeError(w, err)
		return false
	}
	if !isPentest {
		return true
	}
	if h.pentest == nil {
		apierror.Forbidden("Evidence of a pentest finding is changed through its campaign").WriteJSON(w)
		return false
	}
	if err := h.pentest.CheckFindingEvidenceWrite(r.Context(), tenantID.String(), findingID.String(),
		middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context())); err != nil {
		switch {
		case errors.Is(err, shared.ErrNotFound), errors.Is(err, pentest.ErrNotCampaignMember):
			apierror.NotFound("Evidence").WriteJSON(w)
		case errors.Is(err, shared.ErrForbidden), errors.Is(err, pentest.ErrCampaignLocked),
			errors.Is(err, pentest.ErrInsufficientCampaignRole), errors.Is(err, pentest.ErrFindingNotOwned):
			apierror.Forbidden(err.Error()).WriteJSON(w)
		default:
			h.logger.Error("pentest evidence gate failed", "error", logger.SanitizeError(err))
			apierror.InternalServerError("Evidence request failed").WriteJSON(w)
		}
		return false
	}
	return true
}

// Update handles PATCH /api/v1/findings/{id}/evidence-items/{item_id}.
// @Summary      Change an evidence item's role or position
// @Description  Sets what the item shows (baseline, proof, verification, supporting) and/or its reader order. Bumps the finding's evidence_version. Requires findings:write and the finding in the caller's data scope; on a pentest finding the campaign's rules also apply. Audited.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Param        id      path      string                    true  "Finding ID"
// @Param        item_id path      string                    true  "Evidence item ID"
// @Param        body    body      UpdateEvidenceItemRequest true  "Role and/or position"
// @Success      200  {object}  FindingEvidenceItemResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/evidence-items/{item_id} [patch]
func (h *FindingEvidenceItemsHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	itemID, err := shared.IDFromString(r.PathValue("item_id"))
	if err != nil {
		apierror.NotFound("Evidence").WriteJSON(w)
		return
	}
	var req UpdateEvidenceItemRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if !h.authorizeChange(w, r, tenantID, findingID) {
		return
	}
	in := evidenceapp.UpdateInput{
		TenantID: tenantID, FindingID: findingID, EvidenceID: itemID,
		Role: req.Role, Position: req.Position, Audit: h.auditContext(r),
	}
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		in.ActorID = &uid
	}
	rec, err := h.service.Update(r.Context(), in)
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(toEvidenceItemResponse(rec, time.Now()))
}

// Reorder handles PUT /api/v1/findings/{id}/evidence-items/order.
// @Summary      Set the order of a finding's evidence items
// @Description  Puts the listed items first, in that order (positions 0..n-1); the finding's other items follow. Every id must be an item of the finding. Bumps evidence_version when anything moved. Requires findings:write; on a pentest finding the campaign's rules also apply. Audited.
// @Tags         Findings
// @Accept       json
// @Param        id   path  string                  true  "Finding ID"
// @Param        body body  ReorderEvidenceRequest  true  "Item ids in display order"
// @Success      204
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/evidence-items/order [put]
func (h *FindingEvidenceItemsHandler) Reorder(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	var req ReorderEvidenceRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	ids := make([]shared.ID, 0, len(req.ItemIDs))
	for _, v := range req.ItemIDs {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("Invalid item id").WriteJSON(w)
			return
		}
		ids = append(ids, id)
	}
	if !h.authorizeChange(w, r, tenantID, findingID) {
		return
	}
	var actor *shared.ID
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		actor = &uid
	}
	if err := h.service.Reorder(r.Context(), tenantID, findingID, ids, actor, h.auditContext(r)); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *FindingEvidenceItemsHandler) ids(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	findingID, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tenantID, findingID, true
}

func (h *FindingEvidenceItemsHandler) auditContext(r *http.Request) auditapp.AuditContext {
	return auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  middleware.GetRequestID(r.Context()),
		SessionID:  middleware.GetSessionID(r.Context()),
	}
}

func (h *FindingEvidenceItemsHandler) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, evidencedom.ErrNotFound), errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Evidence").WriteJSON(w)
	case errors.Is(err, evidencedom.ErrSecretsExpired):
		apierror.New(http.StatusGone, "EVIDENCE_SECRETS_EXPIRED",
			"The masked values of this evidence are no longer kept").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, evidenceapp.ErrRevealUnavailable):
		apierror.ServiceUnavailable("Evidence reveal is unavailable").WriteJSON(w)
	case errors.Is(err, evidencedom.ErrSecretUnreadable):
		h.logger.Error("evidence secret cannot be decrypted")
		apierror.InternalServerError("Evidence value cannot be decrypted").WriteJSON(w)
	default:
		h.logger.Error("finding evidence request failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Evidence request failed").WriteJSON(w)
	}
}
