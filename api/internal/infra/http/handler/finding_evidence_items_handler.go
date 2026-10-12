package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
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
}

// NewFindingEvidenceItemsHandler creates the handler.
func NewFindingEvidenceItemsHandler(svc *evidenceapp.Service, log *logger.Logger) *FindingEvidenceItemsHandler {
	return &FindingEvidenceItemsHandler{service: svc, logger: log}
}

// FindingEvidenceItemResponse is one masked evidence item of a finding. Its
// content is untrusted tool output: clients render it as text, never HTML.
type FindingEvidenceItemResponse struct {
	ID             string           `json:"id"`
	FindingID      string           `json:"finding_id"`
	RetestID       string           `json:"retest_id,omitempty"`
	Origin         string           `json:"origin"`
	Kind           string           `json:"kind"`
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
	now := time.Now()
	out := FindingEvidenceItemListResponse{Data: make([]FindingEvidenceItemResponse, 0, len(recs))}
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
		RequestID:  r.Header.Get("X-Request-ID"),
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
