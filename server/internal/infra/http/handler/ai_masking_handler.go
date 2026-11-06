package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aibundle"
	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// AIMaskingStore is the organization's AI masking policy
// (*tenantai.MaskingService).
type AIMaskingStore interface {
	GetMasking(ctx context.Context, tenantID string) (tenantai.MaskingView, error)
	SaveMasking(ctx context.Context, tenantID string, in tenantai.MaskingUpdate, actx auditapp.AuditContext) (tenantai.MaskingView, error)
	PreviewMasking(ctx context.Context, in tenantai.PreviewInput, actx auditapp.AuditContext) (tenantai.MaskingPreview, error)
}

// AIMaskingHandler serves /api/v1/organization/settings/ai/masking.
type AIMaskingHandler struct {
	store     AIMaskingStore
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAIMaskingHandler builds the handler.
func NewAIMaskingHandler(store AIMaskingStore, v *validator.Validator, log *logger.Logger) *AIMaskingHandler {
	return &AIMaskingHandler{store: store, validator: v, logger: log.With("handler", "ai-masking")}
}

const (
	aiErrPolicyRestrictedCode apierror.Code = "AI_POLICY_RESTRICTED"
	aiErrNothingToSendCode    apierror.Code = "AI_NOTHING_TO_SEND"
)

// AIMaskingClassState is one class and whether it is masked in internal data.
type AIMaskingClassState struct {
	// Class: hosts, ips, emails, users, url_params, orgs or tickets.
	Class  string `json:"class"`
	Masked bool   `json:"masked"`
}

// AIMaskingResponse is the organization's AI masking policy. Secrets are
// always masked and restricted data is always masked in full; neither is
// configurable, so neither is listed.
type AIMaskingResponse struct {
	Classes []AIMaskingClassState `json:"classes"`
	// MaskSubdomainLabels masks the labels in front of a registrable domain
	// too (payroll.example.com becomes one placeholder).
	MaskSubdomainLabels bool `json:"mask_subdomain_labels"`
	// Terms are extra names (customers, code names) masked everywhere.
	Terms     []string   `json:"terms"`
	MaxTerms  int        `json:"max_terms"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// UpdateAIMaskingRequest replaces the policy.
type UpdateAIMaskingRequest struct {
	// Off lists the classes left readable in internal data.
	Off                 []string `json:"off" validate:"max=16,dive,max=32"`
	MaskSubdomainLabels bool     `json:"mask_subdomain_labels"`
	Terms               []string `json:"terms" validate:"max=200,dive,max=128"`
}

// PreviewAIMaskingRequest selects the finding to preview.
type PreviewAIMaskingRequest struct {
	FindingID string `json:"finding_id" validate:"required,uuid"`
	// DataClass is the ceiling to preview under: public, internal (default)
	// or restricted.
	DataClass string `json:"data_class" validate:"omitempty,oneof=public internal restricted"`
}

// AIMaskingPlaceholder is a placeholder and its class, never its value.
type AIMaskingPlaceholder struct {
	Token string `json:"token"`
	Class string `json:"class"`
}

// AIMaskingPreviewResponse is exactly what the AI model would get.
type AIMaskingPreviewResponse struct {
	// Text is the masked context section of the prompt.
	Text           string                 `json:"text"`
	Placeholders   []AIMaskingPlaceholder `json:"placeholders"`
	FieldsSent     []string               `json:"fields_sent"`
	FieldsWithheld []string               `json:"fields_withheld"`
	DataClass      string                 `json:"data_class"`
}

func toAIMaskingResponse(v tenantai.MaskingView) AIMaskingResponse {
	out := AIMaskingResponse{MaskSubdomainLabels: v.MaskSubdomainLabels, Terms: v.Terms, MaxTerms: v.MaxTerms,
		UpdatedAt: v.UpdatedAt, UpdatedBy: v.UpdatedBy}
	if out.Terms == nil {
		out.Terms = []string{}
	}
	for _, c := range v.Classes {
		out.Classes = append(out.Classes, AIMaskingClassState{Class: c.Class, Masked: c.Masked})
	}
	return out
}

func (h *AIMaskingHandler) actx(r *http.Request) auditapp.AuditContext {
	ctx := r.Context()
	actx := auditapp.AuditContext{
		ActorID: middleware.GetUserID(ctx), ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx),
	}
	if lu := middleware.GetLocalUser(ctx); lu != nil {
		actx.ActorID, actx.ActorEmail = lu.ID().String(), lu.Email()
	}
	return actx
}

func (h *AIMaskingHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, aipolicy.ErrRestricted):
		apierror.New(http.StatusForbidden, aiErrPolicyRestrictedCode,
			"The organization's AI data policy keeps this finding away from AI, so there is nothing to preview.").WriteJSON(w)
	case errors.Is(err, aibundle.ErrEmpty):
		apierror.New(http.StatusUnprocessableEntity, aiErrNothingToSendCode,
			"Nothing of this finding may be sent under this data class.").WriteJSON(w)
	case errors.Is(err, tenantai.ErrPreviewUnavailable):
		apierror.ServiceUnavailable("The preview is not available on this server.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Finding").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("ai masking failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to process the AI masking policy").WriteJSON(w)
	}
}

func decodeAIMaskingJSON[T any](w http.ResponseWriter, r *http.Request, v *validator.Validator, limit int64) (T, bool) {
	var req T
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return req, false
	}
	if err := v.Validate(req); err != nil {
		apierror.BadRequest("Invalid request: check the fields and their lengths").WriteJSON(w)
		return req, false
	}
	return req, true
}

// Get handles GET /api/v1/organization/settings/ai/masking
// @Summary      Read the organization's AI masking policy
// @Description  Which classes of values (hosts, IP addresses, e-mail addresses, user names, URL parameters, organization names, ticket ids) are replaced by placeholders before internal finding data reaches an AI model, the subdomain label switch and the extra terms. Secrets are always masked and restricted data is always masked in full. Owners and administrators.
// @Tags         Tenants
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AIMaskingResponse
// @Router       /organization/settings/ai/masking [get]
func (h *AIMaskingHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	v, err := h.store.GetMasking(r.Context(), tenantID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAIMaskingResponse(v))
}

// Update handles PUT /api/v1/organization/settings/ai/masking
// @Summary      Change the organization's AI masking policy
// @Description  Replaces the policy: the classes left readable in internal data (off), the subdomain label switch and the extra terms (at most 200, 3 to 128 characters each). Owners and administrators; needs a recent sign-in; audited (a change that masks less is flagged; term values are never logged).
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body UpdateAIMaskingRequest true "Policy"
// @Success      200  {object}  AIMaskingResponse
// @Failure      400  {object}  apierror.Error
// @Router       /organization/settings/ai/masking [put]
func (h *AIMaskingHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	req, ok := decodeAIMaskingJSON[UpdateAIMaskingRequest](w, r, h.validator, 64<<10)
	if !ok {
		return
	}
	v, err := h.store.SaveMasking(r.Context(), tenantID,
		tenantai.MaskingUpdate{Off: req.Off, MaskSubdomainLabels: req.MaskSubdomainLabels, Terms: req.Terms}, h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAIMaskingResponse(v))
}

// Preview handles POST /api/v1/organization/settings/ai/masking/preview
// @Summary      Preview what the AI would see for one finding
// @Description  Builds the real context bundle for a finding the caller can read, under the organization's masking policy and AI data policy, and returns the masked text, the placeholders with their class (never their values) and the fields sent and withheld. Nothing is sent to a model and the mapping is discarded. Owners and administrators; audited.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body PreviewAIMaskingRequest true "Finding"
// @Success      200  {object}  AIMaskingPreviewResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Router       /organization/settings/ai/masking/preview [post]
func (h *AIMaskingHandler) Preview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.GetTenantID(ctx)
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	req, ok := decodeAIMaskingJSON[PreviewAIMaskingRequest](w, r, h.validator, 4<<10)
	if !ok {
		return
	}
	p, err := h.store.PreviewMasking(ctx, tenantai.PreviewInput{
		TenantID: tenantID, FindingID: req.FindingID, UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx),
		DataClass: req.DataClass,
	}, h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AIMaskingPreviewResponse{Text: p.Text, FieldsSent: p.FieldsSent, FieldsWithheld: p.FieldsWithheld, DataClass: p.DataClass,
		Placeholders: make([]AIMaskingPlaceholder, 0, len(p.Placeholders))}
	for _, ph := range p.Placeholders {
		out.Placeholders = append(out.Placeholders, AIMaskingPlaceholder{Token: ph.Token, Class: string(ph.Class)})
	}
	writeJSON(w, http.StatusOK, out)
}
