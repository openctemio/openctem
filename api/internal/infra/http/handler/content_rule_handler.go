package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	contentruleapp "github.com/openctemio/openctem/api/internal/app/contentrule"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxContentRuleBody bounds a create, update or test request: a rule plus,
// for a test, the sample.
const maxContentRuleBody = contentruleapp.MaxSampleBytes + 64<<10

// ContentRulePlatformPacks lists the stable platform rule packs
// (contentrule.Service).
type ContentRulePlatformPacks interface {
	PlatformPacks(ctx context.Context) ([]scanrun.PinnedRules, error)
}

// ContentRuleHandler serves an organization's own detection rules
// (/api/v1/content-rules; docs/architecture/rule-packs.md). The tenant
// comes from the JWT; every read and write is scoped to it.
type ContentRuleHandler struct {
	service  *contentruleapp.RulesService
	platform ContentRulePlatformPacks
	logger   *logger.Logger
}

// NewContentRuleHandler creates a ContentRuleHandler. platform may be nil.
func NewContentRuleHandler(svc *contentruleapp.RulesService, platform ContentRulePlatformPacks, log *logger.Logger) *ContentRuleHandler {
	return &ContentRuleHandler{service: svc, platform: platform, logger: log.With("handler", "content_rule")}
}

// ContentRuleResponse is an organization detection rule.
type ContentRuleResponse struct {
	ID        string           `json:"id"`
	Kind      string           `json:"kind"`
	RuleID    string           `json:"rule_id"`
	Name      string           `json:"name"`
	Enabled   bool             `json:"enabled"`
	Version   int              `json:"version"`
	SHA256    string           `json:"sha256"`
	Rule      contentrule.Rule `json:"rule"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

// ContentRulePack is a platform rule pack every engine holds.
type ContentRulePack struct {
	Kind    string `json:"kind"`
	Pack    string `json:"pack"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Rules   int    `json:"rules"`
}

// ContentRuleListResponse is the organization's rules and the platform
// packs in use.
type ContentRuleListResponse struct {
	Items    []ContentRuleResponse `json:"items"`
	Platform []ContentRulePack     `json:"platform"`
	// Limit is the most rules an organization may have.
	Limit int `json:"limit"`
}

// CreateContentRuleRequest creates a rule.
type CreateContentRuleRequest struct {
	// Kind is web-fingerprints or secret-rules.
	Kind    string           `json:"kind"`
	Rule    contentrule.Rule `json:"rule"`
	Enabled *bool            `json:"enabled"`
}

// UpdateContentRuleRequest changes a rule; omitted fields are unchanged.
type UpdateContentRuleRequest struct {
	Rule    *contentrule.Rule `json:"rule"`
	Enabled *bool             `json:"enabled"`
}

// ContentRuleSample is the web response a rule is tested against.
type ContentRuleSample struct {
	URL      string            `json:"url"`
	FinalURL string            `json:"final_url"`
	Title    string            `json:"title"`
	Headers  map[string]string `json:"headers"`
	Cookies  []string          `json:"cookies"`
	Favicon  string            `json:"favicon"`
	Body     string            `json:"body"`
	Scripts  []string          `json:"scripts"`
}

// TestContentRuleRequest tests a draft rule on a sample.
type TestContentRuleRequest struct {
	Kind   string            `json:"kind"`
	Rule   contentrule.Rule  `json:"rule"`
	Sample ContentRuleSample `json:"sample"`
}

// ContentRuleTechnology is a technology a test detected.
type ContentRuleTechnology struct {
	RuleID     string `json:"rule_id"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Category   string `json:"category"`
	CPE        string `json:"cpe"`
	Confidence int    `json:"confidence"`
}

// ContentRuleSecret is a secret a test found, masked: never the value.
type ContentRuleSecret struct {
	RuleID   string `json:"rule_id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Field    string `json:"field"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Preview  string `json:"preview"`
	Length   int    `json:"length"`
}

// TestContentRuleResponse is what a test found.
type TestContentRuleResponse struct {
	Technologies []ContentRuleTechnology `json:"technologies"`
	Secrets      []ContentRuleSecret     `json:"secrets"`
	Truncated    bool                    `json:"truncated"`
	Stopped      string                  `json:"stopped"`
}

func toContentRuleResponse(r *contentrule.StoredRule) ContentRuleResponse {
	return ContentRuleResponse{ID: r.ID.String(), Kind: string(r.Kind), RuleID: r.Rule.ID, Name: r.Rule.Name, Enabled: r.Enabled,
		Version: r.Version, SHA256: r.SHA256, Rule: r.Rule, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

// List handles GET /api/v1/content-rules
// @Summary      List detection rules
// @Description  The organization's own web fingerprint and sensitive-information rules, and the platform rule packs every scan is matched with.
// @Tags         Detection rules
// @Produce      json
// @Success      200  {object}  ContentRuleListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-rules [get]
func (h *ContentRuleHandler) List(w http.ResponseWriter, r *http.Request) {
	rules, err := h.service.List(r.Context(), buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := ContentRuleListResponse{Items: make([]ContentRuleResponse, 0, len(rules)), Platform: []ContentRulePack{},
		Limit: contentrule.MaxOrganizationRules}
	for _, rule := range rules {
		out.Items = append(out.Items, toContentRuleResponse(rule))
	}
	if h.platform != nil {
		packs, err := h.platform.PlatformPacks(r.Context())
		if err != nil {
			h.logger.Warn("platform rule packs not listed", "error", sanitizeLogField(err.Error()))
		}
		for _, p := range packs {
			out.Platform = append(out.Platform, ContentRulePack{Kind: p.Kind, Pack: p.Pack, Version: p.Version, Digest: p.Digest, Rules: p.Rules})
		}
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

// Get handles GET /api/v1/content-rules/{id}
// @Summary      Get a detection rule
// @Tags         Detection rules
// @Produce      json
// @Param        id   path      string  true  "Rule ID"
// @Success      200  {object}  ContentRuleResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-rules/{id} [get]
func (h *ContentRuleHandler) Get(w http.ResponseWriter, r *http.Request) {
	rule, err := h.service.Get(r.Context(), buildScanZoneAuditContext(r), chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentRuleResponse(rule))
}

// Create handles POST /api/v1/content-rules
// @Summary      Create a detection rule
// @Description  The rule is validated: RE2 patterns only, body and script matchers need keywords, and size and complexity are bounded.
// @Tags         Detection rules
// @Accept       json
// @Produce      json
// @Param        body  body      CreateContentRuleRequest  true  "Rule"
// @Success      201   {object}  ContentRuleResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-rules [post]
func (h *ContentRuleHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateContentRuleRequest
	if !decodeContentRuleBody(w, r, &req) {
		return
	}
	rule, err := h.service.Create(r.Context(), buildScanZoneAuditContext(r), contentruleapp.CreateInput{Kind: req.Kind, Rule: req.Rule, Enabled: req.Enabled})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toContentRuleResponse(rule))
}

// Update handles PATCH /api/v1/content-rules/{id}
// @Summary      Update a detection rule
// @Description  Omitted fields are unchanged. A changed rule raises the version.
// @Tags         Detection rules
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Rule ID"
// @Param        body  body      UpdateContentRuleRequest  true  "Changes"
// @Success      200   {object}  ContentRuleResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-rules/{id} [patch]
func (h *ContentRuleHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateContentRuleRequest
	if !decodeContentRuleBody(w, r, &req) {
		return
	}
	rule, err := h.service.Update(r.Context(), buildScanZoneAuditContext(r), chi.URLParam(r, "id"),
		contentruleapp.UpdateInput{Rule: req.Rule, Enabled: req.Enabled})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentRuleResponse(rule))
}

// Delete handles DELETE /api/v1/content-rules/{id}
// @Summary      Delete a detection rule
// @Tags         Detection rules
// @Param        id   path  string  true  "Rule ID"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-rules/{id} [delete]
func (h *ContentRuleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Delete(r.Context(), buildScanZoneAuditContext(r), chi.URLParam(r, "id")); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Test handles POST /api/v1/content-rules/test
// @Summary      Test a detection rule on a sample
// @Description  Validates a draft rule and runs it alone on the sample. Secrets come back masked (a short preview, the length and where); nothing is stored.
// @Tags         Detection rules
// @Accept       json
// @Produce      json
// @Param        body  body      TestContentRuleRequest  true  "Rule and sample"
// @Success      200   {object}  TestContentRuleResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      413   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-rules/test [post]
func (h *ContentRuleHandler) Test(w http.ResponseWriter, r *http.Request) {
	var req TestContentRuleRequest
	if !decodeContentRuleBody(w, r, &req) {
		return
	}
	s := req.Sample
	res, err := h.service.Test(r.Context(), buildScanZoneAuditContext(r), contentruleapp.TestInput{Kind: req.Kind, Rule: req.Rule,
		Document: contentrule.Document{URL: s.URL, FinalURL: s.FinalURL, Title: s.Title, Headers: lowerHeaders(s.Headers),
			Cookies: s.Cookies, Favicon: s.Favicon, Body: []byte(s.Body), Scripts: s.Scripts}})
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := TestContentRuleResponse{Technologies: []ContentRuleTechnology{}, Secrets: []ContentRuleSecret{}, Truncated: res.Truncated, Stopped: res.Stopped}
	for _, t := range res.Technologies {
		out.Technologies = append(out.Technologies, ContentRuleTechnology{RuleID: t.RuleID, Name: t.Name, Version: t.Version,
			Category: t.Category, CPE: t.CPE, Confidence: t.Confidence})
	}
	for _, m := range res.Secrets {
		out.Secrets = append(out.Secrets, ContentRuleSecret{RuleID: m.RuleID, Category: m.Category, Severity: m.Severity,
			Field: m.Field, Line: m.Line, Column: m.Column, Preview: m.Preview, Length: m.Length})
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

func lowerHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[toLowerASCII(k)] = v
	}
	return out
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func decodeContentRuleBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxContentRuleBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			apierror.New(http.StatusRequestEntityTooLarge, "DETECTION_RULE_SAMPLE_TOO_LARGE", "the request is too large").WriteJSON(w)
			return false
		}
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func (h *ContentRuleHandler) handleError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Detection rule").WriteJSON(w)
	case errors.As(err, &de) && errors.Is(err, shared.ErrConflict):
		apierror.New(http.StatusConflict, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.As(err, &de) && errors.Is(err, shared.ErrValidation):
		apierror.New(http.StatusBadRequest, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Invalid detection rule").WriteJSON(w)
	default:
		h.logger.Error("detection rule service error", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
	}
}
