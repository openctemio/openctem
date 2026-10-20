package handler

// Platform console: the settings that moved from environment variables into
// the console (docs/rfcs/RFC-079-console-platform-settings.md): the CAPTCHA
// keys, the one-time deployment region, the default storage quota, the
// alert webhook and the platform AI provider.
//
// Any administrator reads them; secrets are never returned (set / not set,
// and who changed them when). Changes need super_admin and a confirmation
// at the route (a fresh one for the guarded settings), and the guarded ones
// a reason; the services write the admin audit rows and tell every
// administrator.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/internal/app/deploymentregion"
	"github.com/openctemio/openctem/api/internal/app/platformai"
	"github.com/openctemio/openctem/api/internal/app/platformalert"
	"github.com/openctemio/openctem/api/internal/app/platformcaptcha"
	"github.com/openctemio/openctem/api/internal/app/storagequota"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Error codes of the moved settings.
const (
	CodeSettingLockedByEnvironment apierror.Code = "SETTING_LOCKED_BY_ENVIRONMENT"
	CodeRegionAlreadySet           apierror.Code = "REGION_ALREADY_SET"
	CodeRegionOrganizationsExist   apierror.Code = "REGION_ORGANIZATIONS_EXIST"
	CodeSettingTestFailed          apierror.Code = "SETTING_TEST_FAILED"
	CodeSettingNotConfigured       apierror.Code = "SETTING_NOT_CONFIGURED"
)

// AdminDirectory resolves who last changed a setting.
type AdminDirectory interface {
	GetByID(ctx context.Context, id shared.ID) (*admin.AdminUser, error)
}

// AdminPlatformSettingsHandler serves /api/v1/admin/settings/{captcha,
// region, storage-quota, alerts, ai}. Each service may be nil (route not
// mounted).
type AdminPlatformSettingsHandler struct {
	Captcha      *platformcaptcha.Service
	Region       *deploymentregion.Service
	StorageQuota *storagequota.Service
	Alerts       *platformalert.Service
	AI           *platformai.Service
	admins       AdminDirectory
	logger       *logger.Logger
}

// NewAdminPlatformSettingsHandler creates the handler.
func NewAdminPlatformSettingsHandler(admins AdminDirectory, log *logger.Logger) *AdminPlatformSettingsHandler {
	return &AdminPlatformSettingsHandler{admins: admins, logger: log.With("handler", "admin_platform_settings")}
}

// SettingChange is who changed a setting and when (absent: never changed in
// the console).
type SettingChange struct {
	ChangedAt string `json:"changed_at,omitempty"`
	ChangedBy string `json:"changed_by,omitempty"`
}

func (h *AdminPlatformSettingsHandler) change(ctx context.Context, at time.Time, by *shared.ID) SettingChange {
	c := SettingChange{}
	if !at.IsZero() {
		c.ChangedAt = at.UTC().Format(time.RFC3339)
	}
	if by != nil && h.admins != nil {
		if a, err := h.admins.GetByID(ctx, *by); err == nil {
			c.ChangedBy = a.Email()
		}
	}
	return c
}

// decodeSetting reads a small JSON body, refusing unknown fields.
func decodeSetting(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// writeSettingError maps the errors every moved setting shares.
func (h *AdminPlatformSettingsHandler) writeSettingError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, consolesetting.ErrReasonRequired):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, platformsetting.ErrVersionConflict):
		apierror.Conflict("The " + what + " was changed by someone else; reload and try again").WriteJSON(w)
	case errors.Is(err, platformcaptcha.ErrLockedByEnvironment), errors.Is(err, deploymentregion.ErrLockedByEnvironment),
		errors.Is(err, platformai.ErrLockedByEnvironment):
		apierror.New(http.StatusConflict, CodeSettingLockedByEnvironment, err.Error()).WriteJSON(w)
	case errors.Is(err, deploymentregion.ErrAlreadySet):
		apierror.New(http.StatusConflict, CodeRegionAlreadySet, err.Error()).WriteJSON(w)
	case errors.Is(err, deploymentregion.ErrOrganizationsExist):
		apierror.New(http.StatusConflict, CodeRegionOrganizationsExist, err.Error()).WriteJSON(w)
	default:
		h.logger.Error("platform setting failed", "setting", what, "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not save the " + what).WriteJSON(w)
	}
}

func requireActor(w http.ResponseWriter, r *http.Request) *admin.AdminUser {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
	}
	return actor
}

// ---- CAPTCHA ---------------------------------------------------------------

// CaptchaSettingsResponse is the CAPTCHA configuration without the secret.
type CaptchaSettingsResponse struct {
	SiteKey   string `json:"site_key"`
	SecretSet bool   `json:"secret_set"`
	// Source: none, console or environment.
	Source              string `json:"source"`
	LockedByEnvironment bool   `json:"locked_by_environment"`
	// EnvVar names the variable that locks the keys.
	EnvVar  string `json:"env_var"`
	Version int    `json:"version"`
	SettingChange
}

// UpdateCaptchaRequest changes the CAPTCHA keys.
type UpdateCaptchaRequest struct {
	SiteKey string `json:"site_key"`
	// Secret: omit to keep the stored one, "" to remove it.
	Secret  *string `json:"secret,omitempty"`
	Reason  string  `json:"reason"`
	Version int     `json:"version"`
}

// CaptchaVerifyRequest checks a secret key before or after saving it.
type CaptchaVerifyRequest struct {
	// Secret to check; empty checks the secret in force.
	Secret string `json:"secret,omitempty"`
}

// CaptchaVerifyResponse is the outcome of a secret check.
type CaptchaVerifyResponse struct {
	// Result: valid, invalid or unreachable.
	Result string `json:"result"`
}

func (h *AdminPlatformSettingsHandler) captchaResponse(ctx context.Context, s platformcaptcha.Settings) CaptchaSettingsResponse {
	return CaptchaSettingsResponse{SiteKey: s.SiteKey, SecretSet: s.SecretSet, Source: s.Source,
		LockedByEnvironment: s.LockedByEnvironment, EnvVar: platformcaptcha.EnvSecret, Version: s.Version,
		SettingChange: h.change(ctx, s.UpdatedAt, s.UpdatedBy)}
}

// GetCaptcha returns the CAPTCHA keys without the secret.
// @Summary      Get the CAPTCHA keys
// @Description  The Turnstile site key and whether a secret key is set (never the secret), where they come from and who changed them last. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  CaptchaSettingsResponse
// @Security     AdminAuth
// @Router       /admin/settings/captcha [get]
func (h *AdminPlatformSettingsHandler) GetCaptcha(w http.ResponseWriter, r *http.Request) {
	s, err := h.Captcha.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "CAPTCHA keys", err)
		return
	}
	writeJSON(w, http.StatusOK, h.captchaResponse(r.Context(), s))
}

// UpdateCaptcha changes the CAPTCHA keys.
// @Summary      Change the CAPTCHA keys
// @Description  Super admin with a fresh confirmation and a reason. Both keys are set or removed together; the secret is encrypted at rest and never returned. Refused (409 SETTING_LOCKED_BY_ENVIRONMENT) while CAPTCHA_TURNSTILE_SECRET is set on the server. Applies without a restart; audited critical, every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateCaptchaRequest  true  "Keys"
// @Success      200  {object}  CaptchaSettingsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/captcha [put]
func (h *AdminPlatformSettingsHandler) UpdateCaptcha(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdateCaptchaRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	s, err := h.Captcha.Update(r.Context(), actor, platformcaptcha.Input{SiteKey: req.SiteKey, Secret: req.Secret, Reason: req.Reason},
		req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "CAPTCHA keys", err)
		return
	}
	writeJSON(w, http.StatusOK, h.captchaResponse(r.Context(), s))
}

// VerifyCaptcha asks Turnstile whether it knows a secret key.
// @Summary      Check a CAPTCHA secret key
// @Description  Asks Cloudflare Turnstile (a fixed address) whether it accepts the secret key given, or the one in force. Nothing is stored or logged. Super admin.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      CaptchaVerifyRequest  true  "Secret"
// @Success      200  {object}  CaptchaVerifyResponse
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/captcha/verify [post]
func (h *AdminPlatformSettingsHandler) VerifyCaptcha(w http.ResponseWriter, r *http.Request) {
	var req CaptchaVerifyRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	res, err := h.Captcha.CheckSecret(r.Context(), req.Secret)
	if errors.Is(err, platformcaptcha.ErrNoSecret) {
		apierror.New(http.StatusConflict, CodeSettingNotConfigured, "No secret key is set; enter one to check it").WriteJSON(w)
		return
	}
	if err != nil {
		h.writeSettingError(w, "CAPTCHA keys", err)
		return
	}
	writeJSON(w, http.StatusOK, CaptchaVerifyResponse{Result: string(res)})
}

// ---- Deployment region ----------------------------------------------------------

// RegionSettingsResponse is the deployment region.
type RegionSettingsResponse struct {
	Region string `json:"region"`
	// Source: none, console or environment.
	Source              string `json:"source"`
	LockedByEnvironment bool   `json:"locked_by_environment"`
	EnvVar              string `json:"env_var"`
	// Settable: no region is set and no organization exists yet.
	Settable bool `json:"settable"`
	SettingChange
}

// SetRegionRequest sets the region once.
type SetRegionRequest struct {
	Region string `json:"region"`
	Reason string `json:"reason"`
}

func (h *AdminPlatformSettingsHandler) regionResponse(ctx context.Context, s deploymentregion.Settings) RegionSettingsResponse {
	return RegionSettingsResponse{Region: s.Region, Source: s.Source, LockedByEnvironment: s.LockedByEnvironment,
		EnvVar: deploymentregion.EnvVar, Settable: s.Settable, SettingChange: h.change(ctx, s.UpdatedAt, s.UpdatedBy)}
}

// GetRegion returns the deployment region.
// @Summary      Get the deployment region
// @Description  The data region new organizations are stamped with, where it comes from, and whether it can still be set (only before the first organization). Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  RegionSettingsResponse
// @Security     AdminAuth
// @Router       /admin/settings/region [get]
func (h *AdminPlatformSettingsHandler) GetRegion(w http.ResponseWriter, r *http.Request) {
	s, err := h.Region.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "deployment region", err)
		return
	}
	writeJSON(w, http.StatusOK, h.regionResponse(r.Context(), s))
}

// SetRegion sets the deployment region once.
// @Summary      Set the deployment region (once)
// @Description  Super admin with a fresh confirmation and a reason. Allowed once, and only while no organization exists (409 REGION_ORGANIZATIONS_EXIST, REGION_ALREADY_SET); refused while DEPLOYMENT_REGION is set (409 SETTING_LOCKED_BY_ENVIRONMENT). Audited critical, every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      SetRegionRequest  true  "Region"
// @Success      200  {object}  RegionSettingsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/region [put]
func (h *AdminPlatformSettingsHandler) SetRegion(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req SetRegionRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	s, err := h.Region.Set(r.Context(), actor, req.Region, req.Reason, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "deployment region", err)
		return
	}
	writeJSON(w, http.StatusOK, h.regionResponse(r.Context(), s))
}

// ---- Storage quota -----------------------------------------------------------

// StorageQuotaResponse is the default storage quota of organizations.
type StorageQuotaResponse struct {
	// DefaultMB is the quota of an organization without its own storage
	// limit; 0 means no quota.
	DefaultMB int64 `json:"default_mb"`
	// Source: console or environment.
	Source        string `json:"source"`
	EnvVar        string `json:"env_var"`
	EnvironmentMB int64  `json:"environment_mb"`
	MaxMB         int64  `json:"max_mb"`
	Version       int    `json:"version"`
	SettingChange
}

// UpdateStorageQuotaRequest changes the default.
type UpdateStorageQuotaRequest struct {
	DefaultMB int64 `json:"default_mb"`
	Version   int   `json:"version"`
}

func (h *AdminPlatformSettingsHandler) quotaResponse(ctx context.Context, s storagequota.Settings) StorageQuotaResponse {
	return StorageQuotaResponse{DefaultMB: s.DefaultMB, Source: s.Source, EnvVar: storagequota.EnvVar,
		EnvironmentMB: s.EnvironmentMB, MaxMB: storagequota.MaxMB, Version: s.Version,
		SettingChange: h.change(ctx, s.UpdatedAt, s.UpdatedBy)}
}

// GetStorageQuota returns the default storage quota.
// @Summary      Get the default storage quota
// @Description  The MiB of uploaded files an organization without its own storage limit may hold (0: no quota), and where it comes from. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  StorageQuotaResponse
// @Security     AdminAuth
// @Router       /admin/settings/storage-quota [get]
func (h *AdminPlatformSettingsHandler) GetStorageQuota(w http.ResponseWriter, r *http.Request) {
	s, err := h.StorageQuota.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "storage quota", err)
		return
	}
	writeJSON(w, http.StatusOK, h.quotaResponse(r.Context(), s))
}

// UpdateStorageQuota changes the default storage quota.
// @Summary      Change the default storage quota
// @Description  Super admin with a step-up. Applies to the next upload, without a restart; an organization's own storage limit still wins. Audited.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateStorageQuotaRequest  true  "Quota"
// @Success      200  {object}  StorageQuotaResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/storage-quota [put]
func (h *AdminPlatformSettingsHandler) UpdateStorageQuota(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdateStorageQuotaRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	s, err := h.StorageQuota.Update(r.Context(), actor, req.DefaultMB, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "storage quota", err)
		return
	}
	writeJSON(w, http.StatusOK, h.quotaResponse(r.Context(), s))
}

// ---- Alert webhook ---------------------------------------------------------

// AlertWebhookResponse is the alert webhook without its address or secret.
type AlertWebhookResponse struct {
	Enabled bool `json:"enabled"`
	URLSet  bool `json:"url_set"`
	// URLHost is the receiver's host name (the full address is a credential).
	URLHost   string `json:"url_host,omitempty"`
	SecretSet bool   `json:"secret_set"`
	Version   int    `json:"version"`
	SettingChange
}

// UpdateAlertWebhookRequest changes the webhook.
type UpdateAlertWebhookRequest struct {
	Enabled bool `json:"enabled"`
	// URL: omit to keep the stored address, "" to remove it.
	URL *string `json:"url,omitempty"`
	// Secret: omit to keep the stored signing secret, "" to remove it.
	Secret  *string `json:"secret,omitempty"`
	Reason  string  `json:"reason"`
	Version int     `json:"version"`
}

func (h *AdminPlatformSettingsHandler) alertResponse(ctx context.Context, s platformalert.Settings) AlertWebhookResponse {
	return AlertWebhookResponse{Enabled: s.Enabled, URLSet: s.URLSet, URLHost: s.URLHost, SecretSet: s.SecretSet,
		Version: s.Version, SettingChange: h.change(ctx, s.UpdatedAt, s.UpdatedBy)}
}

// GetAlertWebhook returns the alert webhook.
// @Summary      Get the alert webhook
// @Description  Whether alerts for administrators are also sent to a webhook, its host name, and whether a signing secret is set. The address and the secret are never returned. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  AlertWebhookResponse
// @Security     AdminAuth
// @Router       /admin/settings/alerts [get]
func (h *AdminPlatformSettingsHandler) GetAlertWebhook(w http.ResponseWriter, r *http.Request) {
	s, err := h.Alerts.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "alert webhook", err)
		return
	}
	writeJSON(w, http.StatusOK, h.alertResponse(r.Context(), s))
}

// UpdateAlertWebhook changes the alert webhook.
// @Summary      Change the alert webhook
// @Description  Super admin with a fresh confirmation and a reason. HTTPS only; internal addresses are refused. The address and the signing secret are encrypted at rest and never returned. The previous receiver is told before it stops getting alerts. Audited critical, every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateAlertWebhookRequest  true  "Webhook"
// @Success      200  {object}  AlertWebhookResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/alerts [put]
func (h *AdminPlatformSettingsHandler) UpdateAlertWebhook(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdateAlertWebhookRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	s, err := h.Alerts.Update(r.Context(), actor, platformalert.Input{Enabled: req.Enabled, URL: req.URL, Secret: req.Secret, Reason: req.Reason},
		req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "alert webhook", err)
		return
	}
	writeJSON(w, http.StatusOK, h.alertResponse(r.Context(), s))
}

// TestAlertWebhook sends a test alert.
// @Summary      Send a test alert
// @Description  Sends a test alert to the stored webhook (whether or not it is on). The receiver's answer is not returned. Super admin.
// @Tags         Admin System
// @Success      204
// @Failure      409  {object}  apierror.Error
// @Failure      502  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/alerts/test [post]
func (h *AdminPlatformSettingsHandler) TestAlertWebhook(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	err := h.Alerts.SendTest(r.Context(), actor)
	switch {
	case errors.Is(err, platformalert.ErrNotConfigured):
		apierror.New(http.StatusConflict, CodeSettingNotConfigured, "No webhook address is set").WriteJSON(w)
	case err != nil:
		h.logger.Warn("test alert failed", "error", logger.SanitizeError(err))
		apierror.New(http.StatusBadGateway, CodeSettingTestFailed, "The test alert was not accepted: "+err.Error()).WriteJSON(w)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- Platform AI provider --------------------------------------------------

// PlatformAIResponse is the platform AI provider without its key.
type PlatformAIResponse struct {
	Enabled             bool     `json:"enabled"`
	Provider            string   `json:"provider"`
	Model               string   `json:"model"`
	BaseURL             string   `json:"base_url"`
	AllowPrivate        bool     `json:"allow_private"`
	AllowedModels       []string `json:"allowed_models"`
	KeySet              bool     `json:"key_set"`
	LockedByEnvironment bool     `json:"locked_by_environment"`
	Providers           []string `json:"providers"`
	Version             int      `json:"version"`
	SettingChange
}

// UpdatePlatformAIRequest changes the provider.
type UpdatePlatformAIRequest struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	// BaseURL is the OpenAI-compatible server (provider openai_compatible).
	BaseURL string `json:"base_url"`
	// AllowPrivate lets that server be on a private network (RFC1918 / ULA)
	// and use http. Loopback, link-local and cloud metadata stay blocked.
	AllowPrivate bool `json:"allow_private"`
	// AllowedModels limits the models usable on the platform provider (empty: any).
	AllowedModels []string `json:"allowed_models"`
	// APIKey: omit to keep the stored key, "" to remove it.
	APIKey  *string `json:"api_key,omitempty"`
	Reason  string  `json:"reason"`
	Version int     `json:"version"`
}

func (h *AdminPlatformSettingsHandler) aiResponse(ctx context.Context, s platformai.Settings) PlatformAIResponse {
	models := s.AllowedModels
	if models == nil {
		models = []string{}
	}
	return PlatformAIResponse{Enabled: s.Enabled, Provider: s.Provider, Model: s.Model, BaseURL: s.BaseURL,
		AllowPrivate: s.AllowPrivate, AllowedModels: models, KeySet: s.KeySet,
		LockedByEnvironment: s.LockedByEnvironment, Providers: platformai.Providers, Version: s.Version,
		SettingChange: h.change(ctx, s.UpdatedAt, s.UpdatedBy)}
}

// GetPlatformAI returns the platform AI provider.
// @Summary      Get the platform AI provider
// @Description  The provider and model organizations in platform AI mode use, whether it is on and whether a key is set (never the key). Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  PlatformAIResponse
// @Security     AdminAuth
// @Router       /admin/settings/ai [get]
func (h *AdminPlatformSettingsHandler) GetPlatformAI(w http.ResponseWriter, r *http.Request) {
	s, err := h.AI.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "AI provider", err)
		return
	}
	writeJSON(w, http.StatusOK, h.aiResponse(r.Context(), s))
}

// UpdatePlatformAI changes the platform AI provider.
// @Summary      Change the platform AI provider
// @Description  Super admin with a fresh confirmation and a reason. Off by default; turning it on needs a provider, a model and a key (an OpenAI-compatible server: its base URL, the key optional). allow_private lets the OpenAI-compatible server sit on a private network; it is audited with the rest. The key is encrypted at rest and never returned. Refused (409 SETTING_LOCKED_BY_ENVIRONMENT) while an AI key is set on the server. Audited critical, every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdatePlatformAIRequest  true  "Provider"
// @Success      200  {object}  PlatformAIResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/ai [put]
func (h *AdminPlatformSettingsHandler) UpdatePlatformAI(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdatePlatformAIRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	s, err := h.AI.Update(r.Context(), actor, platformai.Input{Enabled: req.Enabled, Provider: req.Provider, Model: req.Model,
		APIKey: req.APIKey, Reason: req.Reason, BaseURL: req.BaseURL, AllowPrivate: req.AllowPrivate, AllowedModels: req.AllowedModels}, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "AI provider", err)
		return
	}
	writeJSON(w, http.StatusOK, h.aiResponse(r.Context(), s))
}

// TestPlatformAI sends one minimal request with the stored key.
// @Summary      Test the platform AI key
// @Description  Sends one minimal request (one token) to the stored provider with the stored key, whether or not platform AI is on. The provider's answer is not returned. Super admin.
// @Tags         Admin System
// @Success      204
// @Failure      409  {object}  apierror.Error
// @Failure      502  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/ai/test [post]
func (h *AdminPlatformSettingsHandler) TestPlatformAI(w http.ResponseWriter, r *http.Request) {
	err := h.AI.Test(r.Context())
	switch {
	case errors.Is(err, platformai.ErrNotConfigured):
		apierror.New(http.StatusConflict, CodeSettingNotConfigured, "Choose a provider and a model and save a key first").WriteJSON(w)
	case errors.Is(err, platformai.ErrLockedByEnvironment):
		apierror.New(http.StatusConflict, CodeSettingLockedByEnvironment, err.Error()).WriteJSON(w)
	case err != nil:
		// The provider's error can quote the request; log it, answer generically.
		h.logger.Warn("platform AI key test failed", "error", logger.SanitizeError(err))
		apierror.New(http.StatusBadGateway, CodeSettingTestFailed,
			"The provider refused the request: check the key and the model (details are in the API log)").WriteJSON(w)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
