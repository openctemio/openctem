package handler

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	samldom "github.com/openctemio/openctem/api/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SAMLHandler exposes the SAML 2.0 SP endpoints (RFC-009 9d+9e): the public SP
// metadata an admin registers with their IdP, admin config CRUD, and the
// SP-initiated browser login (login redirect + ACS).
type SAMLHandler struct {
	svc         *auth.SAMLService
	cookieCfg   CookieConfig
	frontendURL string // origin the browser is redirected to after login
	publicURL   string // configured public origin (APP_URL); see samlBaseURL
	audit       *auditsvc.AuditService
	changes     *auth.SSOChangeService
	logger      *logger.Logger
}

// SetChangeApproval routes SAML changes made from the platform admin console
// through an owner's approval (RFC-022).
func (h *SAMLHandler) SetChangeApproval(svc *auth.SSOChangeService) {
	h.changes = svc
}

// SetAuditService records SAML config changes in the organization's audit log.
func (h *SAMLHandler) SetAuditService(svc *auditsvc.AuditService) {
	h.audit = svc
}

// SetPublicURL sets the configured public origin (APP_URL) the SP URLs are
// built on. When empty, forwarded headers are honored only from trusted
// proxies.
func (h *SAMLHandler) SetPublicURL(publicURL string) {
	h.publicURL = publicURL
}

// NewSAMLHandler creates the handler. cookieCfg + frontendURL drive the
// browser login flow (session cookies + post-login redirect).
func NewSAMLHandler(svc *auth.SAMLService, cookieCfg CookieConfig, frontendURL string, log *logger.Logger) *SAMLHandler {
	return &SAMLHandler{svc: svc, cookieCfg: cookieCfg, frontendURL: frontendURL, logger: log.With("handler", "saml")}
}

// samlRequestCookie is the short-lived cookie that carries the AuthnRequest ID
// so the ACS can bind the response's InResponseTo. It must be SameSite=None +
// Secure because the IdP delivers the response as a cross-site top-level POST
// (Lax cookies are not sent on cross-site POST) — SAML therefore requires HTTPS.
func samlRequestCookieName(org string) string { return "saml_authn_" + org }

// Login handles GET /api/v1/auth/saml/{org}/login — SP-initiated login.
func (h *SAMLHandler) Login(w http.ResponseWriter, r *http.Request) {
	org := chi.URLParam(r, "org")
	redirectURL, requestID, err := h.svc.Login(r.Context(), org, h.baseURL(r))
	if err != nil {
		h.redirectWithError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     samlRequestCookieName(org),
		Value:    requestID,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ACS handles POST /api/v1/auth/saml/{org}/acs — the IdP posts the SAML
// response here. On success it establishes the session cookies and redirects
// the browser to the frontend.
func (h *SAMLHandler) ACS(w http.ResponseWriter, r *http.Request) {
	org := chi.URLParam(r, "org")

	var possibleRequestIDs []string
	if c, cerr := r.Cookie(samlRequestCookieName(org)); cerr == nil && c.Value != "" {
		possibleRequestIDs = []string{c.Value}
	}
	// Clear the single-use request cookie regardless of the outcome.
	http.SetCookie(w, &http.Cookie{
		Name: samlRequestCookieName(org), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode,
	})

	// A SAML response is a few KB; cap the form body the service parses.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	result, err := h.svc.ACS(r.Context(), org, h.baseURL(r), r, possibleRequestIDs)
	if err != nil {
		h.redirectWithError(w, r, err)
		return
	}

	// Establish the session: refresh (httpOnly) + access + tenant cookies, the
	// same contract the local-login and OAuth flows use.
	SetRefreshTokenCookie(w, result.RefreshToken, time.Now().Add(30*24*time.Hour), h.cookieCfg)
	SetAccessTokenCookie(w, result.AccessToken, time.Now().Add(time.Duration(result.ExpiresIn)*time.Second), h.cookieCfg)
	SetTenantCookie(w, result.TenantID, result.TenantSlug, "", h.cookieCfg)

	http.Redirect(w, r, h.frontendURL, http.StatusFound)
}

// redirectWithError sends the browser back to the frontend login page with a
// generic error flag (never leaks the specific SAML failure).
func (h *SAMLHandler) redirectWithError(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.Warn("saml login failed", "error", err)
	dest := strings.TrimSuffix(h.frontendURL, "/") + "/login?error=saml"
	http.Redirect(w, r, dest, http.StatusFound)
}

// baseURL is the deployment origin (scheme://host) the SP URLs are built
// on: entity ID, ACS URL, and the audience/destination an assertion must
// carry. See samlBaseURL.
func (h *SAMLHandler) baseURL(r *http.Request) string {
	return samlBaseURL(r, h.publicURL, trustedProxiesForAuth)
}

// samlBaseURL derives the SP origin. In order:
//
//  1. the configured public URL (APP_URL), when set — the only source a
//     client cannot influence, and what production should use;
//  2. X-Forwarded-Proto / X-Forwarded-Host, but only when the TCP peer is a
//     trusted proxy (SERVER_TRUSTED_PROXIES) and the values are well formed;
//  3. the request's own Host and TLS state.
//
// Taking the forwarded headers from any client let a request to the ACS
// choose the audience the SP checks, so an assertion issued to a different
// service provider at the same IdP could be replayed here.
func samlBaseURL(r *http.Request, publicURL string, trusted *httpsec.TrustedProxySet) string {
	if origin, ok := originOf(publicURL); ok {
		return origin
	}

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host

	if fromTrustedProxy(r, trusted) {
		if fp := strings.ToLower(firstForwardedValue(r.Header.Get("X-Forwarded-Proto"))); fp == "http" || fp == "https" {
			scheme = fp
		}
		if fh := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); validForwardedHost(fh) {
			host = fh
		}
	}
	return scheme + "://" + host
}

// originOf returns scheme://host[:port] of an absolute http(s) URL.
func originOf(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

func fromTrustedProxy(r *http.Request, trusted *httpsec.TrustedProxySet) bool {
	if trusted == nil || trusted.IsEmpty() {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && trusted.Contains(ip)
}

// firstForwardedValue takes the left-most entry of a comma-separated
// forwarded header (the value the outermost proxy set).
func firstForwardedValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// validForwardedHost accepts host or host:port with DNS/IP characters only,
// so nothing that changes the URL structure is echoed into SP URLs.
func validForwardedHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	u, err := url.Parse("http://" + h)
	return err == nil && u.Host == h && u.Path == "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.ContainsAny(h, " \\\t\r\n")
}

// Metadata handles GET /api/v1/auth/saml/{org}/metadata (public).
func (h *SAMLHandler) Metadata(w http.ResponseWriter, r *http.Request) {
	org := chi.URLParam(r, "org")
	xmlStr, err := h.svc.Metadata(r.Context(), org, h.baseURL(r))
	if err != nil {
		apierror.NotFound("tenant").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xmlStr))
}

// samlConfigView is the admin read/write shape (the IdP certificate is public).
type samlConfigView struct {
	IDPEntityID    string   `json:"idp_entity_id"`
	IDPSSOURL      string   `json:"idp_sso_url"`
	IDPCertificate string   `json:"idp_certificate"`
	AllowedDomains []string `json:"allowed_domains"`
	DefaultRole    string   `json:"default_role"`
	AutoProvision  bool     `json:"auto_provision"`
	Enabled        bool     `json:"enabled"`
}

func toSAMLConfigView(p *samldom.SAMLProvider) samlConfigView {
	return samlConfigView{
		IDPEntityID:    p.IDPEntityID(),
		IDPSSOURL:      p.IDPSSOURL(),
		IDPCertificate: p.IDPCertificate(),
		AllowedDomains: p.AllowedDomains(),
		DefaultRole:    p.DefaultRole(),
		AutoProvision:  p.AutoProvision(),
		Enabled:        p.Enabled(),
	}
}

// GetConfig handles GET /api/v1/settings/saml (JWT admin).
// @Summary Get an organization's SAML config
// @Description Platform admin console (RFC-022): runs against the organization in the path.
// @Tags Admin Organization SSO
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/sso/saml [get]
func (h *SAMLHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	p, err := h.svc.GetConfig(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, samldom.ErrNotFound) {
			apierror.NotFound("SAML configuration").WriteJSON(w)
			return
		}
		h.logger.Error("get saml config failed", "error", err)
		apierror.InternalServerError("failed to load SAML configuration").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toSAMLConfigView(p))
}

// SetConfig handles PUT /api/v1/settings/saml (JWT admin).
// @Summary Set an organization's SAML config
// @Description Platform admin console (RFC-022): runs against the organization in the path. When the organization has an owner, the change is stored as pending (202, SSOChangeResponse) and takes effect only after an owner approves it; an organization without an owner yet gets it applied directly (200).
// @Tags Admin Organization SSO
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/sso/saml [put]
func (h *SAMLHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	var body samlConfigView
	if derr := json.NewDecoder(r.Body).Decode(&body); derr != nil {
		apierror.BadRequest("invalid JSON body").WriteJSON(w)
		return
	}
	in := auth.SAMLConfigInput{
		IDPEntityID:    body.IDPEntityID,
		IDPSSOURL:      body.IDPSSOURL,
		IDPCertificate: body.IDPCertificate,
		AllowedDomains: body.AllowedDomains,
		DefaultRole:    body.DefaultRole,
		AutoProvision:  body.AutoProvision,
		Enabled:        body.Enabled,
	}

	// From the platform admin console the change waits for an owner of the
	// organization, unless it has no owner yet (then SubmitSAML applies it).
	var p *samldom.SAMLProvider
	if by := ssoChangeRequester(r); by != nil {
		if h.changes == nil {
			writeSSOChangeApprovalUnavailable(w)
			return
		}
		res, serr := h.changes.SubmitSAML(r.Context(), tenantID, in, *by)
		if serr != nil {
			h.writeSetError(w, serr)
			return
		}
		if !res.Applied {
			writeSSOChangePending(w, r, h.audit, h.logger, res.Change)
			return
		}
		p, err = h.svc.GetConfig(r.Context(), tenantID)
	} else {
		p, err = h.svc.UpsertConfig(r.Context(), tenantID, in)
	}
	if err != nil {
		h.writeSetError(w, err)
		return
	}
	logOrgSSOEvent(r.Context(), h.audit, h.logger, r, auditsvc.NewSuccessEvent(audit.ActionSSOSAMLConfigUpdated, audit.ResourceTypeSAMLConfig, p.ID().String()).
		WithResourceName(p.IDPEntityID()).
		WithMessage("SAML single sign-on configuration saved").
		WithMetadata("idp_entity_id", p.IDPEntityID()).
		WithMetadata("idp_sso_url", p.IDPSSOURL()).
		WithMetadata("idp_certificate_sha256", certificateFingerprint(p.IDPCertificate())).
		WithMetadata("allowed_domains", p.AllowedDomains()).
		WithMetadata("default_role", p.DefaultRole()).
		WithMetadata("auto_provision", p.AutoProvision()).
		WithMetadata("enabled", p.Enabled()))
	writeJSON(w, http.StatusOK, toSAMLConfigView(p))
}

func (h *SAMLHandler) writeSetError(w http.ResponseWriter, err error) {
	if errors.Is(err, shared.ErrValidation) {
		apierror.BadRequest("invalid SAML configuration").WriteJSON(w)
		return
	}
	h.logger.Error("set saml config failed", "error", err)
	apierror.InternalServerError("failed to save SAML configuration").WriteJSON(w)
}

// DeleteConfig handles DELETE /api/v1/settings/saml (JWT admin).
// @Summary Delete an organization's SAML config
// @Description Platform admin console (RFC-022): runs against the organization in the path.
// @Tags Admin Organization SSO
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/sso/saml [delete]
func (h *SAMLHandler) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	if err := h.svc.DeleteConfig(r.Context(), tenantID); err != nil {
		h.logger.Error("delete saml config failed", "error", err)
		apierror.InternalServerError("failed to delete SAML configuration").WriteJSON(w)
		return
	}
	logOrgSSOEvent(r.Context(), h.audit, h.logger, r, auditsvc.NewSuccessEvent(audit.ActionSSOSAMLConfigDeleted, audit.ResourceTypeSAMLConfig, tenantID.String()).
		WithMessage("SAML single sign-on configuration deleted"))
	w.WriteHeader(http.StatusNoContent)
}
