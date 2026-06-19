package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	samldom "github.com/openctemio/api/pkg/domain/samlprovider"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// SAMLHandler exposes the SAML 2.0 SP endpoints (RFC-009 9d): the public SP
// metadata an admin registers with their IdP, and admin config CRUD. The
// SP-initiated login + ACS (9e) are added on top of this in a follow-up.
type SAMLHandler struct {
	svc    *app.SAMLService
	logger *logger.Logger
}

// NewSAMLHandler creates the handler.
func NewSAMLHandler(svc *app.SAMLService, log *logger.Logger) *SAMLHandler {
	return &SAMLHandler{svc: svc, logger: log.With("handler", "saml")}
}

// requestBaseURL derives the deployment origin (scheme://host), honoring the
// reverse-proxy forwarded headers so the SP URLs match the public address.
func requestBaseURL(r *http.Request) string {
	scheme := "https"
	if fp := r.Header.Get("X-Forwarded-Proto"); fp != "" {
		scheme = fp
	} else if r.TLS == nil {
		scheme = "http"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// Metadata handles GET /api/v1/auth/saml/{org}/metadata (public).
func (h *SAMLHandler) Metadata(w http.ResponseWriter, r *http.Request) {
	org := chi.URLParam(r, "org")
	xmlStr, err := h.svc.Metadata(r.Context(), org, requestBaseURL(r))
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
	p, err := h.svc.UpsertConfig(r.Context(), tenantID, app.SAMLConfigInput{
		IDPEntityID:    body.IDPEntityID,
		IDPSSOURL:      body.IDPSSOURL,
		IDPCertificate: body.IDPCertificate,
		AllowedDomains: body.AllowedDomains,
		DefaultRole:    body.DefaultRole,
		AutoProvision:  body.AutoProvision,
		Enabled:        body.Enabled,
	})
	if err != nil {
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest("invalid SAML configuration").WriteJSON(w)
			return
		}
		h.logger.Error("set saml config failed", "error", err)
		apierror.InternalServerError("failed to save SAML configuration").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toSAMLConfigView(p))
}

// DeleteConfig handles DELETE /api/v1/settings/saml (JWT admin).
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
	w.WriteHeader(http.StatusNoContent)
}
