package handler

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MCPOAuthHandler serves the authorization server of the MCP endpoint
// (RFC-062): its metadata, /oauth/authorize, /oauth/token, /oauth/revoke and
// the consent API the web consent page calls.
type MCPOAuthHandler struct {
	svc *mcpoauthapp.Service
	log *logger.Logger
}

// NewMCPOAuthHandler builds the handler.
func NewMCPOAuthHandler(svc *mcpoauthapp.Service, log *logger.Logger) *MCPOAuthHandler {
	return &MCPOAuthHandler{svc: svc, log: log.With("handler", "mcp-oauth")}
}

// Paths of the authorization server, relative to the issuer.
const (
	mcpAuthorizePath = "/oauth/authorize"
	mcpTokenPath     = "/oauth/token"
	mcpRevokePath    = "/oauth/revoke"
	// mcpConsentPage is the web page that asks the person.
	mcpConsentPage = "/oauth/consent"
	// maxOAuthFormBytes bounds a token or revocation request body.
	maxOAuthFormBytes = 16 * 1024
)

// authorizationServerMetadata is the RFC 8414 document.
type authorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// ServerMetadata serves GET /.well-known/oauth-authorization-server.
func (h *MCPOAuthHandler) ServerMetadata(w http.ResponseWriter, _ *http.Request) {
	e := h.svc.Endpoints()
	scopes := mcpoauth.ReadScopes()
	names := make([]string, len(scopes))
	for i, s := range scopes {
		names[i] = string(s)
	}
	writePublicMetadata(w, authorizationServerMetadata{
		Issuer:                                     e.Issuer,
		AuthorizationEndpoint:                      e.Issuer + mcpAuthorizePath,
		TokenEndpoint:                              e.Issuer + mcpTokenPath,
		RevocationEndpoint:                         e.Issuer + mcpRevokePath,
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		TokenEndpointAuthMethodsSupported:          []string{"none"},
		RevocationEndpointAuthMethodsSupported:     []string{"none"},
		ScopesSupported:                            names,
		ClientIDMetadataDocumentSupported:          true,
		AuthorizationResponseIssParameterSupported: true,
	})
}

// Authorize serves GET /oauth/authorize. A valid request is stored and the
// browser goes to the consent page; a request whose client or redirect URI
// cannot be trusted gets an error page and is never redirected (RFC 6749
// §4.1.2.1); any other error goes back to the client.
func (h *MCPOAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	id, aerr := h.svc.StartAuthorization(r.Context(), r.URL.Query())
	if aerr != nil {
		if aerr.Redirect {
			http.Redirect(w, r, h.svc.AuthorizeErrorRedirect(aerr), http.StatusFound)
			return
		}
		writeOAuthErrorPage(w, aerr.Code)
		return
	}
	target := h.svc.Endpoints().Issuer + mcpConsentPage + "?" + url.Values{"request": {id.String()}}.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

// oauthErrorPage is the page shown when an authorization request cannot be
// sent back to the client. Fixed text only: nothing from the request is
// echoed.
const oauthErrorPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cannot connect the application</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#222}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}</style></head>
<body><h1>Cannot connect the application</h1><p>The application asked to connect to OpenCTEM in a way that cannot be accepted (unknown application, or a return address it did not register). Nothing was shared.</p><p>Contact whoever provides the application.</p></body></html>`

func writeOAuthErrorPage(w http.ResponseWriter, code string) {
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("X-OAuth-Error", code)
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(oauthErrorPage))
}

// Token serves POST /oauth/token.
func (h *MCPOAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	form, oerr := readOAuthForm(w, r)
	if oerr != nil {
		writeOAuthError(w, http.StatusBadRequest, oerr)
		return
	}
	resp, oerr := h.svc.Token(r.Context(), form, oauthActor(r))
	if oerr != nil {
		status := http.StatusBadRequest
		if oerr.Code == "invalid_client" {
			status = http.StatusUnauthorized
		}
		if oerr.Code == "server_error" {
			status = http.StatusInternalServerError
		}
		writeOAuthError(w, status, oerr)
		return
	}
	noStoreJSON(w, http.StatusOK, resp)
}

// Revoke serves POST /oauth/revoke (RFC 7009). It answers 200 whether or not
// the token was known.
func (h *MCPOAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	form, oerr := readOAuthForm(w, r)
	if oerr != nil {
		writeOAuthError(w, http.StatusBadRequest, oerr)
		return
	}
	h.svc.Revoke(r.Context(), form.Get("token"), form.Get("client_id"), oauthActor(r))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

// readOAuthForm reads an application/x-www-form-urlencoded body. Client
// secrets are not supported: an Authorization header is invalid_client.
func readOAuthForm(w http.ResponseWriter, r *http.Request) (url.Values, *mcpoauthapp.OAuthError) {
	if r.Header.Get("Authorization") != "" {
		return nil, &mcpoauthapp.OAuthError{Code: "invalid_client", Description: "public clients only: send client_id, no client authentication"}
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" {
		return nil, &mcpoauthapp.OAuthError{Code: "invalid_request", Description: "content type must be application/x-www-form-urlencoded"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthFormBytes)
	if err := r.ParseForm(); err != nil {
		return nil, &mcpoauthapp.OAuthError{Code: "invalid_request", Description: "malformed form body"}
	}
	// Parameters only from the body, never the query string (tokens and
	// codes must not travel in URLs).
	if r.URL.RawQuery != "" {
		return nil, &mcpoauthapp.OAuthError{Code: "invalid_request", Description: "parameters must be sent in the body"}
	}
	return r.PostForm, nil
}

func writeOAuthError(w http.ResponseWriter, status int, e *mcpoauthapp.OAuthError) {
	noStoreJSON(w, status, map[string]string{"error": e.Code, "error_description": e.Description})
}

func noStoreJSON(w http.ResponseWriter, status int, v any) {
	hdr := w.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Pragma", "no-cache")
	// Public clients may run in a browser; nothing here relies on cookies.
	hdr.Set("Access-Control-Allow-Origin", "*")
	hdr.Del("Access-Control-Allow-Credentials")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthActor(r *http.Request) mcpoauthapp.Actor {
	return mcpoauthapp.Actor{IP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID")}
}

// --- Consent API (signed-in session) ---------------------------------------

type consentScopeResponse struct {
	Scope   string `json:"scope"`
	Title   string `json:"title"`
	Write   bool   `json:"write"`
	Granted bool   `json:"granted"`
}

type consentRequestResponse struct {
	ID           string                 `json:"id"`
	ClientName   string                 `json:"client_name"`
	ClientID     string                 `json:"client_id"`
	ClientKind   string                 `json:"client_kind"`
	ClientHost   string                 `json:"client_host,omitempty"`
	RedirectHost string                 `json:"redirect_host"`
	RedirectURI  string                 `json:"redirect_uri"`
	LoopbackOnly bool                   `json:"loopback_only"`
	Scopes       []consentScopeResponse `json:"scopes"`
	ExpiresAt    time.Time              `json:"expires_at"`
}

type consentDecisionResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// consentCaller reads the signed-in user, their organization and the
// request id. Only a browser session may answer a consent request.
func consentCaller(r *http.Request) (requestID, userID, tenantID shared.ID, ok bool) {
	ctx := r.Context()
	if middleware.IsAPIKeyAuthenticated(ctx) {
		return requestID, userID, tenantID, false
	}
	var err1, err2, err3 error
	requestID, err1 = shared.IDFromString(chi.URLParam(r, "id"))
	userID, err2 = shared.IDFromString(middleware.GetUserID(ctx))
	tenantID, err3 = shared.IDFromString(middleware.GetTenantID(ctx))
	return requestID, userID, tenantID, err1 == nil && err2 == nil && err3 == nil
}

// GetConsentRequest serves GET /api/v1/oauth/requests/{id}: what the consent
// page shows. Opening it claims the request for the signed-in user.
func (h *MCPOAuthHandler) GetConsentRequest(w http.ResponseWriter, r *http.Request) {
	requestID, userID, tenantID, ok := consentCaller(r)
	if !ok {
		apierror.NotFound("Authorization request").WriteJSON(w)
		return
	}
	view, err := h.svc.ConsentRequest(r.Context(), requestID, userID, tenantID)
	if err != nil {
		h.consentError(w, err)
		return
	}
	out := consentRequestResponse{
		ID: view.RequestID, ClientName: view.ClientName, ClientID: view.ClientID, ClientKind: string(view.ClientKind),
		ClientHost: view.ClientHost, RedirectHost: view.RedirectHost, RedirectURI: view.RedirectURI,
		LoopbackOnly: view.LoopbackOnly, ExpiresAt: view.ExpiresAt,
	}
	for _, s := range view.Scopes {
		out.Scopes = append(out.Scopes, consentScopeResponse{Scope: string(s.Scope), Title: s.Title, Write: s.Write, Granted: s.Granted})
	}
	noStoreJSON(w, http.StatusOK, out)
}

// ApproveConsent serves POST /api/v1/oauth/requests/{id}/approve.
func (h *MCPOAuthHandler) ApproveConsent(w http.ResponseWriter, r *http.Request) {
	requestID, userID, tenantID, ok := consentCaller(r)
	if !ok {
		apierror.NotFound("Authorization request").WriteJSON(w)
		return
	}
	to, err := h.svc.Approve(r.Context(), requestID, userID, tenantID, oauthActor(r))
	if err != nil {
		h.consentError(w, err)
		return
	}
	noStoreJSON(w, http.StatusOK, consentDecisionResponse{RedirectTo: to})
}

// DenyConsent serves POST /api/v1/oauth/requests/{id}/deny.
func (h *MCPOAuthHandler) DenyConsent(w http.ResponseWriter, r *http.Request) {
	requestID, userID, tenantID, ok := consentCaller(r)
	if !ok {
		apierror.NotFound("Authorization request").WriteJSON(w)
		return
	}
	to, err := h.svc.Deny(r.Context(), requestID, userID, tenantID, oauthActor(r))
	if err != nil {
		h.consentError(w, err)
		return
	}
	noStoreJSON(w, http.StatusOK, consentDecisionResponse{RedirectTo: to})
}

func (h *MCPOAuthHandler) consentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mcpoauthapp.ErrNothingToGrant):
		apierror.Forbidden("You have none of the access this application asks for in this organization").WriteJSON(w)
	case errors.Is(err, mcpoauthapp.ErrConsentUnavailable):
		apierror.NotFound("Authorization request").WriteJSON(w)
	default:
		h.log.Error("mcp oauth consent", "error", err.Error())
		apierror.InternalServerError("Could not complete the request").WriteJSON(w)
	}
}
