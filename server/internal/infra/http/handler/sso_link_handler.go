package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// Account > Security, "Organization sign-in": the signed-in person links and
// unlinks their organization's single sign-on on their own account
// (auth/sso_link.go). The account and session are always the caller's; no
// request field names an account.

// SSOLinkStartRequest starts linking an organization's sign-in.
type SSOLinkStartRequest struct {
	// Org is the organization's slug (one the caller is a member of).
	Org         string `json:"org"`
	RedirectURI string `json:"redirect_uri"`
	LinkProofRequest
}

// SSOLinkCompleteRequest finishes a link after the identity provider's
// redirect.
type SSOLinkCompleteRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
	// BrowserBinding is the secret the link start gave this browser.
	BrowserBinding string `json:"browser_binding"`
}

// ListSSOLinks returns the caller's organizations with single sign-on.
// @Summary      List my organization sign-in links
// @Description  The organizations of the signed-in account that have an OIDC single sign-on, with the account's identity at each (absent when not linked), other organization identities, and the proof a link or unlink asks for.
// @Tags         Account
// @Produce      json
// @Success      200  {object}  auth.SSOLinks
// @Router       /me/sso-links [get]
func (h *SSOHandler) ListSSOLinks(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	out, err := h.ssoService.ListSSOLinks(r.Context(), userID)
	if err != nil {
		h.handlePublicError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeIdentityJSON(w, http.StatusOK, out)
}

// StartSSOLink returns the identity provider's authorization URL for linking
// the organization's sign-in to the signed-in account.
// @Summary      Start linking an organization's sign-in
// @Description  Returns the authorization URL of the organization's identity provider, which is asked to authenticate the person again. The state is bound to this account, this session and the organization, is accepted only by the link callback, once, within the state lifetime, and only with browser_binding (keep it in an HttpOnly cookie). step_up must carry the authenticator code (never a recovery code) or else the password, typed for this request. 403 LINK_PROOF_REQUIRED, LINK_PROOF_FAILED, LINK_PROOF_UNAVAILABLE, ACCOUNT_LOCKED, SSO_NOT_A_MEMBER (not an active member of the organization).
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        provider  path  string               true  "entra_id, okta or google_workspace"
// @Param        request   body  SSOLinkStartRequest  true  "Organization, callback URL and proof"
// @Success      200  {object}  auth.SSOAuthorizeResult
// @Router       /me/sso-links/{provider}/start [post]
func (h *SSOHandler) StartSSOLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	if userID == "" || sessionID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req SSOLinkStartRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if req.Org == "" || req.RedirectURI == "" {
		apierror.BadRequest("org and redirect_uri are required").WriteJSON(w)
		return
	}
	res, err := h.ssoService.StartSSOLink(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()), auth.SSOLinkStartInput{
		UserID: userID, SessionID: sessionID, OrgSlug: req.Org,
		Provider: r.PathValue("provider"), RedirectURI: req.RedirectURI, Proof: req.StepUp,
	})
	if err != nil {
		h.handlePublicError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeIdentityJSON(w, http.StatusOK, res)
}

// CompleteSSOLink binds the organization identity to the signed-in account.
// @Summary      Finish linking an organization's sign-in
// @Description  Redeems the identity provider's code and links the verified identity to the signed-in account. No session is issued; the account's other sessions are signed out. The state must come from the link start of this account and this session, once, with this browser's browser_binding; otherwise 400 SSO_INVALID_STATE. 409 IDENTITY_LINKED_ELSEWHERE (the identity belongs to another account) or PROVIDER_ALREADY_LINKED (the account holds another identity of this provider); 403 SSO_NOT_A_MEMBER.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        provider  path  string                  true  "entra_id, okta or google_workspace"
// @Param        request   body  SSOLinkCompleteRequest  true  "Code, state and browser binding"
// @Success      200  {object}  auth.SSOLink
// @Router       /me/sso-links/{provider}/complete [post]
func (h *SSOHandler) CompleteSSOLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	if userID == "" || sessionID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req SSOLinkCompleteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if req.Code == "" || req.State == "" || req.BrowserBinding == "" {
		apierror.BadRequest("code, state and browser_binding are required").WriteJSON(w)
		return
	}
	res, err := h.ssoService.CompleteSSOLink(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()), auth.SSOLinkCompleteInput{
		UserID: userID, SessionID: sessionID, Provider: r.PathValue("provider"),
		Code: req.Code, State: req.State, BrowserBinding: req.BrowserBinding,
	})
	if err != nil {
		h.handlePublicError(w, err)
		return
	}
	writeIdentityJSON(w, http.StatusOK, res)
}

// UnlinkSSOIdentity removes an organization sign-in identity from the
// signed-in account.
// @Summary      Unlink an organization's sign-in
// @Description  Removes one organization (OIDC) sign-in identity of the signed-in account; only an account with a password may (409 IDENTITY_MANAGED_BY_ORGANIZATION otherwise). step_up must carry the authenticator code or else the password, typed for this request: 403 LINK_PROOF_REQUIRED, LINK_PROOF_FAILED, LINK_PROOF_UNAVAILABLE, ACCOUNT_LOCKED.
// @Tags         Account
// @Accept       json
// @Param        id       path  string            true  "Identity id"
// @Param        request  body  LinkProofRequest  true  "Proof typed in the confirm dialog"
// @Success      204
// @Router       /me/sso-links/identities/{identity} [delete]
func (h *SSOHandler) UnlinkSSOIdentity(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	if userID == "" || sessionID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	proof, ok := decodeLinkProof(w, r)
	if !ok {
		return
	}
	err := h.ssoService.UnlinkSSOIdentity(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()), auth.SSOUnlinkInput{
		UserID: userID, SessionID: sessionID, IdentityID: r.PathValue("identity"), Proof: proof,
	})
	if err != nil {
		h.handlePublicError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
