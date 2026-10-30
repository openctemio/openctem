package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// Account > Security, "Connected sign-in methods": the signed-in person links
// and unlinks Google, GitHub and Microsoft sign-in on their own account
// (auth/identity_link.go). The account is always the session's; no request
// field names an account.

// LinkStartRequest starts linking a provider.
type LinkStartRequest struct {
	RedirectURI string `json:"redirect_uri"`
}

// LinkCallbackRequest finishes a link after the provider's redirect.
type LinkCallbackRequest struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
	// BrowserBinding is the secret the link start gave this browser.
	BrowserBinding string `json:"browser_binding"`
}

// ListSignInMethods returns the caller's sign-in methods.
// @Summary      List my sign-in methods
// @Description  The password (when the account has one) and the linked sign-in identities of the signed-in account, with the providers this platform offers for linking.
// @Tags         Account
// @Produce      json
// @Success      200  {object}  auth.SignInMethods
// @Router       /me/sign-in-methods [get]
func (h *OAuthHandler) ListSignInMethods(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	out, err := h.oauthService.ListSignInMethods(r.Context(), userID)
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}
	writeIdentityJSON(w, http.StatusOK, out)
}

// StartLink returns the provider's authorization URL for linking it to the
// signed-in account. Needs a fresh step-up (route gate).
// @Summary      Start linking a sign-in provider
// @Description  Returns the authorization URL of the provider. The state is bound to this account and this session and is accepted only by the link callback, once, within the state lifetime. browser_binding is a one-time secret for the browser that started the link: keep it in an HttpOnly cookie and send it back with the link callback. Requires a recent re-authentication (STEP_UP_REQUIRED).
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        provider  path  string            true  "google, github or microsoft"
// @Param        request   body  LinkStartRequest  true  "Callback URL"
// @Success      200  {object}  AuthorizeResponse
// @Router       /me/sign-in-method-links/{provider}/start [post]
func (h *OAuthHandler) StartLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	if userID == "" || sessionID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req LinkStartRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if req.RedirectURI == "" {
		req.RedirectURI = h.oauthConfig.FrontendCallbackURL
	}
	if !h.isRedirectAllowed(req.RedirectURI) {
		apierror.BadRequest("Invalid redirect URI").WriteJSON(w)
		return
	}
	res, err := h.oauthService.StartLink(r.Context(), auth.LinkStartInput{
		UserID: userID, SessionID: sessionID,
		Provider: auth.OAuthProvider(r.PathValue("provider")), RedirectURI: req.RedirectURI,
	})
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}
	writeIdentityJSON(w, http.StatusOK, AuthorizeResponse{AuthorizationURL: res.AuthorizationURL, State: res.State, BrowserBinding: res.BrowserBinding})
}

// CompleteLink binds the provider identity to the signed-in account.
// @Summary      Finish linking a sign-in provider
// @Description  Exchanges the provider's code and links the identity to the signed-in account. The state must have been issued by the link start for this account and this session, is single use and expires, and browser_binding must be the secret the link start gave this browser; otherwise 400 OAUTH_INVALID_STATE. 409 IDENTITY_LINKED_ELSEWHERE or PROVIDER_ALREADY_LINKED when it cannot be linked.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        provider  path  string               true  "google, github or microsoft"
// @Param        request   body  LinkCallbackRequest  true  "Code, state and browser binding"
// @Success      200  {object}  auth.SignInMethod
// @Router       /me/sign-in-method-links/{provider}/complete [post]
func (h *OAuthHandler) CompleteLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	if userID == "" || sessionID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req LinkCallbackRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if req.Code == "" || req.State == "" {
		apierror.BadRequest("Authorization code and state are required").WriteJSON(w)
		return
	}
	if req.RedirectURI == "" {
		req.RedirectURI = h.oauthConfig.FrontendCallbackURL
	}
	if !h.isRedirectAllowed(req.RedirectURI) {
		apierror.BadRequest("Invalid redirect URI").WriteJSON(w)
		return
	}
	m, err := h.oauthService.CompleteLink(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()), auth.LinkCompleteInput{
		UserID: userID, SessionID: sessionID,
		Provider: auth.OAuthProvider(r.PathValue("provider")),
		Code:     req.Code, State: req.State, RedirectURI: req.RedirectURI,
		BrowserBinding: req.BrowserBinding,
	})
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}
	writeIdentityJSON(w, http.StatusOK, m)
}

// Unlink removes a linked sign-in identity from the signed-in account. Needs a
// fresh step-up (route gate). The last sign-in method is never removed.
// @Summary      Unlink a sign-in provider
// @Description  Removes one linked Google, GitHub or Microsoft identity of the signed-in account. 409 LAST_SIGN_IN_METHOD when it is the account's only way to sign in. Requires a recent re-authentication (STEP_UP_REQUIRED).
// @Tags         Account
// @Param        id  path  string  true  "Identity id"
// @Success      204
// @Router       /me/sign-in-methods/{id} [delete]
func (h *OAuthHandler) Unlink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	err := h.oauthService.Unlink(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()), userID, r.PathValue("id"))
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeIdentityJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// PendingLinkDetails is the details of a 409 OAUTH_ACCOUNT_EXISTS that left a
// pending link: the secret the web server keeps for this browser in an
// HttpOnly cookie, and the provider.
type PendingLinkDetails struct {
	PendingLink string `json:"pending_link"`
	Provider    string `json:"provider"`
}

// PendingLinkRequest names a pending link by its secret.
type PendingLinkRequest struct {
	Token string `json:"token"`
}

func decodePendingLink(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req PendingLinkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.Token == "" {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return "", false
	}
	return req.Token, true
}

// DescribePendingLink tells the signed-in account which provider account is
// waiting to be linked to it.
// @Summary      Describe the sign-in method waiting to be linked
// @Description  A social sign-in refused with OAUTH_ACCOUNT_EXISTS leaves a pending link (details.pending_link). After signing in to that account, this returns the provider and its address. 404 PENDING_LINK_INVALID when there is none for this account (expired, used, or made for another account, which also spends it).
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        request  body  PendingLinkRequest  true  "Pending link secret"
// @Success      200  {object}  auth.PendingLinkInfo
// @Router       /me/pending-sign-in-link/describe [post]
func (h *OAuthHandler) DescribePendingLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	token, ok := decodePendingLink(w, r)
	if !ok {
		return
	}
	info, err := h.oauthService.DescribePendingLink(r.Context(), userID, token)
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}
	writeIdentityJSON(w, http.StatusOK, info)
}

// ConfirmPendingLink links the pending provider identity to the signed-in
// account.
// @Summary      Link the sign-in method waiting to be linked
// @Description  Links the provider identity of a pending link to the signed-in account and signs out the account's other sessions. The session must have signed in (or stepped up) after the pending link was made: 403 PENDING_LINK_SIGN_IN_REQUIRED otherwise; requires a recent re-authentication (STEP_UP_REQUIRED). 404 PENDING_LINK_INVALID, 409 IDENTITY_LINKED_ELSEWHERE or PROVIDER_ALREADY_LINKED when it cannot be linked.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        request  body  PendingLinkRequest  true  "Pending link secret"
// @Success      200  {object}  auth.SignInMethod
// @Router       /me/pending-sign-in-link/confirm [post]
func (h *OAuthHandler) ConfirmPendingLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	if userID == "" || sessionID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	token, ok := decodePendingLink(w, r)
	if !ok {
		return
	}
	m, err := h.oauthService.ConfirmPendingLink(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()),
		auth.ConfirmPendingLinkInput{UserID: userID, SessionID: sessionID, Token: token})
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}
	writeIdentityJSON(w, http.StatusOK, m)
}

// CancelPendingLink drops a pending link ("not now").
// @Summary      Decline the sign-in method waiting to be linked
// @Description  Drops the pending link. Always 204.
// @Tags         Account
// @Accept       json
// @Param        request  body  PendingLinkRequest  true  "Pending link secret"
// @Success      204
// @Router       /me/pending-sign-in-link/cancel [post]
func (h *OAuthHandler) CancelPendingLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	token, ok := decodePendingLink(w, r)
	if !ok {
		return
	}
	h.oauthService.CancelPendingLink(r.Context(), userID, token)
	w.WriteHeader(http.StatusNoContent)
}
