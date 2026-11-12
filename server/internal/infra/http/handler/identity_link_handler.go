package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// Account > Security, "Connected sign-in methods": the signed-in person links
// and unlinks Google, GitHub and Microsoft sign-in on their own account
// (auth/identity_link.go). The account is always the session's; no request
// field names an account.

// LinkProofRequest is the proof typed in the confirm dialog of a link or an
// unlink: the authenticator code when the account has two-factor
// authentication, else the password (auth/link_proof.go).
type LinkProofRequest struct {
	StepUp auth.StepUpProof `json:"step_up"`
}

// LinkStartRequest starts linking a provider.
type LinkStartRequest struct {
	RedirectURI string `json:"redirect_uri"`
	LinkProofRequest
}

// decodeLinkProof reads an optional LinkProofRequest body (an empty body is
// no proof: the service answers LINK_PROOF_REQUIRED).
func decodeLinkProof(w http.ResponseWriter, r *http.Request) (auth.StepUpProof, bool) {
	var req LinkProofRequest
	if r.Body == nil || r.ContentLength == 0 {
		return auth.StepUpProof{}, true
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return auth.StepUpProof{}, false
	}
	return req.StepUp, true
}

// keepsPendingLink reports whether a refused confirmation may be retried with
// the same pending link (the proof was missing or mistyped).
func keepsPendingLink(err error) bool {
	return errors.Is(err, auth.ErrLinkProofRequired) || errors.Is(err, auth.ErrLinkProofFailed)
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
// signed-in account. Needs the proof typed in the confirm dialog.
// @Summary      Start linking a sign-in provider
// @Description  Returns the authorization URL of the provider. The state is bound to this account and this session and is accepted only by the link callback, once, within the state lifetime. browser_binding is a one-time secret for the browser that started the link: keep it in an HttpOnly cookie and send it back with the link callback. step_up must carry the authenticator code (two-factor accounts; never a recovery code) or else the password, typed for this request; a recent sign-in does not count. 403 LINK_PROOF_REQUIRED, LINK_PROOF_FAILED (counts towards the lockout), LINK_PROOF_UNAVAILABLE (no two-factor and no password), ACCOUNT_LOCKED.
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
	res, err := h.oauthService.StartLink(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()), auth.LinkStartInput{
		UserID: userID, SessionID: sessionID,
		Provider: auth.OAuthProvider(r.PathValue("provider")), RedirectURI: req.RedirectURI,
		Proof: req.StepUp,
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

// Unlink removes a linked sign-in identity from the signed-in account. Needs
// the proof typed in the confirm dialog. The last sign-in method is never
// removed.
// @Summary      Unlink a sign-in provider
// @Description  Removes one linked Google, GitHub or Microsoft identity of the signed-in account. 409 LAST_SIGN_IN_METHOD when it is the account's only way to sign in. step_up must carry the authenticator code (never a recovery code) or else the password, typed for this request: 403 LINK_PROOF_REQUIRED, LINK_PROOF_FAILED, LINK_PROOF_UNAVAILABLE, ACCOUNT_LOCKED.
// @Tags         Account
// @Accept       json
// @Param        id       path  string            true  "Identity id"
// @Param        request  body  LinkProofRequest  true  "Proof typed in the confirm dialog"
// @Success      204
// @Router       /me/sign-in-methods/{id} [delete]
func (h *OAuthHandler) Unlink(w http.ResponseWriter, r *http.Request) {
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
	err := h.oauthService.Unlink(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()), auth.UnlinkInput{
		UserID: userID, SessionID: sessionID, IdentityID: r.PathValue("id"), Proof: proof,
	})
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
// pending link. The secret itself is only in the HttpOnly pending-link cookie.
type PendingLinkDetails struct {
	LinkPending bool   `json:"link_pending"`
	Provider    string `json:"provider"`
}

// Pending-link cookie: HttpOnly, SameSite=Lax, Path=/, 10 minutes. With
// Secure cookies it carries the __Host- prefix, so no subdomain can set it.
const (
	pendingLinkCookieSecure = "__Host-oauth_pending_link"
	pendingLinkCookiePlain  = "oauth_pending_link"
)

func (h *OAuthHandler) pendingLinkCookieName() string {
	if h.authConfig.CookieSecure {
		return pendingLinkCookieSecure
	}
	return pendingLinkCookiePlain
}

func (h *OAuthHandler) setPendingLinkCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.pendingLinkCookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *OAuthHandler) clearPendingLinkCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: h.pendingLinkCookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: h.authConfig.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// pendingLinkToken reads the pending-link secret from its cookie only: it is
// never accepted from the body or the URL.
func (h *OAuthHandler) pendingLinkToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := r.Cookie(h.pendingLinkCookieName())
	if err != nil || c.Value == "" {
		// No cookie: a malformed request (400), with the same code as an
		// unknown pending link.
		apierror.New(http.StatusBadRequest, codePendingLinkInvalid, "There is no sign-in method waiting to be linked to this account.").WriteJSON(w)
		return "", false
	}
	return c.Value, true
}

// DescribePendingLink tells the signed-in account which provider account is
// waiting to be linked to it.
// @Summary      Describe the sign-in method waiting to be linked
// @Description  A social sign-in refused with OAUTH_ACCOUNT_EXISTS leaves a pending link (details.link_pending; the secret is in the HttpOnly pending-link cookie, read from the cookie only). After signing in to that account, this returns the provider and its address. 404 PENDING_LINK_INVALID when there is none for this account (expired, used, or made for another account, which also spends it).
// @Tags         Account
// @Produce      json
// @Success      200  {object}  auth.PendingLinkInfo
// @Router       /me/pending-sign-in-link/describe [post]
func (h *OAuthHandler) DescribePendingLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	token, ok := h.pendingLinkToken(w, r)
	if !ok {
		return
	}
	info, err := h.oauthService.DescribePendingLink(r.Context(), userID, token)
	if err != nil {
		h.clearPendingLinkCookie(w)
		h.handleOAuthError(w, err)
		return
	}
	writeIdentityJSON(w, http.StatusOK, info)
}

// ConfirmPendingLink links the pending provider identity to the signed-in
// account.
// @Summary      Link the sign-in method waiting to be linked
// @Description  Links the provider identity of a pending link to the signed-in account and signs out the account's other sessions. step_up must carry the authenticator code (never a recovery code) or else the password, typed for this request; the sign-in that just happened does not count: 403 LINK_PROOF_REQUIRED or LINK_PROOF_FAILED (the pending link stays for another try), LINK_PROOF_UNAVAILABLE, ACCOUNT_LOCKED. The session must have signed in (or stepped up) after the pending link was made: 403 PENDING_LINK_SIGN_IN_REQUIRED otherwise. 404 PENDING_LINK_INVALID, 409 IDENTITY_LINKED_ELSEWHERE or PROVIDER_ALREADY_LINKED when it cannot be linked.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        request  body  LinkProofRequest  true  "Proof typed in the confirm dialog"
// @Success      200  {object}  auth.SignInMethod
// @Router       /me/pending-sign-in-link/complete [post]
func (h *OAuthHandler) ConfirmPendingLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	if userID == "" || sessionID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	token, ok := h.pendingLinkToken(w, r)
	if !ok {
		return
	}
	proof, ok := decodeLinkProof(w, r)
	if !ok {
		return
	}
	m, err := h.oauthService.ConfirmPendingLink(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()),
		auth.ConfirmPendingLinkInput{UserID: userID, SessionID: sessionID, Token: token, Proof: proof})
	if !keepsPendingLink(err) {
		h.clearPendingLinkCookie(w)
	}
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}
	writeIdentityJSON(w, http.StatusOK, m)
}

// CancelPendingLink drops a pending link ("not now").
// @Summary      Decline the sign-in method waiting to be linked
// @Description  Drops the pending link of the pending-link cookie and clears the cookie. Always 204.
// @Tags         Account
// @Success      204
// @Router       /me/pending-sign-in-link/cancel [post]
func (h *OAuthHandler) CancelPendingLink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	if c, err := r.Cookie(h.pendingLinkCookieName()); err == nil && c.Value != "" {
		h.oauthService.CancelPendingLink(r.Context(), userID, c.Value)
	}
	h.clearPendingLinkCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
