package handler

// Console WebAuthn: sign-in with a security key or passkey, recovery codes,
// WebAuthn step-up, authenticator management and the "require WebAuthn"
// policy (docs/rfcs/RFC-078-passkeys-and-security-notices.md).

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Error codes the console acts on.
const (
	codeWebAuthnRequired    apierror.Code = "WEBAUTHN_REQUIRED"
	codeWebAuthnUnavailable apierror.Code = "WEBAUTHN_UNAVAILABLE"
	codePolicyNotCompliant  apierror.Code = "MFA_POLICY_ACTOR_NOT_COMPLIANT"
	codeKeepAuthenticators  apierror.Code = "WEBAUTHN_KEEP_REQUIRED"
)

// maxWebAuthnBody bounds an attestation or assertion response.
const maxWebAuthnBody = 64 << 10

// AdminRecoveryLoginRequest is the recovery-code sign-in step.
type AdminRecoveryLoginRequest struct {
	Code string `json:"code"`
}

// AdminWebAuthnRegisterRequest completes an authenticator registration.
type AdminWebAuthnRegisterRequest struct {
	Name string `json:"name"`
	// Credential is the browser's PublicKeyCredential (toJSON()).
	Credential json.RawMessage `json:"credential" swaggertype:"object"`
}

// AdminWebAuthnRenameRequest relabels an authenticator.
type AdminWebAuthnRenameRequest struct {
	Name string `json:"name"`
}

// AdminWebAuthnCredentialResponse describes one authenticator (no key material).
type AdminWebAuthnCredentialResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	AAGUID      string     `json:"aaguid,omitempty"`
	Transports  []string   `json:"transports"`
	Attachment  string     `json:"attachment,omitempty"`
	Synced      bool       `json:"synced"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	SyncCapable bool       `json:"sync_capable"`
}

// AdminFactorsResponse is the signed-in administrator's console factors.
type AdminFactorsResponse struct {
	WebAuthnEnabled   bool                              `json:"webauthn_enabled"`
	Authenticators    []AdminWebAuthnCredentialResponse `json:"authenticators"`
	RecoveryCodesLeft int                               `json:"recovery_codes_left"`
	TOTPEnabled       bool                              `json:"totp_enabled"`
	TOTPAllowed       bool                              `json:"totp_allowed"`
	RequireWebAuthn   bool                              `json:"require_webauthn"`
	// WebAuthnGraceUntil is when TOTP stops working for an administrator
	// without a security key (policy on); the console shows it.
	WebAuthnGraceUntil *time.Time `json:"webauthn_grace_until,omitempty"`
	EnrollmentRequired bool       `json:"enrollment_required"`
	MinAuthenticators  int        `json:"min_authenticators"`
	MaxAuthenticators  int        `json:"max_authenticators"`
}

// AdminRecoveryCodesResponse returns new recovery codes once.
type AdminRecoveryCodesResponse struct {
	Codes []string `json:"codes"`
}

// AdminMFAPolicyResponse is the console MFA policy.
type AdminMFAPolicyResponse struct {
	RequireWebAuthn bool `json:"require_webauthn"`
	// GraceUntil: administrators without a security key may use TOTP until
	// then (set when the policy is switched on).
	GraceUntil      *time.Time `json:"grace_until,omitempty"`
	Version         int        `json:"version"`
	WebAuthnEnabled bool       `json:"webauthn_enabled"`
}

// AdminMFAPolicyRequest changes the console MFA policy.
type AdminMFAPolicyRequest struct {
	RequireWebAuthn bool `json:"require_webauthn"`
	// Version is the policy version read (0: never stored).
	Version int `json:"version"`
}

func readWebAuthnBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebAuthnBody))
	if err != nil || len(body) == 0 {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return nil, false
	}
	return body, true
}

func pendingToken(r *http.Request) string {
	if c, err := r.Cookie(middleware.AdminMFACookie); err == nil {
		return c.Value
	}
	return ""
}

// writeFactorError maps the factor errors; it reports whether it wrote one.
func (h *AdminConsoleHandler) writeFactorError(w http.ResponseWriter, err error, op string) {
	switch {
	case errors.Is(err, admin.ErrWebAuthnUnavailable):
		apierror.New(http.StatusForbidden, codeWebAuthnUnavailable,
			"Security keys are not available for this account or this console").WriteJSON(w)
	case errors.Is(err, admin.ErrInvalidAssertion), errors.Is(err, admin.ErrInvalidMFACode):
		apierror.Unauthorized("The security key response was not accepted; try again").WriteJSON(w)
	case errors.Is(err, admin.ErrInvalidRecoveryCode):
		apierror.Unauthorized("Invalid or already used recovery code").WriteJSON(w)
	case errors.Is(err, admin.ErrIdPSignInRequired):
		apierror.New(http.StatusForbidden, codeIdPSignInRequired,
			"Sign in to the admin console with the identity provider").WriteJSON(w)
	case errors.Is(err, admin.ErrWebAuthnRequired):
		apierror.New(http.StatusForbidden, codeWebAuthnRequired,
			"Use your security key or passkey").WriteJSON(w)
	case errors.Is(err, admin.ErrStepUpRequired), errors.Is(err, admin.ErrSessionNotFound):
		apierror.Unauthorized("administrator session required").WriteJSON(w)
	case errors.Is(err, admin.ErrWebAuthnCredentialExists):
		apierror.Conflict("This security key is already registered").WriteJSON(w)
	case errors.Is(err, admin.ErrTooManyWebAuthnCredentials):
		apierror.BadRequest("You have the maximum number of security keys; remove one first").WriteJSON(w)
	case errors.Is(err, admin.ErrLastWebAuthnCredential):
		apierror.New(http.StatusConflict, codeKeepAuthenticators,
			"The console requires security keys: register a replacement before removing this one").WriteJSON(w)
	case errors.Is(err, admin.ErrWebAuthnCredentialNotFound):
		apierror.NotFound("security key").WriteJSON(w)
	case errors.Is(err, admin.ErrPolicyActorNotCompliant):
		apierror.New(http.StatusConflict, codePolicyNotCompliant,
			"Register at least two security keys and recovery codes before requiring them").WriteJSON(w)
	case errors.Is(err, admin.ErrConsoleMFAPolicyConflict):
		apierror.Conflict("The policy changed since you read it; reload and try again").WriteJSON(w)
	case shared.IsValidation(err):
		apierror.BadRequest(sanitizeLogField(err.Error())).WriteJSON(w)
	default:
		h.logger.Error("console factor", "op", op, "error", err)
		apierror.InternalServerError("could not complete the request").WriteJSON(w)
	}
}

// WebAuthnLoginOptions handles POST /api/v1/admin/auth/webauthn/session/options.
// @Summary Security key sign-in: request
// @Description Returns the WebAuthn assertion request for the pending console sign-in (admin_mfa cookie); only the administrator's own authenticators are allowed.
// @Tags Admin Auth
// @Produce json
// @Success 200 {object} object "PublicKeyCredentialRequestOptions under publicKey"
// @Failure 401 {object} apierror.Error "No pending sign-in"
// @Failure 403 {object} apierror.Error "No security key registered"
// @Router /admin/auth/webauthn/session/options [post]
func (h *AdminConsoleHandler) WebAuthnLoginOptions(w http.ResponseWriter, r *http.Request) {
	opts, err := h.svc.BeginWebAuthnLogin(r.Context(), pendingToken(r))
	if err != nil {
		h.writeFactorError(w, err, "login options")
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// WebAuthnLogin handles POST /api/v1/admin/auth/webauthn/session.
// @Summary Security key sign-in: answer
// @Description Verifies the assertion for the pending console sign-in and issues the admin_session and admin_csrf cookies. A refused assertion counts toward the account lockout.
// @Tags Admin Auth
// @Accept json
// @Produce json
// @Param request body object true "PublicKeyCredential (toJSON)"
// @Success 200 {object} ValidateResponse
// @Failure 401 {object} apierror.Error "Not accepted"
// @Router /admin/auth/webauthn/session [post]
func (h *AdminConsoleHandler) WebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	token, a, err := h.svc.FinishWebAuthnLogin(r.Context(), pendingToken(r), body, clientInfo(r))
	if err != nil {
		h.writeFactorError(w, err, "login")
		return
	}
	h.writeSignedIn(w, token, a)
}

// RecoveryLogin handles POST /api/v1/admin/auth/recovery.
// @Summary Recovery code sign-in
// @Description Completes the pending console sign-in with a one-time recovery code. A wrong code counts toward the account lockout.
// @Tags Admin Auth
// @Accept json
// @Produce json
// @Param request body AdminRecoveryLoginRequest true "Recovery code"
// @Success 200 {object} ValidateResponse
// @Failure 401 {object} apierror.Error "Invalid or used code"
// @Router /admin/auth/recovery [post]
func (h *AdminConsoleHandler) RecoveryLogin(w http.ResponseWriter, r *http.Request) {
	var req AdminRecoveryLoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.Code == "" {
		apierror.BadRequest("code is required").WriteJSON(w)
		return
	}
	token, a, err := h.svc.RecoveryLogin(r.Context(), pendingToken(r), req.Code, clientInfo(r))
	if err != nil {
		h.writeFactorError(w, err, "recovery login")
		return
	}
	h.writeSignedIn(w, token, a)
}

// Factors handles GET /api/v1/admin/auth/factors.
// @Summary My console factors
// @Description The signed-in administrator's security keys (no key material), recovery codes left, TOTP state and the console MFA policy.
// @Tags Admin Auth
// @Produce json
// @Success 200 {object} AdminFactorsResponse
// @Router /admin/auth/factors [get]
func (h *AdminConsoleHandler) Factors(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	st, err := h.svc.FactorStatus(r.Context(), a)
	if err != nil {
		h.writeFactorError(w, err, "factors")
		return
	}
	resp := AdminFactorsResponse{
		WebAuthnEnabled:    h.svc.WebAuthnEnabled(),
		Authenticators:     []AdminWebAuthnCredentialResponse{},
		RecoveryCodesLeft:  st.RecoveryCodesLeft,
		TOTPEnabled:        st.TOTPEnabled,
		TOTPAllowed:        st.TOTPAllowed(),
		RequireWebAuthn:    st.PolicyRequires,
		WebAuthnGraceUntil: st.GraceUntil,
		EnrollmentRequired: st.EnrollmentRequired(),
		MinAuthenticators:  admin.MinWebAuthnCredentialsRequired,
		MaxAuthenticators:  admin.MaxWebAuthnCredentials,
	}
	if h.svc.WebAuthnEnabled() {
		creds, err := h.svc.ListWebAuthn(r.Context(), a)
		if err != nil {
			h.writeFactorError(w, err, "list authenticators")
			return
		}
		for _, c := range creds {
			resp.Authenticators = append(resp.Authenticators, toWebAuthnResponse(c))
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func toWebAuthnResponse(c *admin.WebAuthnCredential) AdminWebAuthnCredentialResponse {
	out := AdminWebAuthnCredentialResponse{
		ID: c.ID.String(), Name: c.Name, Transports: c.Transports, Attachment: c.Attachment,
		Synced: c.BackupState, SyncCapable: c.BackupEligible, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt,
	}
	if out.Transports == nil {
		out.Transports = []string{}
	}
	if len(c.AAGUID) == 16 {
		if id, err := uuid.FromBytes(c.AAGUID); err == nil && id != uuid.Nil {
			out.AAGUID = id.String()
		}
	}
	return out
}

// WebAuthnRegisterOptions handles POST /api/v1/admin/auth/webauthn/credentials/options.
// @Summary Register a security key: request
// @Description Returns the WebAuthn creation request for a new authenticator of the signed-in administrator (route-level step-up). The relying party is the console origin.
// @Tags Admin Auth
// @Produce json
// @Success 200 {object} object "PublicKeyCredentialCreationOptions under publicKey"
// @Failure 401 {object} apierror.Error "Step-up required"
// @Router /admin/auth/webauthn/credentials/options [post]
func (h *AdminConsoleHandler) WebAuthnRegisterOptions(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	opts, err := h.svc.BeginWebAuthnRegistration(r.Context(), a, middleware.GetAdminSession(r.Context()))
	if err != nil {
		h.writeFactorError(w, err, "register options")
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// WebAuthnRegister handles POST /api/v1/admin/auth/webauthn/credentials.
// @Summary Register a security key: answer
// @Description Verifies the attestation response of the ceremony the options call opened in this session and stores the authenticator (public key only). User verification is required; attestation is not requested.
// @Tags Admin Auth
// @Accept json
// @Produce json
// @Param request body AdminWebAuthnRegisterRequest true "Name and credential"
// @Success 201 {object} AdminWebAuthnCredentialResponse
// @Failure 401 {object} apierror.Error "Not accepted"
// @Router /admin/auth/webauthn/credentials [post]
func (h *AdminConsoleHandler) WebAuthnRegister(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	var req AdminWebAuthnRegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWebAuthnBody)).Decode(&req); err != nil || len(req.Credential) == 0 {
		apierror.BadRequest("name and credential are required").WriteJSON(w)
		return
	}
	c, err := h.svc.FinishWebAuthnRegistration(r.Context(), a, middleware.GetAdminSession(r.Context()), req.Name, req.Credential, clientInfo(r))
	if err != nil {
		h.writeFactorError(w, err, "register")
		return
	}
	writeJSON(w, http.StatusCreated, toWebAuthnResponse(c))
}

// WebAuthnRename handles PATCH /api/v1/admin/auth/webauthn/credentials/{id}.
// @Summary Rename a security key
// @Tags Admin Auth
// @Accept json
// @Param id path string true "Authenticator id"
// @Param request body AdminWebAuthnRenameRequest true "New name"
// @Success 204 "No Content"
// @Failure 404 {object} apierror.Error "Not one of yours"
// @Router /admin/auth/webauthn/credentials/{id} [patch]
func (h *AdminConsoleHandler) WebAuthnRename(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("security key").WriteJSON(w)
		return
	}
	var req AdminWebAuthnRenameRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.svc.RenameWebAuthn(r.Context(), a, id, req.Name, clientInfo(r)); err != nil {
		h.writeFactorError(w, err, "rename")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// WebAuthnRemove handles DELETE /api/v1/admin/auth/webauthn/credentials/{id}.
// @Summary Remove a security key
// @Description Removes one of the signed-in administrator's authenticators (route-level step-up). While the console requires security keys, the last two are kept.
// @Tags Admin Auth
// @Param id path string true "Authenticator id"
// @Success 204 "No Content"
// @Failure 404 {object} apierror.Error "Not one of yours"
// @Failure 409 {object} apierror.Error "Would drop below the required number"
// @Router /admin/auth/webauthn/credentials/{id} [delete]
func (h *AdminConsoleHandler) WebAuthnRemove(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("security key").WriteJSON(w)
		return
	}
	if err := h.svc.RemoveWebAuthn(r.Context(), a, id, clientInfo(r)); err != nil {
		h.writeFactorError(w, err, "remove")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GenerateRecoveryCodes handles POST /api/v1/admin/auth/recovery-codes.
// @Summary New recovery codes
// @Description Replaces the signed-in administrator's recovery codes with ten new one-time codes, shown once (route-level step-up).
// @Tags Admin Auth
// @Produce json
// @Success 200 {object} AdminRecoveryCodesResponse
// @Router /admin/auth/recovery-codes [post]
func (h *AdminConsoleHandler) GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	codes, err := h.svc.GenerateRecoveryCodes(r.Context(), a, clientInfo(r))
	if err != nil {
		h.writeFactorError(w, err, "recovery codes")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, AdminRecoveryCodesResponse{Codes: codes})
}

// WebAuthnStepUpOptions handles POST /api/v1/admin/auth/step-up/webauthn/options.
// @Summary Confirm with a security key: request
// @Description Returns an assertion request that, once answered, confirms protected actions of this console session for five minutes.
// @Tags Admin Auth
// @Produce json
// @Success 200 {object} object "PublicKeyCredentialRequestOptions under publicKey"
// @Router /admin/auth/step-up/webauthn/options [post]
func (h *AdminConsoleHandler) WebAuthnStepUpOptions(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	opts, err := h.svc.BeginWebAuthnStepUp(r.Context(), a, middleware.GetAdminSession(r.Context()))
	if err != nil {
		h.writeFactorError(w, err, "step-up options")
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// WebAuthnStepUp handles POST /api/v1/admin/auth/step-up/webauthn.
// @Summary Confirm with a security key: answer
// @Description Verifies the assertion and opens this session's five-minute step-up window; retry the protected action without a code. A refused assertion counts toward the lockout.
// @Tags Admin Auth
// @Accept json
// @Param request body object true "PublicKeyCredential (toJSON)"
// @Success 204 "No Content"
// @Failure 401 {object} apierror.Error "Not accepted"
// @Router /admin/auth/step-up/webauthn [post]
func (h *AdminConsoleHandler) WebAuthnStepUp(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	if err := h.svc.FinishWebAuthnStepUp(r.Context(), a, middleware.GetAdminSession(r.Context()), body, clientInfo(r)); err != nil {
		h.writeFactorError(w, err, "step-up")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetMFAPolicy handles GET /api/v1/admin/settings/console-mfa.
// @Summary Console MFA policy
// @Tags Admin Settings
// @Produce json
// @Success 200 {object} AdminMFAPolicyResponse
// @Router /admin/settings/console-mfa [get]
func (h *AdminConsoleHandler) GetMFAPolicy(w http.ResponseWriter, r *http.Request) {
	p, v, err := h.svc.MFAPolicy(r.Context())
	if err != nil {
		h.writeFactorError(w, err, "read policy")
		return
	}
	writeJSON(w, http.StatusOK, AdminMFAPolicyResponse{RequireWebAuthn: p.RequireWebAuthn, GraceUntil: p.GraceUntil, Version: v, WebAuthnEnabled: h.svc.WebAuthnEnabled()})
}

// PutMFAPolicy handles PUT /api/v1/admin/settings/console-mfa (super admin, step-up).
// @Summary Change the console MFA policy
// @Description Turns "require security keys" on or off. Turning it on needs WebAuthn configured (ADMIN_PUBLIC_URL) and an actor with at least two security keys and recovery codes; other administrators are held on the enrollment page until they comply.
// @Tags Admin Settings
// @Accept json
// @Produce json
// @Param request body AdminMFAPolicyRequest true "Policy"
// @Success 200 {object} AdminMFAPolicyResponse
// @Failure 409 {object} apierror.Error "Actor not compliant, or a concurrent change"
// @Router /admin/settings/console-mfa [put]
func (h *AdminConsoleHandler) PutMFAPolicy(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	var req AdminMFAPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.Version < 0 {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	// Turning "require security keys" off needs a second super admin.
	var grant *adminapproval.Grant
	if !req.RequireWebAuthn {
		cur, _, err := h.svc.MFAPolicy(r.Context())
		if err != nil {
			h.writeFactorError(w, err, "read policy")
			return
		}
		if cur.RequireWebAuthn {
			var ok bool
			if grant, ok = requireSecondApproval(w, r, h.approvals, a, admin.ApprovalConsoleMFAOff, "off", h.logger); !ok {
				return
			}
		}
	}
	v, err := h.svc.SetMFAPolicy(r.Context(), a, admin.ConsoleMFAPolicy{RequireWebAuthn: req.RequireWebAuthn}, req.Version, clientInfo(r))
	if err != nil {
		releaseSecondApproval(r, h.approvals, a, grant)
		h.writeFactorError(w, err, "set policy")
		return
	}
	stored, _, _ := h.svc.MFAPolicy(r.Context())
	writeJSON(w, http.StatusOK, AdminMFAPolicyResponse{RequireWebAuthn: req.RequireWebAuthn, GraceUntil: stored.GraceUntil, Version: v, WebAuthnEnabled: h.svc.WebAuthnEnabled()})
}

// writeSignedIn finishes a second-factor sign-in: it sets the session and CSRF
// cookies and returns the CSRF token in the body, as the password sign-in
// does, so the console keeps it in memory.
func (h *AdminConsoleHandler) writeSignedIn(w http.ResponseWriter, token string, a *admin.AdminUser) {
	csrf, err := h.issueSessionCookies(w, token)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, ValidateResponse{
		ID: a.ID().String(), Email: a.Email(), Name: a.Name(), Role: string(a.Role()), IsBreakGlass: a.IsBreakGlass(),
		CSRFToken: csrf,
	})
}
