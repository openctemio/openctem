package handler

// Step-up re-authentication endpoints (docs/architecture/step-up-reauth.md).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Error codes of POST /auth/step-up besides the shared STEP_UP_* codes.
const (
	// CodeStepUpFailed: the code or password is wrong.
	CodeStepUpFailed = "STEP_UP_FAILED"
	// CodeStepUpCodeUsed: the authenticator code is from a time step that was
	// already used; the next code will work.
	CodeStepUpCodeUsed = "STEP_UP_CODE_USED"
)

// stepUpRateLimitAuditGap is how often a rate-limited step-up is recorded per
// user: one row says "this person hit the limit", a row per refused request
// would let a flood fill the audit log.
const stepUpRateLimitAuditGap = time.Minute

// AuditStepUpRateLimit wraps the step-up rate limit so that a request it
// refuses is recorded as auth.step_up_failed with reason rate_limited for the
// signed-in user (at most once per stepUpRateLimitAuditGap per user). It must
// run after the authentication middleware, which names the user.
func (h *LocalAuthHandler) AuditStepUpRateLimit(limit func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	var (
		mu   sync.Mutex
		last = map[string]time.Time{}
	)
	due := func(userID string, now time.Time) bool {
		mu.Lock()
		defer mu.Unlock()
		if at, ok := last[userID]; ok && now.Sub(at) < stepUpRateLimitAuditGap {
			return false
		}
		if len(last) > 4096 {
			for id, at := range last {
				if now.Sub(at) >= stepUpRateLimitAuditGap {
					delete(last, id)
				}
			}
		}
		last[userID] = now
		return true
	}
	return func(next http.Handler) http.Handler {
		// The limit calls inner only for a request it lets through.
		limited := limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if passed, ok := r.Context().Value(stepUpPassedKey{}).(*bool); ok {
				*passed = true
			}
			next.ServeHTTP(w, r)
		}))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			passed := false
			rec := &stepUpStatusRecorder{ResponseWriter: w}
			limited.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), stepUpPassedKey{}, &passed)))
			userID := middleware.GetUserID(r.Context())
			if passed || rec.status != http.StatusTooManyRequests || userID == "" || !due(userID, time.Now()) {
				return
			}
			actx := selfAuditContext(r)
			actx.TenantID = middleware.GetTenantID(r.Context())
			h.authService.AuditStepUpRateLimited(r.Context(), actx, userID)
		})
	}
}

type stepUpPassedKey struct{}

// stepUpStatusRecorder remembers the status passed to WriteHeader. It does not
// wrap Write: the rate limit refuses with an explicit 429 header, and a body
// written without one is an implicit 200, which is not what it looks for.
type stepUpStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *stepUpStatusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

// StepUpRequest is the proof for POST /auth/step-up: totp when the account
// has an authenticator, otherwise password.
type StepUpRequest struct {
	TOTP     string `json:"totp" validate:"omitempty,max=16"`
	Password string `json:"password" validate:"omitempty,max=128"`
}

// StepUpResponse reports the window a successful step-up opened.
type StepUpResponse struct {
	ValidUntil    time.Time `json:"valid_until"`
	WindowSeconds int       `json:"window_seconds"`
}

// GetStepUp reports what the signed-in user must present and whether the
// current session is inside its re-authentication window.
// @Summary      Step-up re-authentication state
// @Description  method is totp (an authenticator code), password, or fresh_sign_in (an SSO account without an authenticator: sign in again). valid_until is set while the session is inside its window.
// @Tags         Authentication
// @Produce      json
// @Success      200  {object}  authapp.StepUpState
// @Failure      401  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /auth/step-up [get]
func (h *LocalAuthHandler) GetStepUp(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	state, err := h.authService.GetStepUpState(r.Context(), userID, middleware.GetSessionID(r.Context()))
	if err != nil {
		h.logger.Error("step-up state", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read re-authentication state").WriteJSON(w)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, state)
}

// StepUp re-authenticates the signed-in user and opens a short window on this
// session in which sensitive actions are accepted.
// @Summary      Step-up re-authentication
// @Description  Verifies a current authenticator code (accounts with two-factor authentication; recovery codes are not accepted) or the password (other local accounts) and lets this session perform sensitive actions for 10 minutes. The window belongs to this session only and is extended only by another successful step-up. Failures count towards the account lockout. SSO accounts without an authenticator get STEP_UP_UNAVAILABLE and sign in again instead.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      StepUpRequest  true  "Authenticator code or password"
// @Success      200  {object}  StepUpResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error  "STEP_UP_FAILED (wrong code or password), STEP_UP_CODE_USED (the code's time step was already used: wait for the next code), STEP_UP_UNAVAILABLE, or a locked account"
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /auth/step-up [post]
func (h *LocalAuthHandler) StepUp(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req StepUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}
	actx := selfAuditContext(r)
	actx.TenantID = middleware.GetTenantID(r.Context())
	until, err := h.authService.StepUp(r.Context(), actx, userID, middleware.GetSessionID(r.Context()),
		authapp.StepUpProof{TOTP: req.TOTP, Password: req.Password})
	switch {
	case err == nil:
		writeNoStoreJSON(w, http.StatusOK, StepUpResponse{ValidUntil: until, WindowSeconds: int(authapp.StepUpWindow.Seconds())})
	case errors.Is(err, authapp.ErrStepUpRequired):
		apierror.BadRequest("Enter your authenticator code or password").WriteJSON(w)
	case errors.Is(err, authapp.ErrStepUpCodeReused):
		apierror.New(http.StatusForbidden, CodeStepUpCodeUsed, "That code was already used. Wait for the next code.").WriteJSON(w)
	case errors.Is(err, authapp.ErrStepUpFailed):
		apierror.New(http.StatusForbidden, CodeStepUpFailed, "Re-authentication failed").WriteJSON(w)
	case errors.Is(err, authapp.ErrAccountLocked):
		apierror.Forbidden("Account is locked due to too many failed attempts").WriteJSON(w)
	case errors.Is(err, authapp.ErrStepUpUnavailable):
		apierror.New(http.StatusForbidden, middleware.CodeStepUpUnavailable,
			"Sign in again to confirm your identity").WriteJSON(w)
	default:
		h.logger.Error("step-up", "error", logger.SanitizeError(err))
		apierror.InternalServerError("re-authentication failed").WriteJSON(w)
	}
}

// RecentAuthChecker is what middleware.RequireRecentAuth asks: when the
// caller last signed in or stepped up in their session.
func (h *LocalAuthHandler) RecentAuthChecker() middleware.RecentAuthChecker {
	return recentAuthChecker{svc: h.authService}
}

type recentAuthChecker struct{ svc *authapp.AuthService }

func (c recentAuthChecker) RecentAuthAt(ctx context.Context, userID, sessionID string) (time.Time, error) {
	at, err := c.svc.RecentAuthAt(ctx, userID, sessionID)
	if errors.Is(err, authapp.ErrStepUpUnavailable) {
		return time.Time{}, middleware.ErrNoRecentAuth
	}
	return at, err
}

// SpendRecentAuth implements middleware.RecentAuthSpender (every_time).
func (c recentAuthChecker) SpendRecentAuth(ctx context.Context, userID, sessionID string, notBefore time.Time) (bool, error) {
	ok, err := c.svc.SpendRecentAuth(ctx, userID, sessionID, notBefore)
	if errors.Is(err, authapp.ErrStepUpUnavailable) {
		return false, nil
	}
	return ok, err
}

// OwnSignInChecker is what middleware.RequireOwnSignIn asks: whether an
// action on the account itself needs the account's own sign-in.
func (h *LocalAuthHandler) OwnSignInChecker() middleware.OwnSignInChecker {
	return h.authService
}

// CredentialFactorChecker is what middleware.RequireCredentialFactor asks:
// whether the caller holds the second factor the organization or the
// platform floor requires before they create a credential.
func (h *LocalAuthHandler) CredentialFactorChecker() middleware.CredentialFactorChecker {
	return credentialFactorChecker{svc: h.authService}
}

type credentialFactorChecker struct{ svc *authapp.AuthService }

func (c credentialFactorChecker) CheckCredentialFactor(ctx context.Context, userID, tenantID, sessionID string) error {
	err := c.svc.CheckCredentialFactor(ctx, userID, tenantID, sessionID)
	switch {
	case errors.Is(err, authapp.ErrSSOMFAEvidenceRequired):
		return middleware.ErrCredentialProofRequired
	case errors.Is(err, authapp.ErrMFAEnrollmentRequired):
		return middleware.ErrCredentialFactorRequired
	}
	return err
}
