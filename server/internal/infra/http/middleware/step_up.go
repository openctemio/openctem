package middleware

// RequireRecentAuth: step-up re-authentication for sensitive routes
// (docs/architecture/step-up-reauth.md).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stepup"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Step-up error codes. The web client answers STEP_UP_REQUIRED with its
// re-authentication dialog and retries the request once.
const (
	// CodeStepUpRequired: the session has not authenticated within the window.
	CodeStepUpRequired = apierror.CodeStepUpRequired
	// CodeStepUpUnavailable: this credential cannot step up (no user session,
	// e.g. an API key, or step-up is not wired).
	CodeStepUpUnavailable = apierror.CodeStepUpUnavailable
)

// ErrNoRecentAuth is what a RecentAuthChecker returns when the session cannot
// be used for step-up (unknown, revoked, expired, or another user's).
var ErrNoRecentAuth = errors.New("no usable session for step-up")

// RecentAuthChecker returns when userID last authenticated (signed in or
// stepped up) in sessionID.
type RecentAuthChecker interface {
	RecentAuthAt(ctx context.Context, userID, sessionID string) (time.Time, error)
}

// Errors CheckRecentAuth returns for a caller that has not re-authenticated
// recently (ErrStepUpRequired) or cannot (ErrStepUpUnavailable).
var (
	ErrStepUpRequired    = errors.New("step-up re-authentication required")
	ErrStepUpUnavailable = errors.New("step-up re-authentication unavailable for this credential")
)

// CheckRecentAuth is the critical-tier decision of the legacy policy (a
// fixed window) for code that has no organization policy to read. Prefer
// CheckStepUp.
func CheckRecentAuth(ctx context.Context, checker RecentAuthChecker, window time.Duration) error {
	return checkRule(ctx, checker, stepup.TierCritical, ruleForWindow(window))
}

// ruleForWindow is a once_per_window rule of an arbitrary length (callers of
// CheckRecentAuth pass the legacy 10-minute window).
func ruleForWindow(window time.Duration) stepRule {
	return stepRule{Rule: stepup.Rule{Mode: stepup.ModeWindow, Window: stepup.Window10m}, window: window}
}

// stepRule is a policy rule with its window length resolved.
type stepRule struct {
	stepup.Rule
	window  time.Duration
	session bool
}

func resolveRule(r stepup.Rule) stepRule {
	d, session := r.Duration()
	return stepRule{Rule: r, window: d, session: session}
}

// StepUpPolicyProvider reads an organization's re-verification policy (the
// effective one: stored, clamped to the platform floor, or the default).
type StepUpPolicyProvider interface {
	StepUpPolicy(ctx context.Context, tenantID string) (stepup.Policy, error)
}

// RecentAuthSpender spends a session's proof for an every_time action: it
// succeeds once per proof, and only for a proof given at or after notBefore.
// The PostgreSQL session repository implements it (through the auth service).
type RecentAuthSpender interface {
	SpendRecentAuth(ctx context.Context, userID, sessionID string, notBefore time.Time) (bool, error)
}

// StepUpRequiredError is ErrStepUpRequired with the rule that asked, so the
// client can say how long the proof will last.
type StepUpRequiredError struct {
	Tier stepup.Tier
	Rule stepup.Rule
}

func (e *StepUpRequiredError) Error() string { return ErrStepUpRequired.Error() }

// Is makes errors.Is(err, ErrStepUpRequired) hold.
func (e *StepUpRequiredError) Is(target error) bool { return target == ErrStepUpRequired }

// policyRule returns the rule of tier in the organization the request acts
// in: the organization of a /tenants/{tenant} URL (its membership checked by
// the tenant middleware), else the organization of the credential. Never a
// value from the request body. A request without an organization, or without
// a provider wired, gets the legacy policy.
func policyRule(ctx context.Context, policies StepUpPolicyProvider, tier stepup.Tier) (stepup.Rule, error) {
	tenantID := GetTenantID(ctx)
	if team := GetTeamID(ctx); !team.IsZero() {
		tenantID = team.String()
	}
	if policies == nil || tenantID == "" {
		return stepup.LegacyPolicy().Rule(tier), nil
	}
	p, err := policies.StepUpPolicy(ctx, tenantID)
	if err != nil {
		return stepup.Rule{}, fmt.Errorf("read the re-verification policy: %w", err)
	}
	return p.Rule(tier), nil
}

// interactiveSession reports whether the caller is a person in a session
// that can re-authenticate (a platform session, or an external OIDC token).
func interactiveSession(ctx context.Context) bool {
	if IsAPIKeyAuthenticated(ctx) {
		return false
	}
	if GetAuthProvider(ctx) == AuthProviderOIDC {
		return true
	}
	return GetUserID(ctx) != "" && GetSessionID(ctx) != ""
}

// CheckStepUp is the decision for an action of tier under the organization's
// policy (docs/architecture/step-up-reauth.md):
//   - routine actions never refuse a credential that cannot re-authenticate
//     (API keys, MCP tokens): the policy is about people in sessions;
//   - critical and sensitive actions stay interactive-only whatever the
//     policy: a credential without a session gets STEP_UP_UNAVAILABLE, even
//     when the tier is off;
//   - off admits a session; once_per_window admits a proof (sign-in or
//     step-up) younger than the window, or any proof of this session for the
//     session window; every_time spends one proof given within
//     stepup.EveryTimeFreshness, once.
//
// The rule that admitted the action is recorded on the request state for the
// audit trail. It fails closed: an unreadable policy or session is an error.
func CheckStepUp(ctx context.Context, checker RecentAuthChecker, policies StepUpPolicyProvider, tier stepup.Tier) error {
	interactive := interactiveSession(ctx)
	if tier == stepup.TierRoutine && !interactive {
		return nil
	}
	rule, err := policyRule(ctx, policies, tier)
	if err != nil {
		return err
	}
	if !interactive {
		return ErrStepUpUnavailable
	}
	return checkRule(ctx, checker, tier, resolveRule(rule))
}

func checkRule(ctx context.Context, checker RecentAuthChecker, tier stepup.Tier, rule stepRule) error {
	if err := evaluateRule(ctx, checker, tier, rule); err != nil {
		return err
	}
	stepup.StateFrom(ctx).Record(stepup.Applied{Tier: tier, Mode: rule.Mode, Window: rule.Window})
	return nil
}

func evaluateRule(ctx context.Context, checker RecentAuthChecker, tier stepup.Tier, rule stepRule) error {
	required := &StepUpRequiredError{Tier: tier, Rule: rule.Rule}
	if rule.Mode == stepup.ModeOff {
		if GetAuthProvider(ctx) != AuthProviderOIDC && (IsAPIKeyAuthenticated(ctx) || GetUserID(ctx) == "" || GetSessionID(ctx) == "") {
			return ErrStepUpUnavailable
		}
		return nil
	}
	// A token from the external OIDC provider has no platform session: its
	// recent authentication is the provider's own, the signature-verified
	// auth_time claim. The client steps up by signing in at the provider
	// again (prompt=login, max_age=0); a token without auth_time cannot step
	// up. Such a proof cannot be spent: every_time asks for one younger than
	// stepup.EveryTimeFreshness.
	if GetAuthProvider(ctx) == AuthProviderOIDC {
		claims := GetClaims(ctx)
		if claims == nil || claims.AuthTime == nil {
			return ErrStepUpUnavailable
		}
		if !proofAdmits(claims.AuthTime.Time, rule) {
			return required
		}
		return nil
	}
	userID, sessionID := GetUserID(ctx), GetSessionID(ctx)
	if checker == nil || IsAPIKeyAuthenticated(ctx) || userID == "" || sessionID == "" {
		return ErrStepUpUnavailable
	}
	if rule.Mode == stepup.ModeEveryTime {
		state := stepup.StateFrom(ctx)
		if state.Spent() {
			return nil
		}
		spender, ok := checker.(RecentAuthSpender)
		if !ok {
			return ErrStepUpUnavailable
		}
		spent, err := spender.SpendRecentAuth(ctx, userID, sessionID, time.Now().Add(-stepup.EveryTimeFreshness))
		if err != nil {
			return err
		}
		if !spent {
			return required
		}
		state.MarkSpent()
		return nil
	}
	at, err := checker.RecentAuthAt(ctx, userID, sessionID)
	if err != nil && !errors.Is(err, ErrNoRecentAuth) {
		return err
	}
	if err != nil || !proofAdmits(at, rule) {
		return required
	}
	return nil
}

// proofAdmits reports whether a proof given at `at` admits a window or
// every_time rule.
func proofAdmits(at time.Time, rule stepRule) bool {
	switch {
	case rule.Mode == stepup.ModeEveryTime:
		return recentEnough(at, stepup.EveryTimeFreshness)
	case rule.session:
		// Any proof of this session; the epoch is the store's "none".
		return at.Unix() > 0 && !at.After(time.Now().Add(time.Minute))
	default:
		return recentEnough(at, rule.window)
	}
}

// recentEnough reports whether at lies within window before now (and not
// more than a minute of clock skew ahead).
func recentEnough(at time.Time, window time.Duration) bool {
	now := time.Now()
	return !at.IsZero() && !at.After(now.Add(time.Minute)) && now.Sub(at) <= window
}

// WriteStepUpError answers ErrStepUpRequired / ErrStepUpUnavailable the way
// RequireRecentAuth does, so the web client's re-authentication dialog
// handles both paths. The details name the tier and its rule when the error
// carries them (window_seconds 0: the proof is spent by this action, or lasts
// the session), and window otherwise. It reports false for any other error.
func WriteStepUpError(w http.ResponseWriter, err error, window time.Duration) bool {
	var req *StepUpRequiredError
	switch {
	case errors.As(err, &req):
		r := resolveRule(req.Rule)
		apierror.New(http.StatusForbidden, CodeStepUpRequired, "Confirm your identity to continue").
			WithDetails(map[string]any{
				"window_seconds": int(r.window.Seconds()),
				"tier":           string(req.Tier),
				"mode":           string(req.Rule.Mode),
				"window":         req.Rule.Window,
			}).WriteJSON(w)
	case errors.Is(err, ErrStepUpRequired):
		apierror.New(http.StatusForbidden, CodeStepUpRequired, "Confirm your identity to continue").
			WithDetails(map[string]int{"window_seconds": int(window.Seconds())}).WriteJSON(w)
	case errors.Is(err, ErrStepUpUnavailable):
		apierror.New(http.StatusForbidden, CodeStepUpUnavailable,
			"This action needs a signed-in user session that can re-authenticate").WriteJSON(w)
	default:
		return false
	}
	return true
}

// RequireStepUp admits a request when CheckStepUp admits the caller for tier
// under the organization's policy; otherwise 403 STEP_UP_REQUIRED or
// STEP_UP_UNAVAILABLE. A lookup error refuses the request (500).
//
// Mount it after authentication and the route's permission check, so a caller
// without the permission is told so before being asked to re-authenticate.
func RequireStepUp(checker RecentAuthChecker, policies StepUpPolicyProvider, tier stepup.Tier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if err := CheckStepUp(ctx, checker, policies, tier); err != nil {
				writeStepUpFailure(ctx, w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeStepUpFailure(ctx context.Context, w http.ResponseWriter, err error) {
	if WriteStepUpError(w, err, 0) {
		return
	}
	if l := logger.FromContext(ctx); l != nil {
		l.Error("step-up check failed", "error", logger.SanitizeError(err))
	}
	apierror.InternalServerError("could not check re-authentication").WriteJSON(w)
}

// RequireRecentAuth admits a request only when the caller's session
// authenticated within window (the legacy fixed-window check of the critical
// tier). Routes use RequireStepUp, which reads the organization's policy.
func RequireRecentAuth(checker RecentAuthChecker, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if err := CheckRecentAuth(ctx, checker, window); err != nil {
				writeStepUpFailure(ctx, w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RecentAuthGate is CheckStepUp for a service that decides whether an
// action needs step-up (granting an administrator or owner role, loosening a
// governance setting). The handler answers its error with WriteStepUpError.
// RequireRecentAuth checks the critical tier; RequireRecentAuthTier another.
type RecentAuthGate struct {
	Checker  RecentAuthChecker
	Policies StepUpPolicyProvider
}

var (
	_ shared.RecentAuthGate = RecentAuthGate{}
	_ stepup.TieredGate     = RecentAuthGate{}
)

// RequireRecentAuth is RequireRecentAuthTier for the critical tier.
func (g RecentAuthGate) RequireRecentAuth(ctx context.Context, actorID string) error {
	return g.RequireRecentAuthTier(ctx, actorID, stepup.TierCritical)
}

// RequireRecentAuthTier returns nil when actorID is not the user making this
// request (a system path, or a grant authorized earlier and applied for
// someone else, such as an invitation accepted by the invitee); otherwise
// CheckStepUp's answer for that user.
func (g RecentAuthGate) RequireRecentAuthTier(ctx context.Context, actorID string, tier stepup.Tier) error {
	if actorID == "" || GetUserID(ctx) != actorID {
		return nil
	}
	return CheckStepUp(ctx, g.Checker, g.Policies, tier)
}
