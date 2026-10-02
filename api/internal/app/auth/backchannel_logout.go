package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	sessiondom "github.com/openctemio/api/pkg/domain/session"
)

// backchannelLogoutEvent is the OIDC Back-Channel Logout 1.0 event identifier
// the logout_token's `events` claim MUST contain (with an empty-object value).
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// logoutTokenMaxAge bounds how old a logout_token's `iat` may be. Back-channel
// logout tokens are delivered promptly server-to-server, so a stale token is
// treated as a replay and rejected.
const logoutTokenMaxAge = 5 * time.Minute

// logoutTokenFutureLeeway tolerates minor clock skew on `iat`.
const logoutTokenFutureLeeway = 2 * time.Minute

// ErrLogoutTokenInvalid is the single generic error returned for ANY logout_token
// validation failure. The endpoint maps it to a 400 with no detail so a caller
// cannot probe which check failed (and thus cannot learn which sids/issuers exist).
var ErrLogoutTokenInvalid = errors.New("invalid logout_token")

// logoutTokenClaims are the claims read from an OIDC Back-Channel Logout
// logout_token. Nonce is a pointer so we can distinguish "absent" (nil, required)
// from "present" (non-nil, which the spec forbids and we reject).
type logoutTokenClaims struct {
	Events map[string]json.RawMessage `json:"events"`
	SID    string                     `json:"sid"`
	Nonce  *string                    `json:"nonce"`
	jwtv5.RegisteredClaims
}

// idpSessionFinder is the optional capability a session repository exposes to
// locate federated sessions by their IdP binding. The postgres repository
// implements it; the SSO service type-asserts so the domain Repository interface
// (and its many test doubles) stays unchanged.
type idpSessionFinder interface {
	GetActiveByIDPSID(ctx context.Context, issuer, sid string) ([]*sessiondom.Session, error)
	GetActiveByIDPSub(ctx context.Context, issuer, sub string) ([]*sessiondom.Session, error)
}

// logoutIssuerResolution is the verified binding of a logout_token's `iss` to the
// configured provider(s): the JWKS to verify the signature against and the set of
// client_ids that are acceptable audiences for that issuer.
type logoutIssuerResolution struct {
	jwksURL          string
	allowedClientIDs []string
}

// BackChannelLogout validates an OIDC Back-Channel Logout 1.0 logout_token and
// revokes the session(s) it targets. It is the security-critical entry point: a
// forged token must NEVER revoke a session. Validation order (all fail-closed):
//
//  1. Read `iss` WITHOUT trusting the token.
//  2. Resolve `iss` to a configured provider → its JWKS + acceptable client_ids.
//     No configured provider for this issuer ⇒ reject (nothing to revoke).
//  3. Verify the RS256 signature against that provider's JWKS, and that `aud`
//     equals one of the provider's client_ids.
//  4. Enforce logout-token claim rules: `iss` matches, NO `nonce`, `events`
//     contains the back-channel-logout member, `sid` and/or `sub` present,
//     `iat` present + recent, `exp` (if present) validated by the parser.
//  5. Revoke matching sessions — issuer-scoped, so a token from provider X can
//     only revoke sessions bound to X's issuer (no cross-provider revocation).
//
// Returns the number of sessions revoked (0 is a success — an unknown sid must
// not leak via the response). Any validation failure returns ErrLogoutTokenInvalid.
func (s *SSOService) BackChannelLogout(ctx context.Context, logoutToken string) (int, error) {
	logoutToken = strings.TrimSpace(logoutToken)
	if logoutToken == "" {
		return 0, ErrLogoutTokenInvalid
	}

	// 1. Untrusted issuer read (used only to select the provider/JWKS).
	iss, err := unverifiedIssuer(logoutToken)
	if err != nil || iss == "" {
		return 0, ErrLogoutTokenInvalid
	}

	// 2. Resolve issuer → provider JWKS + acceptable audiences.
	res, err := s.resolveLogoutIssuer(ctx, iss)
	if err != nil {
		s.logger.Warn("back-channel logout: no configured provider for issuer", "issuer", iss)
		return 0, ErrLogoutTokenInvalid
	}

	// 3. Verify signature (provider JWKS) + audience.
	claims, err := s.verifyLogoutToken(ctx, logoutToken, res)
	if err != nil {
		s.logger.Warn("back-channel logout: token verification failed", "issuer", iss, "error", err)
		return 0, ErrLogoutTokenInvalid
	}

	// 4. Logout-token-specific claim rules.
	if err := validateLogoutClaims(claims, iss); err != nil {
		s.logger.Warn("back-channel logout: claim validation failed", "issuer", iss, "error", err)
		return 0, ErrLogoutTokenInvalid
	}

	// 5. Revoke matching sessions (issuer-scoped).
	finder, ok := s.sessionRepo.(idpSessionFinder)
	if !ok {
		// Wiring error, not attacker-controllable — surface as a 400 (generic) but
		// log loudly so it is caught in staging.
		s.logger.Error("back-channel logout: session repository lacks idp lookup capability")
		return 0, ErrLogoutTokenInvalid
	}

	var targets []*sessiondom.Session
	if claims.SID != "" {
		// A sid identifies one specific IdP session → revoke exactly that session.
		targets, err = finder.GetActiveByIDPSID(ctx, iss, claims.SID)
	} else {
		// Sub-only logout → revoke every active session for this user at this issuer.
		targets, err = finder.GetActiveByIDPSub(ctx, iss, claims.Subject)
	}
	if err != nil {
		return 0, err
	}

	revoked := 0
	for _, sess := range targets {
		if rerr := sess.Revoke(); rerr != nil {
			continue // already revoked — idempotent
		}
		if uerr := s.sessionRepo.Update(ctx, sess); uerr != nil {
			s.logger.Error("back-channel logout: failed to revoke session", "session_id", sess.ID().String(), "error", uerr)
			continue
		}
		if terr := s.refreshTokenRepo.RevokeBySessionID(ctx, sess.ID()); terr != nil {
			s.logger.Error("back-channel logout: failed to revoke refresh tokens", "session_id", sess.ID().String(), "error", terr)
		}
		revoked++
	}

	s.logger.Info("back-channel logout processed", "issuer", iss, "revoked_sessions", revoked)
	return revoked, nil
}

// unverifiedIssuer extracts the `iss` claim WITHOUT verifying the signature. It
// is safe because the value is used only to SELECT which provider's JWKS to then
// verify against — the token is never trusted until the signature check passes.
func unverifiedIssuer(token string) (string, error) {
	parser := jwtv5.NewParser()
	var claims jwtv5.RegisteredClaims
	if _, _, err := parser.ParseUnverified(token, &claims); err != nil {
		return "", err
	}
	return claims.Issuer, nil
}

// verifyLogoutToken checks the RS256 signature against the resolved provider's
// JWKS and that the audience is one of the provider's client_ids. It deliberately
// does NOT require `exp` (optional for logout tokens) but the parser still
// validates `exp`/`nbf` when present. `alg` is pinned to RS256 (blocks alg=none
// and HS256 key-confusion).
func (s *SSOService) verifyLogoutToken(ctx context.Context, token string, res logoutIssuerResolution) (*logoutTokenClaims, error) {
	claims := &logoutTokenClaims{}
	parser := jwtv5.NewParser(
		jwtv5.WithValidMethods([]string{"RS256"}),
		jwtv5.WithLeeway(logoutTokenFutureLeeway),
	)
	keyFunc := func(t *jwtv5.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		return s.oidcVerifier.keyForKID(ctx, res.jwksURL, kid)
	}
	if _, err := parser.ParseWithClaims(token, claims, keyFunc); err != nil {
		return nil, err
	}
	if !audienceMatches(claims.Audience, res.allowedClientIDs) {
		return nil, errors.New("logout_token audience mismatch")
	}
	return claims, nil
}

// audienceMatches reports whether any token audience equals one of the acceptable
// client_ids for the issuer.
func audienceMatches(aud jwtv5.ClaimStrings, allowed []string) bool {
	for _, a := range aud {
		for _, c := range allowed {
			if a == c && c != "" {
				return true
			}
		}
	}
	return false
}

// validateLogoutClaims enforces the OIDC Back-Channel Logout 1.0 logout_token
// claim rules that the signature/audience check does not cover.
func validateLogoutClaims(c *logoutTokenClaims, iss string) error {
	if c.Issuer != iss {
		return errors.New("issuer mismatch")
	}
	// A logout_token MUST NOT contain a nonce (it is not the result of an
	// authentication request). Presence signals a forged/mis-issued token.
	if c.Nonce != nil {
		return errors.New("nonce must not be present in logout_token")
	}
	// events MUST contain the back-channel-logout member, whose value is an
	// (empty) JSON object.
	raw, ok := c.Events[backchannelLogoutEvent]
	if !ok {
		return errors.New("events missing back-channel-logout member")
	}
	if !isJSONObject(raw) {
		return errors.New("back-channel-logout event value is not an object")
	}
	// A logout_token MUST contain a sid and/or a sub.
	if c.SID == "" && c.Subject == "" {
		return errors.New("logout_token missing both sid and sub")
	}
	// iat is REQUIRED and must be recent (replay guard).
	if c.IssuedAt == nil {
		return errors.New("logout_token missing iat")
	}
	age := time.Since(c.IssuedAt.Time)
	if age > logoutTokenMaxAge || age < -logoutTokenFutureLeeway {
		return errors.New("logout_token iat out of acceptable range")
	}
	return nil
}

// isJSONObject reports whether raw is a JSON object (`{...}`), per the spec's
// requirement that the event value be a JSON object (SHOULD be empty).
func isJSONObject(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	return json.Unmarshal(raw, &obj) == nil
}

// resolveLogoutIssuer maps a logout_token's `iss` to the provider config that
// could have issued it: the JWKS to verify against and the set of client_ids that
// are acceptable audiences. It considers the platform env Entra fallback and all
// active per-tenant providers. Returns an error when no configured provider
// matches the issuer (⇒ the token is rejected, nothing to revoke).
func (s *SSOService) resolveLogoutIssuer(ctx context.Context, iss string) (logoutIssuerResolution, error) {
	// --- Microsoft Entra ID (issuer embeds the directory id) ---
	if tid, ok := entraTIDFromIssuer(iss); ok {
		clientIDs := make([]string, 0, 2)

		// Platform env fallback.
		if s.authConfig.EntraSSO.IsConfigured() {
			ecfg := s.authConfig.EntraSSO
			if isNonSpecificEntraTenant(ecfg.TenantID) || strings.EqualFold(ecfg.TenantID, tid) {
				clientIDs = append(clientIDs, ecfg.ClientID)
			}
		}
		// Per-tenant Entra providers (cross-tenant lookup — resolves audiences only).
		if ips, err := s.ipRepo.ListActiveByProvider(ctx, identityproviderdom.ProviderEntraID); err == nil {
			for _, ip := range ips {
				ti := ip.TenantIdentifier()
				if isNonSpecificEntraTenant(ti) || strings.EqualFold(ti, tid) {
					clientIDs = append(clientIDs, ip.ClientID())
				}
			}
		}
		if len(clientIDs) == 0 {
			return logoutIssuerResolution{}, ErrLogoutTokenInvalid
		}
		return logoutIssuerResolution{
			jwksURL:          identityproviderdom.ProviderEntraID.JWKSURL(tid),
			allowedClientIDs: clientIDs,
		}, nil
	}

	// --- Okta / Google Workspace (exact issuer match) ---
	for _, provider := range []identityproviderdom.Provider{
		identityproviderdom.ProviderOkta,
		identityproviderdom.ProviderGoogleWorkspace,
	} {
		ips, err := s.ipRepo.ListActiveByProvider(ctx, provider)
		if err != nil {
			continue
		}
		clientIDs := make([]string, 0, 1)
		jwksURL := ""
		for _, ip := range ips {
			if providerIssuerMatches(ip, iss) {
				clientIDs = append(clientIDs, ip.ClientID())
				jwksURL = ip.Provider().JWKSURL(ip.TenantIdentifier())
			}
		}
		if len(clientIDs) > 0 && jwksURL != "" {
			return logoutIssuerResolution{jwksURL: jwksURL, allowedClientIDs: clientIDs}, nil
		}
	}

	return logoutIssuerResolution{}, ErrLogoutTokenInvalid
}

// entraTIDFromIssuer extracts the directory id from a Microsoft Entra ID v2
// issuer (https://login.microsoftonline.com/{tid}/v2.0), or returns ok=false.
func entraTIDFromIssuer(iss string) (string, bool) {
	const prefix = "https://login.microsoftonline.com/"
	const suffix = "/v2.0"
	if !strings.HasPrefix(iss, prefix) || !strings.HasSuffix(iss, suffix) {
		return "", false
	}
	tid := iss[len(prefix) : len(iss)-len(suffix)]
	if tid == "" || strings.Contains(tid, "/") {
		return "", false
	}
	return tid, true
}

// providerIssuerMatches reports whether a non-Entra provider config corresponds
// to the given issuer. Uses the explicitly stored issuer URL when set, otherwise
// the provider-specific derivation.
func providerIssuerMatches(ip *identityproviderdom.IdentityProvider, iss string) bool {
	if ip.IssuerURL() != "" && strings.EqualFold(ip.IssuerURL(), iss) {
		return true
	}
	switch ip.Provider() {
	case identityproviderdom.ProviderOkta:
		// Okta org authorization server issuer.
		return strings.EqualFold(strings.TrimRight(ip.TenantIdentifier(), "/")+"/oauth2/default", iss)
	case identityproviderdom.ProviderGoogleWorkspace:
		return iss == "https://accounts.google.com" || iss == "accounts.google.com"
	case identityproviderdom.ProviderEntraID:
		return false // handled by the Entra branch
	}
	return false
}
