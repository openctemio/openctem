package adminconsole

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/oidc"
)

// Platform identity provider for administrators (RFC-022 revision 4): one
// OIDC provider, configured by super admins, separate from every
// organization's identity providers. No administrator is ever created from
// it: an IdP identity is matched to an existing administrator, by verified
// email on the first sign-in (then bound) and by (issuer, subject) after that.

// Audit actions for the platform IdP.
const (
	ActionIdPLogin        = "console.idp_login"
	ActionIdPLoginFailed  = "console.idp_login_failed"
	ActionIdPBound        = "console.idp_bound"
	ActionIdPUnbound      = "console.idp_unbound"
	ActionPlatformIdPSave = "platform_idp.update"
	ActionPlatformIdPDel  = "platform_idp.delete"
)

// OIDCProvider is the relying-party client (pkg/oidc in production, built over
// httpsec.SafeHTTPClient + httpsec.ValidateURL).
type OIDCProvider interface {
	Discover(ctx context.Context, issuer string) (*oidc.Discovery, error)
	Exchange(ctx context.Context, r oidc.ExchangeRequest) (string, error)
	VerifyIDToken(ctx context.Context, raw string, exp oidc.Expectations) (*oidc.Claims, error)
}

// SetPlatformIdP wires the platform IdP store and the OIDC client.
func (s *Service) SetPlatformIdP(repo admin.PlatformIdPRepository, client OIDCProvider) {
	s.idps = repo
	s.oidc = client
}

// platformIdP returns the configuration, or nil when none is configured.
func (s *Service) platformIdP(ctx context.Context) (*admin.PlatformIdP, error) {
	if s.idps == nil {
		return nil, nil
	}
	p, err := s.idps.Get(ctx)
	if errors.Is(err, admin.ErrPlatformIdPNotConfigured) {
		return nil, nil
	}
	return p, err
}

// =============================================================================
// Configuration (super admin)
// =============================================================================

// PlatformIdPInput is the configuration a super admin submits. An empty
// ClientSecret on update keeps the stored one.
type PlatformIdPInput struct {
	Enabled          bool
	DisplayName      string
	Issuer           string
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	Scopes           []string
	RequireIdP       bool
	TrustedACRValues []string
	TrustedAMRValues []string
}

// PublicIdPInfo is what the console sign-in page may know.
type PublicIdPInfo struct {
	Enabled     bool
	DisplayName string
}

// GetPlatformIdP returns the configuration (secret ciphertext included; the
// handler never serializes it), or admin.ErrPlatformIdPNotConfigured.
func (s *Service) GetPlatformIdP(ctx context.Context) (*admin.PlatformIdP, error) {
	if s.idps == nil {
		return nil, admin.ErrPlatformIdPNotConfigured
	}
	return s.idps.Get(ctx)
}

// PublicIdP tells the console sign-in page whether to offer the IdP.
func (s *Service) PublicIdP(ctx context.Context) PublicIdPInfo {
	p, err := s.platformIdP(ctx)
	if err != nil || p == nil || !p.Enabled {
		return PublicIdPInfo{}
	}
	return PublicIdPInfo{Enabled: true, DisplayName: p.DisplayName}
}

var tokenRe = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]{1,200}$`) // RFC 6749 scope-token / acr / amr value

func validationErr(msg string) error {
	return shared.NewDomainError("VALIDATION", msg, shared.ErrValidation)
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return validationErr("redirect_uri must be an absolute URL without credentials or fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		// RFC 8252 7.3: plain http only for the loopback interface (local dev).
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return validationErr("redirect_uri must use https (http only for localhost)")
}

func validateValues(field string, vals []string, max int) ([]string, error) {
	out := make([]string, 0, len(vals))
	seen := map[string]bool{}
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		if !tokenRe.MatchString(v) {
			return nil, validationErr(field + " contains an invalid value")
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) > max {
		return nil, validationErr(fmt.Sprintf("%s accepts at most %d values", field, max))
	}
	return out, nil
}

// normalizePlatformIdPInput trims and validates the submitted configuration.
func normalizePlatformIdPInput(in PlatformIdPInput) (PlatformIdPInput, error) {
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Issuer = strings.TrimSpace(in.Issuer)
	in.ClientID = strings.TrimSpace(in.ClientID)
	in.RedirectURI = strings.TrimSpace(in.RedirectURI)
	if in.DisplayName == "" || len(in.DisplayName) > 100 {
		return in, validationErr("display_name is required (at most 100 characters)")
	}
	if err := oidc.ValidateIssuer(in.Issuer); err != nil || len(in.Issuer) > 512 {
		return in, validationErr("issuer must be an https URL without query or fragment")
	}
	if in.ClientID == "" || len(in.ClientID) > 255 {
		return in, validationErr("client_id is required")
	}
	if len(in.ClientSecret) > 1024 {
		return in, validationErr("client_secret is too long")
	}
	if err := validateRedirectURI(in.RedirectURI); err != nil || len(in.RedirectURI) > 512 {
		return in, validationErr("redirect_uri must use https (http only for localhost)")
	}
	scopes, err := validateValues("scopes", in.Scopes, 20)
	if err != nil {
		return in, err
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	hasOpenID := false
	for _, sc := range scopes {
		hasOpenID = hasOpenID || sc == "openid"
	}
	if !hasOpenID {
		return in, validationErr(`scopes must include "openid"`)
	}
	in.Scopes = scopes
	if in.TrustedACRValues, err = validateValues("trusted_acr_values", in.TrustedACRValues, 10); err != nil {
		return in, err
	}
	if in.TrustedAMRValues, err = validateValues("trusted_amr_values", in.TrustedAMRValues, 10); err != nil {
		return in, err
	}
	return in, nil
}

// SavePlatformIdP validates, discovers and stores the configuration.
func (s *Service) SavePlatformIdP(ctx context.Context, actor *admin.AdminUser, in PlatformIdPInput, client ClientInfo) (*admin.PlatformIdP, error) {
	if s.idps == nil || s.oidc == nil {
		return nil, errors.New("platform identity provider is not available")
	}
	in, err := normalizePlatformIdPInput(in)
	if err != nil {
		return nil, err
	}
	acr, amr := in.TrustedACRValues, in.TrustedAMRValues

	existing, err := s.platformIdP(ctx)
	if err != nil {
		return nil, err
	}
	secretEnc := ""
	switch {
	case in.ClientSecret != "":
		if secretEnc, err = s.encryptor.EncryptString(in.ClientSecret); err != nil {
			return nil, fmt.Errorf("encrypt client secret: %w", err)
		}
	case existing != nil:
		secretEnc = existing.ClientSecretEncrypted
	default:
		return nil, validationErr("client_secret is required")
	}

	d, err := s.oidc.Discover(ctx, in.Issuer)
	if err != nil {
		s.log.Warn("platform IdP discovery failed", "error", logSafe(err.Error()))
		return nil, validationErr("could not read the issuer's OpenID configuration (check the issuer URL and that it is reachable)")
	}

	p := &admin.PlatformIdP{
		Enabled:                 in.Enabled,
		DisplayName:             in.DisplayName,
		Issuer:                  in.Issuer,
		ClientID:                in.ClientID,
		ClientSecretEncrypted:   secretEnc,
		RedirectURI:             in.RedirectURI,
		Scopes:                  in.Scopes,
		AuthorizationEndpoint:   d.AuthorizationEndpoint,
		TokenEndpoint:           d.TokenEndpoint,
		JWKSURI:                 d.JWKSURI,
		TokenEndpointAuthMethod: d.TokenEndpointAuthMethod,
		RequireIdP:              in.RequireIdP,
		TrustedACRValues:        acr,
		TrustedAMRValues:        amr,
	}
	if actor != nil {
		id := actor.ID()
		p.UpdatedBy = &id
	}
	clearBindings := existing != nil && existing.Issuer != p.Issuer
	if err := s.idps.Save(ctx, p, clearBindings); err != nil {
		return nil, err
	}
	if p.Enforced() && !existing.Enforced() {
		// Password sessions of non-break-glass administrators end now.
		if n, err := s.console.DeletePasswordSessionsExceptBreakGlass(ctx); err != nil {
			s.log.Warn("end password console sessions after require-IdP", "error", err)
		} else if n > 0 {
			s.log.Info("ended password console sessions after require-IdP", "sessions", n)
		}
	}
	if s.audit != nil && actor != nil {
		entry := admin.NewAuditLogBuilder(actor, ActionPlatformIdPSave).
			Resource("platform_idp", nil, p.Issuer).
			Context(client.IP, client.UserAgent).
			Request("", "", map[string]interface{}{
				"enabled":            p.Enabled,
				"issuer":             p.Issuer,
				"client_id":          p.ClientID,
				"redirect_uri":       p.RedirectURI,
				"require_idp":        p.RequireIdP,
				"trusted_acr_values": acr,
				"trusted_amr_values": amr,
				"secret_changed":     in.ClientSecret != "",
				"bindings_cleared":   clearBindings,
			}).
			High().
			Build()
		s.writeAudit(ctx, ActionPlatformIdPSave, entry)
	}
	return s.idps.Get(ctx)
}

// DeletePlatformIdP removes the configuration (and "require IdP" with it).
func (s *Service) DeletePlatformIdP(ctx context.Context, actor *admin.AdminUser, client ClientInfo) error {
	if s.idps == nil {
		return admin.ErrPlatformIdPNotConfigured
	}
	existing, err := s.idps.Get(ctx)
	if err != nil {
		return err
	}
	if err := s.idps.Delete(ctx); err != nil {
		return err
	}
	if s.audit != nil && actor != nil {
		entry := admin.NewAuditLogBuilder(actor, ActionPlatformIdPDel).
			Resource("platform_idp", nil, existing.Issuer).
			Context(client.IP, client.UserAgent).
			High().
			Build()
		s.writeAudit(ctx, ActionPlatformIdPDel, entry)
	}
	return nil
}

// UnbindIdP removes an administrator's IdP binding (super admin), e.g. when
// their IdP account was recreated. They are bound again on their next IdP
// sign-in, by verified email.
func (s *Service) UnbindIdP(ctx context.Context, actor *admin.AdminUser, targetID shared.ID, client ClientInfo) error {
	target, err := s.admins.GetByID(ctx, targetID)
	if err != nil {
		return err
	}
	if err := s.admins.UnbindIdP(ctx, target.ID()); err != nil {
		return err
	}
	// Sessions opened through the old binding end.
	if err := s.console.DeleteSessionsForAdmin(ctx, target.ID()); err != nil {
		s.log.Warn("end sessions after IdP unbind", "error", err)
	}
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(actor, ActionIdPUnbound).
			Resource("admin_user", ptr(target.ID()), target.Email()).
			Context(client.IP, client.UserAgent).
			High().
			Build()
		s.writeAudit(ctx, ActionIdPUnbound, entry)
	}
	return nil
}

// =============================================================================
// Sign-in
// =============================================================================

// IdPStart is the beginning of an IdP sign-in: send the browser to
// AuthorizationURL and keep State in an HttpOnly cookie.
type IdPStart struct {
	AuthorizationURL string
	State            string
}

// StartIdPLogin begins an authorization-code + PKCE sign-in.
func (s *Service) StartIdPLogin(ctx context.Context) (*IdPStart, error) {
	p, err := s.platformIdP(ctx)
	if err != nil {
		return nil, err
	}
	if p == nil || !p.Enabled || s.oidc == nil {
		return nil, admin.ErrPlatformIdPNotConfigured
	}
	if err := s.idps.DeleteExpiredLoginStates(ctx, s.now()); err != nil {
		s.log.Warn("purge expired IdP sign-in states", "error", err)
	}
	state, err := oidc.RandomString(32)
	if err != nil {
		return nil, err
	}
	nonce, err := oidc.RandomString(32)
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := oidc.NewPKCE()
	if err != nil {
		return nil, err
	}
	encVerifier, err := s.encryptor.EncryptString(verifier)
	if err != nil {
		return nil, fmt.Errorf("encrypt pkce verifier: %w", err)
	}
	now := s.now()
	if err := s.idps.CreateLoginState(ctx, &admin.IdPLoginState{
		StateHash:             hashToken(state),
		Nonce:                 nonce,
		CodeVerifierEncrypted: encVerifier,
		CreatedAt:             now,
		ExpiresAt:             now.Add(admin.IdPLoginStateTTL),
	}); err != nil {
		return nil, err
	}
	authURL, err := oidc.AuthorizationURL(p.AuthorizationEndpoint, oidc.AuthorizationRequest{
		ClientID:      p.ClientID,
		RedirectURI:   p.RedirectURI,
		Scopes:        p.Scopes,
		State:         state,
		Nonce:         nonce,
		CodeChallenge: challenge,
		ACRValues:     p.TrustedACRValues,
	})
	if err != nil {
		return nil, err
	}
	return &IdPStart{AuthorizationURL: authURL, State: state}, nil
}

// IdPLoginResult is the outcome of the IdP callback. Status is
// StatusSignedIn (SessionToken set: the IdP's MFA was trusted) or one of the
// TOTP statuses (Second set: continue with VerifyMFA).
type IdPLoginResult struct {
	Status       LoginStatus
	SessionToken string
	Second       *LoginResult
	Admin        *admin.AdminUser
}

// idpFailure carries the server-side reason; the client only ever sees
// admin.ErrIdPSignInFailed.
type idpFailure struct {
	reason string
	email  string
	admin  *admin.AdminUser
	cause  error
}

func (s *Service) failIdP(ctx context.Context, f idpFailure, client ClientInfo) error {
	if s.audit != nil {
		b := admin.NewAuditLogBuilder(f.admin, ActionIdPLoginFailed).
			Context(client.IP, client.UserAgent).
			Error(f.reason)
		entry := b.Build()
		if f.admin == nil && f.email != "" {
			entry.AdminEmail = truncate(f.email, 255)
		}
		s.writeAudit(ctx, ActionIdPLoginFailed, entry)
	}
	attrs := []any{"reason", f.reason}
	if f.cause != nil {
		attrs = append(attrs, "error", logSafe(f.cause.Error()))
	}
	s.log.Warn("platform IdP sign-in refused", attrs...)
	return admin.ErrIdPSignInFailed
}

// CompleteIdPLogin finishes an IdP sign-in. cookieState is the state from the
// browser's HttpOnly cookie, state and code come from the IdP redirect.
func (s *Service) CompleteIdPLogin(ctx context.Context, cookieState, state, code string, client ClientInfo) (*IdPLoginResult, error) {
	p, err := s.platformIdP(ctx)
	if err != nil {
		return nil, err
	}
	if p == nil || !p.Enabled || s.oidc == nil {
		return nil, s.failIdP(ctx, idpFailure{reason: "identity provider not enabled"}, client)
	}
	if state == "" || code == "" || cookieState == "" ||
		subtle.ConstantTimeCompare([]byte(hashToken(cookieState)), []byte(hashToken(state))) != 1 {
		return nil, s.failIdP(ctx, idpFailure{reason: "state does not match this browser"}, client)
	}
	st, err := s.idps.ConsumeLoginState(ctx, hashToken(state), s.now())
	if err != nil {
		return nil, s.failIdP(ctx, idpFailure{reason: "unknown, used or expired state", cause: err}, client)
	}
	verifier, err := s.encryptor.DecryptString(st.CodeVerifierEncrypted)
	if err != nil {
		return nil, s.failIdP(ctx, idpFailure{reason: "pkce verifier unreadable", cause: err}, client)
	}
	secret, err := s.encryptor.DecryptString(p.ClientSecretEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt client secret: %w", err)
	}
	rawIDToken, err := s.oidc.Exchange(ctx, oidc.ExchangeRequest{
		TokenEndpoint: p.TokenEndpoint,
		AuthMethod:    p.TokenEndpointAuthMethod,
		ClientID:      p.ClientID,
		ClientSecret:  secret,
		Code:          code,
		RedirectURI:   p.RedirectURI,
		CodeVerifier:  verifier,
	})
	if err != nil {
		return nil, s.failIdP(ctx, idpFailure{reason: "code exchange failed", cause: err}, client)
	}
	claims, err := s.oidc.VerifyIDToken(ctx, rawIDToken, oidc.Expectations{
		Issuer: p.Issuer, ClientID: p.ClientID, Nonce: st.Nonce, JWKSURI: p.JWKSURI,
	})
	if err != nil {
		return nil, s.failIdP(ctx, idpFailure{reason: "id_token rejected", cause: err}, client)
	}

	a, err := s.matchAdmin(ctx, p, claims, client)
	if err != nil {
		return nil, err
	}

	if !a.IsActive() || a.IsLocked() || !s.accountActive(ctx, a) {
		return nil, s.failIdP(ctx, idpFailure{reason: "administrator inactive, locked or account suspended", admin: a}, client)
	}

	if note, ok := trustedIdPMFA(p, claims); ok {
		token, err := s.openVerifiedSession(ctx, a, admin.AuthMethodIdP, client, "identity provider; second factor by the IdP ("+note+")")
		if err != nil {
			return nil, err
		}
		if a.FailedLoginCount() > 0 {
			a.ResetFailedLogins()
			if err := s.admins.Update(ctx, a); err != nil {
				s.log.Warn("reset admin failed-login counter", "error", err)
			}
		}
		return &IdPLoginResult{Status: StatusSignedIn, SessionToken: token, Admin: a}, nil
	}

	second, err := s.beginSecondFactor(ctx, a, admin.AuthMethodIdP, client)
	if err != nil {
		return nil, err
	}
	s.recordNote(ctx, a, ActionIdPLogin, client, "identity provider verified; console TOTP required")
	return &IdPLoginResult{Status: second.Status, Second: second, Admin: a}, nil
}

// matchAdmin finds the administrator for the IdP identity: bound (issuer,
// subject) first; otherwise a first sign-in binds the administrator with the
// same, verified, email. No administrator is ever created.
func (s *Service) matchAdmin(ctx context.Context, p *admin.PlatformIdP, claims *oidc.Claims, client ClientInfo) (*admin.AdminUser, error) {
	a, err := s.admins.GetByIdPSubject(ctx, p.Issuer, claims.Subject)
	if err == nil {
		return a, nil
	}
	if !admin.IsAdminNotFound(err) {
		return nil, err
	}

	email := strings.TrimSpace(claims.Email)
	if email == "" || !claims.EmailIsVerified() {
		return nil, s.failIdP(ctx, idpFailure{reason: "unbound identity without a verified email", email: email}, client)
	}
	a, err = s.admins.GetByEmail(ctx, email)
	if err != nil {
		if admin.IsAdminNotFound(err) {
			return nil, s.failIdP(ctx, idpFailure{reason: "no administrator for this identity (no JIT creation)", email: email}, client)
		}
		return nil, err
	}
	switch {
	case a.IsBreakGlass():
		return nil, s.failIdP(ctx, idpFailure{reason: "break-glass administrators cannot sign in through the IdP", admin: a}, client)
	case a.IdPBound():
		return nil, s.failIdP(ctx, idpFailure{reason: "administrator is bound to a different IdP identity", admin: a}, client)
	case !a.IsActive():
		return nil, s.failIdP(ctx, idpFailure{reason: "administrator inactive", admin: a}, client)
	}
	if err := s.admins.BindIdP(ctx, a.ID(), p.Issuer, claims.Subject); err != nil {
		return nil, s.failIdP(ctx, idpFailure{reason: "binding refused", admin: a, cause: err}, client)
	}
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(a, ActionIdPBound).
			Resource("admin_user", ptr(a.ID()), a.Email()).
			Context(client.IP, client.UserAgent).
			Request("", "", map[string]interface{}{"issuer": p.Issuer}).
			High().
			Build()
		s.writeAudit(ctx, ActionIdPBound, entry)
	}
	return s.admins.GetByID(ctx, a.ID())
}

// trustedIdPMFA reports whether the token proves MFA the configuration trusts.
func trustedIdPMFA(p *admin.PlatformIdP, c *oidc.Claims) (string, bool) {
	for _, v := range p.TrustedACRValues {
		if c.ACR != "" && c.ACR == v {
			return "acr=" + v, true
		}
	}
	for _, v := range p.TrustedAMRValues {
		for _, m := range c.AMR {
			if m == v {
				return "amr=" + v, true
			}
		}
	}
	return "", false
}
