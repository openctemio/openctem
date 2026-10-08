// Package mcpoauth is the OAuth 2.1 authorization server of the MCP
// endpoint: authorization requests, consent, the token and revocation
// endpoints, and the check every MCP request's access token goes through.
//
// Design: docs/rfcs/RFC-062-mcp-authorization.md.
package mcpoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MembershipChecker reports whether a user is an active member of a tenant
// with an active account (apikey.NewMembershipChecker).
type MembershipChecker interface {
	IsActiveMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}

// HolderPermissions returns what a user holds in a tenant now; all=true for
// an owner or administrator (apikey.NewHolderPermissions).
type HolderPermissions interface {
	HeldPermissions(ctx context.Context, tenantID, userID shared.ID) (all bool, perms []string, err error)
}

// AuditLogger is the slice of the audit service the authorization server
// writes to.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service is the authorization server.
type Service struct {
	repo        mcpoauth.Repository
	endpoints   mcpoauth.Endpoints
	pepper      string
	oldPeppers  []string
	fetcher     MetadataFetcher
	members     MembershipChecker
	permissions HolderPermissions
	audit       AuditLogger
	log         *logger.Logger
	now         func() time.Time
}

// Config wires the service.
type Config struct {
	Repository  mcpoauth.Repository
	Endpoints   mcpoauth.Endpoints
	Pepper      string
	OldPeppers  []string
	Fetcher     MetadataFetcher
	Members     MembershipChecker
	Permissions HolderPermissions
	Audit       AuditLogger
	Logger      *logger.Logger
}

// NewService builds the authorization server. Members and Permissions are
// required: without them no token could be checked against the user's
// current access, so the constructor refuses.
func NewService(c Config) (*Service, error) {
	if c.Repository == nil || c.Members == nil || c.Permissions == nil || c.Logger == nil {
		return nil, errors.New("mcpoauth: repository, membership, permissions and logger are required")
	}
	return &Service{
		repo: c.Repository, endpoints: c.Endpoints, pepper: c.Pepper, oldPeppers: c.OldPeppers,
		fetcher: c.Fetcher, members: c.Members, permissions: c.Permissions, audit: c.Audit,
		log: c.Logger.With("service", "mcp-oauth"), now: time.Now,
	}, nil
}

// Endpoints returns the public identifiers.
func (s *Service) Endpoints() mcpoauth.Endpoints { return s.endpoints }

// Actor describes who made a request, for the audit trail.
type Actor struct {
	IP        string
	UserAgent string
	RequestID string
}

// OAuthError is an OAuth error response (RFC 6749 §4.1.2.1, §5.2).
type OAuthError struct {
	Code        string
	Description string
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

func oauthErr(code, desc string) *OAuthError { return &OAuthError{Code: code, Description: desc} }

// --- Authorization endpoint -------------------------------------------------

// AuthorizeError is a refused authorization request. When Redirect is true
// the error goes back to the client's redirect URI; otherwise the client or
// its redirect URI could not be trusted and the error is shown as a page.
type AuthorizeError struct {
	OAuthError
	Redirect    bool
	RedirectURI string
	State       string
}

var (
	pkceChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pkceVerifierRe  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

const maxStateLen = 512

// StartAuthorization validates an authorization request (the query of
// GET /oauth/authorize) and stores it for the consent page. It returns the
// request id.
func (s *Service) StartAuthorization(ctx context.Context, q url.Values) (shared.ID, *AuthorizeError) {
	// RFC 6749 §3.1: parameters must not be repeated.
	for k, v := range q {
		if len(v) > 1 {
			return shared.ID{}, &AuthorizeError{OAuthError: *oauthErr("invalid_request", "parameter "+k+" repeated")}
		}
	}
	clientID := q.Get("client_id")
	client, err := s.resolveClient(ctx, clientID)
	if err != nil {
		return shared.ID{}, &AuthorizeError{OAuthError: *oauthErr("invalid_client", "unknown or unusable client")}
	}
	redirectURI := q.Get("redirect_uri")
	if !mcpoauth.MatchRedirectURI(client.RedirectURIs, redirectURI) {
		return shared.ID{}, &AuthorizeError{OAuthError: *oauthErr("invalid_request", "redirect_uri is not registered for this client")}
	}
	state := q.Get("state")
	fail := func(code, desc string) (shared.ID, *AuthorizeError) {
		return shared.ID{}, &AuthorizeError{OAuthError: *oauthErr(code, desc), Redirect: true, RedirectURI: redirectURI, State: state}
	}
	if len(state) > maxStateLen {
		return fail("invalid_request", "state too long")
	}
	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "only response_type=code is supported")
	}
	if m := q.Get("code_challenge_method"); m != "S256" {
		return fail("invalid_request", "code_challenge_method must be S256")
	}
	if !pkceChallengeRe.MatchString(q.Get("code_challenge")) {
		return fail("invalid_request", "code_challenge must be an S256 challenge")
	}
	if !s.isResource(q.Get("resource")) {
		return fail("invalid_target", "resource must be "+s.endpoints.Resource)
	}
	if q.Get("prompt") == "none" {
		return fail("consent_required", "consent is required")
	}
	scopes, perr := mcpoauth.ParseScopes(q.Get("scope"))
	if perr != nil {
		return fail("invalid_scope", "unknown scope")
	}
	if len(scopes) == 0 {
		scopes = mcpoauth.ReadScopes()
	}
	now := s.now()
	req := &mcpoauth.AuthRequest{
		ID:            shared.NewID(),
		Client:        *client,
		RedirectURI:   redirectURI,
		State:         state,
		CodeChallenge: q.Get("code_challenge"),
		Resource:      s.endpoints.Resource,
		Scopes:        scopes,
		Status:        mcpoauth.RequestPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(mcpoauth.RequestTTL),
	}
	if err := s.repo.CreateRequest(ctx, req); err != nil {
		s.log.Error("mcp oauth: store authorization request", "error", err.Error())
		return fail("server_error", "try again")
	}
	return req.ID, nil
}

// isResource reports whether r names the MCP endpoint. Scheme and host are
// compared case-insensitively and a trailing slash is ignored (MCP: servers
// SHOULD accept uppercase scheme and host); the path must match exactly.
func (s *Service) isResource(r string) bool {
	if r == "" {
		return false
	}
	u, err := url.Parse(r)
	if err != nil || u.Fragment != "" || u.RawQuery != "" || u.User != nil {
		return false
	}
	canon := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.EscapedPath(), "/")
	return canon == s.endpoints.Resource
}

// AuthorizeErrorRedirect builds the redirect URL carrying an authorization
// error back to the client, with the issuer (RFC 9207).
func (s *Service) AuthorizeErrorRedirect(e *AuthorizeError) string {
	return withQuery(e.RedirectURI, map[string]string{
		"error": e.Code, "error_description": e.Description, "state": e.State, "iss": s.endpoints.Issuer,
	})
}

// --- Consent ---------------------------------------------------------------

// ScopeView is one requested scope as the consent page shows it.
type ScopeView struct {
	Scope mcpoauth.Scope
	Title string
	Write bool
	// Granted is false when the person holds none of the scope's
	// permissions in the organization: the scope would give nothing.
	Granted bool
}

// ConsentView is what the consent page shows.
type ConsentView struct {
	RequestID    string
	ClientName   string
	ClientID     string
	ClientKind   mcpoauth.ClientKind
	ClientHost   string
	RedirectURI  string
	RedirectHost string
	LoopbackOnly bool
	Scopes       []ScopeView
	ExpiresAt    time.Time
}

// ErrConsentUnavailable is any consent request that cannot be acted on:
// unknown, expired, already decided, or opened by someone else. One error,
// so a request id cannot be probed.
var ErrConsentUnavailable = fmt.Errorf("%w: authorization request not available", shared.ErrNotFound)

// ErrNothingToGrant means the person holds none of the requested access in
// the organization.
var ErrNothingToGrant = fmt.Errorf("%w: you have none of the access this application asks for in this organization", shared.ErrForbidden)

// ConsentRequest claims the request for the signed-in user and returns what
// the consent page shows for the organization the session works in.
func (s *Service) ConsentRequest(ctx context.Context, requestID, userID, tenantID shared.ID) (*ConsentView, error) {
	req, err := s.repo.ClaimRequest(ctx, requestID, userID, s.now())
	if err != nil {
		return nil, ErrConsentUnavailable
	}
	if req.Client.BlockedAt != nil {
		return nil, ErrConsentUnavailable
	}
	all, held, err := s.permissions.HeldPermissions(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("read permissions: %w", err)
	}
	view := &ConsentView{
		RequestID:    req.ID.String(),
		ClientName:   req.Client.Name,
		ClientID:     req.Client.ClientID,
		ClientKind:   req.Client.Kind,
		ClientHost:   clientHost(req.Client),
		RedirectURI:  req.RedirectURI,
		RedirectHost: mcpoauth.RedirectHost(req.RedirectURI),
		LoopbackOnly: mcpoauth.IsLoopbackOnly(req.Client.RedirectURIs),
		ExpiresAt:    req.ExpiresAt,
	}
	for _, sc := range req.Scopes {
		view.Scopes = append(view.Scopes, ScopeView{
			Scope: sc, Title: mcpoauth.Title(sc), Write: mcpoauth.IsWrite(sc),
			Granted: all || len(intersect(mcpoauth.Permissions([]mcpoauth.Scope{sc}), held)) > 0,
		})
	}
	return view, nil
}

// clientHost is the host a person should recognize: the metadata document's
// host. Registered clients have no URL.
func clientHost(c mcpoauth.Client) string {
	if c.Kind != mcpoauth.ClientKindMetadataDocument {
		return ""
	}
	u, err := url.Parse(c.ClientID)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Approve records the person's approval in the organization the session
// works in and returns the URL the browser goes to (the client's redirect
// URI with the code).
func (s *Service) Approve(ctx context.Context, requestID, userID, tenantID shared.ID, actor Actor) (string, error) {
	now := s.now()
	req, err := s.repo.ClaimRequest(ctx, requestID, userID, now)
	if err != nil || req.Client.BlockedAt != nil {
		return "", ErrConsentUnavailable
	}
	ok, err := s.members.IsActiveMember(ctx, tenantID, userID)
	if err != nil || !ok {
		return "", ErrConsentUnavailable
	}
	all, held, err := s.permissions.HeldPermissions(ctx, tenantID, userID)
	if err != nil {
		return "", fmt.Errorf("read permissions: %w", err)
	}
	granted := make([]mcpoauth.Scope, 0, len(req.Scopes))
	for _, sc := range req.Scopes {
		if all || len(intersect(mcpoauth.Permissions([]mcpoauth.Scope{sc}), held)) > 0 {
			granted = append(granted, sc)
		}
	}
	if len(granted) == 0 {
		return "", ErrNothingToGrant
	}
	code, err := randomToken("")
	if err != nil {
		return "", err
	}
	if err := s.repo.ApproveRequest(ctx, req.ID, userID, tenantID, granted, s.hash(code), now.Add(mcpoauth.CodeTTL), now); err != nil {
		return "", ErrConsentUnavailable
	}
	s.logAudit(ctx, tenantID.String(), userID.String(), actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPClientAuthorized, auditdom.ResourceTypeMCPGrant, req.ID.String()).
			WithResourceName(req.Client.Name).
			WithMessage("MCP client authorized: "+req.Client.Name).
			WithMetadata("client_id", req.Client.ClientID).
			WithMetadata("client_kind", string(req.Client.Kind)).
			WithMetadata("redirect_host", mcpoauth.RedirectHost(req.RedirectURI)).
			WithMetadata("scopes", mcpoauth.Join(granted)))
	return withQuery(req.RedirectURI, map[string]string{"code": code, "state": req.State, "iss": s.endpoints.Issuer}), nil
}

// Deny records the person's refusal and returns the URL the browser goes to.
func (s *Service) Deny(ctx context.Context, requestID, userID, tenantID shared.ID, actor Actor) (string, error) {
	now := s.now()
	req, err := s.repo.ClaimRequest(ctx, requestID, userID, now)
	if err != nil {
		return "", ErrConsentUnavailable
	}
	if err := s.repo.DenyRequest(ctx, req.ID, userID, now); err != nil {
		return "", ErrConsentUnavailable
	}
	s.logAudit(ctx, tenantID.String(), userID.String(), actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPClientDenied, auditdom.ResourceTypeMCPGrant, req.ID.String()).
			WithResourceName(req.Client.Name).
			WithMessage("MCP client refused: "+req.Client.Name).
			WithMetadata("client_id", req.Client.ClientID))
	return withQuery(req.RedirectURI, map[string]string{
		"error": "access_denied", "error_description": "the user refused", "state": req.State, "iss": s.endpoints.Issuer,
	}), nil
}

// --- Token endpoint --------------------------------------------------------

// TokenResponse is a successful token response (RFC 6749 §5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// Token handles POST /oauth/token for the two supported grant types.
func (s *Service) Token(ctx context.Context, form url.Values, actor Actor) (*TokenResponse, *OAuthError) {
	for k, v := range form {
		if len(v) > 1 {
			return nil, oauthErr("invalid_request", "parameter "+k+" repeated")
		}
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		return s.exchangeCode(ctx, form, actor)
	case "refresh_token":
		return s.refresh(ctx, form, actor)
	case "":
		return nil, oauthErr("invalid_request", "grant_type is required")
	default:
		return nil, oauthErr("unsupported_grant_type", "only authorization_code and refresh_token are supported")
	}
}

func (s *Service) exchangeCode(ctx context.Context, form url.Values, actor Actor) (*TokenResponse, *OAuthError) {
	invalid := oauthErr("invalid_grant", "the authorization code is invalid, expired or was already used")
	code, verifier, clientID := form.Get("code"), form.Get("code_verifier"), form.Get("client_id")
	if code == "" || clientID == "" || !pkceVerifierRe.MatchString(verifier) {
		return nil, oauthErr("invalid_request", "code, client_id and a valid code_verifier are required")
	}
	if !s.isResource(form.Get("resource")) {
		return nil, oauthErr("invalid_target", "resource must be "+s.endpoints.Resource)
	}
	now := s.now()
	req, err := s.repo.RedeemCode(ctx, s.hash(code), now)
	if errors.Is(err, mcpoauth.ErrCodeReused) {
		// RFC 9700 §4.2.4: a code presented twice; revoke what the first
		// redemption issued.
		if req.GrantID != nil {
			if req.TenantID != nil {
				_ = s.repo.RevokeGrant(ctx, *req.TenantID, *req.GrantID, mcpoauth.RevokedCodeReuse, now)
			}
		}
		s.logAudit(ctx, idString(req.TenantID), idString(req.UserID), actor,
			auditapp.NewDeniedEvent(auditdom.ActionMCPCodeReused, auditdom.ResourceTypeMCPGrant, idString(req.GrantID), "authorization code reused").
				WithResourceName(req.Client.Name).
				WithMetadata("client_id", req.Client.ClientID))
		return nil, invalid
	}
	if err != nil {
		return nil, invalid
	}
	// The code is consumed from here on: any mismatch burns it.
	if req.Client.ClientID != clientID || req.RedirectURI != form.Get("redirect_uri") ||
		!verifyPKCE(verifier, req.CodeChallenge) || req.Client.BlockedAt != nil ||
		req.UserID == nil || req.TenantID == nil {
		return nil, invalid
	}
	if ok, err := s.members.IsActiveMember(ctx, *req.TenantID, *req.UserID); err != nil || !ok {
		return nil, invalid
	}
	grant := &mcpoauth.Grant{
		ID:        shared.NewID(),
		TenantID:  *req.TenantID,
		UserID:    *req.UserID,
		Client:    req.Client,
		Resource:  req.Resource,
		Scopes:    req.GrantedScopes,
		CreatedAt: now,
		ExpiresAt: now.Add(mcpoauth.GrantMaxTTL),
	}
	resp, tokens, err := s.newTokens(grant, now)
	if err != nil {
		return nil, oauthErr("server_error", "try again")
	}
	if err := s.repo.CreateGrant(ctx, grant, req.ID, tokens...); err != nil {
		s.log.Error("mcp oauth: create grant", "error", err.Error())
		return nil, oauthErr("server_error", "try again")
	}
	s.logAudit(ctx, grant.TenantID.String(), grant.UserID.String(), actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPTokenIssued, auditdom.ResourceTypeMCPGrant, grant.ID.String()).
			WithResourceName(grant.Client.Name).
			WithMessage("MCP access granted to "+grant.Client.Name).
			WithMetadata("client_id", grant.Client.ClientID).
			WithMetadata("scopes", mcpoauth.Join(grant.Scopes)))
	return resp, nil
}

func (s *Service) refresh(ctx context.Context, form url.Values, actor Actor) (*TokenResponse, *OAuthError) {
	invalid := oauthErr("invalid_grant", "the refresh token is invalid or expired")
	raw, clientID := form.Get("refresh_token"), form.Get("client_id")
	if !strings.HasPrefix(raw, mcpoauth.RefreshTokenPrefix) || clientID == "" {
		return nil, oauthErr("invalid_request", "refresh_token and client_id are required")
	}
	if r := form.Get("resource"); r != "" && !s.isResource(r) {
		return nil, oauthErr("invalid_target", "resource must be "+s.endpoints.Resource)
	}
	now := s.now()
	grant, hash, err := s.grantByToken(ctx, raw, mcpoauth.TokenRefresh, now)
	if errors.Is(err, mcpoauth.ErrRefreshReused) {
		s.revokeForReuse(ctx, grant, actor, now)
		return nil, invalid
	}
	if err != nil || grant.Client.ClientID != clientID || !grant.Active(now) || grant.Resource != s.endpoints.Resource {
		return nil, invalid
	}
	if ok, err := s.members.IsActiveMember(ctx, grant.TenantID, grant.UserID); err != nil || !ok {
		if err == nil {
			_ = s.repo.RevokeGrant(ctx, grant.TenantID, grant.ID, mcpoauth.RevokedMembershipGone, now)
		}
		return nil, invalid
	}
	var narrowed []mcpoauth.Scope
	if raw := form.Get("scope"); raw != "" {
		want, perr := mcpoauth.ParseScopes(raw)
		if perr != nil || len(want) == 0 || !subset(want, grant.Scopes) {
			return nil, oauthErr("invalid_scope", "a refresh can only narrow the granted scopes")
		}
		narrowed, grant.Scopes = want, want
	}
	resp, tokens, err := s.newTokens(grant, now)
	if err != nil {
		return nil, oauthErr("server_error", "try again")
	}
	if err := s.repo.RotateRefresh(ctx, grant.TenantID, hash, narrowed, now, tokens...); err != nil {
		if errors.Is(err, mcpoauth.ErrRefreshReused) {
			// Lost a race with another use of the same token: someone else
			// holds a copy.
			s.revokeForReuse(ctx, grant, actor, now)
			return nil, invalid
		}
		s.log.Error("mcp oauth: rotate refresh token", "error", err.Error())
		return nil, oauthErr("server_error", "try again")
	}
	return resp, nil
}

func (s *Service) revokeForReuse(ctx context.Context, grant *mcpoauth.Grant, actor Actor, now time.Time) {
	if grant == nil {
		return
	}
	_ = s.repo.RevokeGrant(ctx, grant.TenantID, grant.ID, mcpoauth.RevokedRefreshReuse, now)
	s.logAudit(ctx, grant.TenantID.String(), grant.UserID.String(), actor,
		auditapp.NewDeniedEvent(auditdom.ActionMCPRefreshReused, auditdom.ResourceTypeMCPGrant, grant.ID.String(), "refresh token reused").
			WithResourceName(grant.Client.Name).
			WithMessage("A used MCP refresh token was presented again; the connection to "+grant.Client.Name+" was revoked").
			WithMetadata("client_id", grant.Client.ClientID))
}

// newTokens mints an access and a refresh token for the grant.
func (s *Service) newTokens(g *mcpoauth.Grant, now time.Time) (*TokenResponse, []mcpoauth.Token, error) {
	access, err := randomToken(mcpoauth.AccessTokenPrefix)
	if err != nil {
		return nil, nil, err
	}
	refresh, err := randomToken(mcpoauth.RefreshTokenPrefix)
	if err != nil {
		return nil, nil, err
	}
	refreshExp := now.Add(mcpoauth.RefreshIdleTTL)
	if refreshExp.After(g.ExpiresAt) {
		refreshExp = g.ExpiresAt
	}
	tokens := []mcpoauth.Token{
		{Hash: s.hash(access), GrantID: g.ID, Kind: mcpoauth.TokenAccess, ExpiresAt: now.Add(mcpoauth.AccessTokenTTL)},
		{Hash: s.hash(refresh), GrantID: g.ID, Kind: mcpoauth.TokenRefresh, ExpiresAt: refreshExp},
	}
	return &TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(mcpoauth.AccessTokenTTL.Seconds()),
		RefreshToken: refresh,
		Scope:        mcpoauth.Join(g.Scopes),
	}, tokens, nil
}

// --- Revocation endpoint ---------------------------------------------------

// Revoke handles POST /oauth/revoke (RFC 7009): a token of the presenting
// client revokes its whole grant. Unknown tokens and other clients' tokens
// are ignored; the endpoint answers 200 either way (RFC 7009 §2.2).
func (s *Service) Revoke(ctx context.Context, raw, clientID string, actor Actor) {
	if raw == "" || clientID == "" {
		return
	}
	now := s.now()
	kind := mcpoauth.TokenAccess
	if strings.HasPrefix(raw, mcpoauth.RefreshTokenPrefix) {
		kind = mcpoauth.TokenRefresh
	}
	grant, _, err := s.grantByToken(ctx, raw, kind, now)
	if grant == nil || (err != nil && !errors.Is(err, mcpoauth.ErrRefreshReused)) || grant.Client.ClientID != clientID {
		return
	}
	if grant.RevokedAt != nil {
		return
	}
	if err := s.repo.RevokeGrant(ctx, grant.TenantID, grant.ID, mcpoauth.RevokedByClient, now); err != nil {
		s.log.Error("mcp oauth: revoke grant", "error", err.Error())
		return
	}
	s.logAudit(ctx, grant.TenantID.String(), grant.UserID.String(), actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPGrantRevoked, auditdom.ResourceTypeMCPGrant, grant.ID.String()).
			WithResourceName(grant.Client.Name).
			WithMessage("MCP connection revoked by "+grant.Client.Name).
			WithMetadata("client_id", grant.Client.ClientID).
			WithMetadata("reason", mcpoauth.RevokedByClient))
}

// --- Resource server -------------------------------------------------------

// Principal is the caller of an MCP request authenticated by an access token.
type Principal struct {
	GrantID    string
	TenantID   string
	UserID     string
	ClientID   string
	ClientName string
	Scopes     []mcpoauth.Scope
	// Permissions is what the request may do: the permissions of the
	// granted scopes the user still holds.
	Permissions []string
	// HeldAll and Held are what the user holds, scopes aside; the MCP
	// endpoint uses them to tell "ask for another scope" from "not allowed".
	HeldAll bool
	Held    []string
}

// ErrInvalidToken is every access-token failure (unknown, expired, revoked,
// another resource, membership gone). One error, logged with its reason.
var ErrInvalidToken = errors.New("invalid access token")

// AuthenticateAccessToken checks an MCP request's bearer token and returns
// its principal, with the permissions recomputed from the user's current
// access.
func (s *Service) AuthenticateAccessToken(ctx context.Context, raw, ip string) (*Principal, error) {
	if !strings.HasPrefix(raw, mcpoauth.AccessTokenPrefix) {
		return nil, ErrInvalidToken
	}
	now := s.now()
	grant, _, err := s.grantByToken(ctx, raw, mcpoauth.TokenAccess, now)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !grant.Active(now) || grant.Resource != s.endpoints.Resource {
		return nil, ErrInvalidToken
	}
	ok, err := s.members.IsActiveMember(ctx, grant.TenantID, grant.UserID)
	if err != nil || !ok {
		s.log.Debug("mcp oauth: token of an inactive membership", "grant_id", grant.ID.String())
		return nil, ErrInvalidToken
	}
	all, held, err := s.permissions.HeldPermissions(ctx, grant.TenantID, grant.UserID)
	if err != nil {
		return nil, ErrInvalidToken
	}
	scopePerms := mcpoauth.Permissions(grant.Scopes)
	effective := scopePerms
	if !all {
		effective = intersect(scopePerms, held)
	}
	if err := s.repo.TouchGrant(ctx, grant.TenantID, grant.ID, ip, now); err != nil {
		s.log.Debug("mcp oauth: touch grant", "error", err.Error())
	}
	return &Principal{
		GrantID:     grant.ID.String(),
		TenantID:    grant.TenantID.String(),
		UserID:      grant.UserID.String(),
		ClientID:    grant.Client.ClientID,
		ClientName:  grant.Client.Name,
		Scopes:      grant.Scopes,
		Permissions: effective,
		HeldAll:     all,
		Held:        held,
	}, nil
}

// --- helpers ---------------------------------------------------------------

// grantByToken looks a token up under the current pepper, then the previous
// ones (a key rotation must not sign every connected application out).
func (s *Service) grantByToken(ctx context.Context, raw string, kind mcpoauth.TokenKind, now time.Time) (*mcpoauth.Grant, string, error) {
	var lastErr error = mcpoauth.ErrNotFound
	for _, p := range append([]string{s.pepper}, s.oldPeppers...) {
		h := crypto.HashTokenPeppered(raw, p)
		g, err := s.repo.GetGrantByToken(ctx, h, kind, now)
		if err == nil || errors.Is(err, mcpoauth.ErrRefreshReused) {
			return g, h, err
		}
		lastErr = err
	}
	return nil, "", lastErr
}

func (s *Service) hash(raw string) string { return crypto.HashTokenPeppered(raw, s.pepper) }

// randomToken returns prefix + 256 random bits, base64url.
func randomToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// verifyPKCE checks an S256 code verifier against the stored challenge in
// constant time.
func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// withQuery adds parameters to a redirect URI, keeping its own query. Empty
// values are left out.
func withQuery(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func intersect(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, x := range b {
		set[x] = true
	}
	out := []string{}
	for _, x := range a {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}

func subset(a, b []mcpoauth.Scope) bool {
	set := make(map[mcpoauth.Scope]bool, len(b))
	for _, x := range b {
		set[x] = true
	}
	for _, x := range a {
		if !set[x] {
			return false
		}
	}
	return true
}

func idString(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func (s *Service) logAudit(ctx context.Context, tenantID, userID string, actor Actor, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, auditapp.AuditContext{
		TenantID: tenantID, ActorID: userID, ActorIP: actor.IP, UserAgent: actor.UserAgent, RequestID: actor.RequestID,
	}, event); err != nil {
		s.log.Warn("mcp oauth: audit", "error", err.Error())
	}
}
