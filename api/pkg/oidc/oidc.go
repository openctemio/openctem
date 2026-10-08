// Package oidc is the API's one OpenID Connect and JWT verification core:
// discovery, the authorization-code exchange with PKCE, the JWKS key cache and
// token verification (VerifyJWT), with the per-flow rules on top: sign-in
// id_tokens (VerifyIDToken: tenant SSO, Microsoft sign-in, the platform
// administrators' identity provider), CI workload tokens
// (VerifyWorkloadToken) and, through pkg/keycloak, the external OIDC
// provider's access tokens. Trust (which issuers, which audiences) stays with
// each flow's own configuration.
//
// Every outbound request goes through the http.Client given to NewClient
// (production: httpsec.SafeHTTPClient) after the URL guard (production:
// httpsec.ValidateURL).
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Token endpoint client authentication methods (OIDC Core 9).
const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
)

const (
	maxBody   = 1 << 20
	userAgent = "OpenCTEM-OIDC/1"
)

// Client performs OIDC requests. Safe for concurrent use.
type Client struct {
	http     *http.Client
	checkURL func(string) error
	now      func() time.Time

	mu   sync.Mutex
	jwks map[string]*jwksEntry
	// discovery caches the jwks_uri of workload-token issuers (workload.go).
	discovery map[string]discoveredJWKS
}

// NewClient returns a client using httpClient for every request and checkURL
// to refuse a URL before it is dialed.
func NewClient(httpClient *http.Client, checkURL func(string) error) *Client {
	if checkURL == nil {
		checkURL = func(string) error { return nil }
	}
	return &Client{http: httpClient, checkURL: checkURL, now: time.Now, jwks: map[string]*jwksEntry{}}
}

// Discovery is the subset of the provider metadata the client uses.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	// TokenEndpointAuthMethods as advertised; empty means client_secret_basic.
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	// TokenEndpointAuthMethod is the method this client will use.
	TokenEndpointAuthMethod string `json:"-"`
}

// ValidateIssuer checks the shape of a configured issuer: https, a host, no
// userinfo, query or fragment.
func ValidateIssuer(issuer string) error {
	return requireHTTPS(issuer, false)
}

func requireHTTPS(raw string, allowQuery bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("malformed URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("must use https")
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("must have a host and no credentials")
	}
	if !allowQuery && (u.RawQuery != "" || u.Fragment != "") {
		return fmt.Errorf("must not have a query or fragment")
	}
	if u.Fragment != "" {
		return fmt.Errorf("must not have a fragment")
	}
	return nil
}

// Discover fetches {issuer}/.well-known/openid-configuration. The document's
// issuer must equal issuer exactly (OIDC Discovery 4.3) and every endpoint
// must be https.
func (c *Client) Discover(ctx context.Context, issuer string) (*Discovery, error) {
	if err := ValidateIssuer(issuer); err != nil {
		return nil, fmt.Errorf("issuer %w", err)
	}
	body, err := c.get(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("discovery: invalid document")
	}
	if d.Issuer != issuer {
		return nil, fmt.Errorf("discovery: issuer %q does not match the configured issuer", d.Issuer)
	}
	for name, ep := range map[string]string{
		"authorization_endpoint": d.AuthorizationEndpoint,
		"token_endpoint":         d.TokenEndpoint,
		"jwks_uri":               d.JWKSURI,
	} {
		if ep == "" {
			return nil, fmt.Errorf("discovery: %s is missing", name)
		}
		if err := requireHTTPS(ep, true); err != nil {
			return nil, fmt.Errorf("discovery: %s %w", name, err)
		}
	}
	switch {
	case len(d.TokenEndpointAuthMethods) == 0 || contains(d.TokenEndpointAuthMethods, AuthMethodClientSecretBasic):
		d.TokenEndpointAuthMethod = AuthMethodClientSecretBasic
	case contains(d.TokenEndpointAuthMethods, AuthMethodClientSecretPost):
		d.TokenEndpointAuthMethod = AuthMethodClientSecretPost
	default:
		return nil, fmt.Errorf("discovery: the provider supports neither client_secret_basic nor client_secret_post")
	}
	return &d, nil
}

// AuthorizationRequest is the authorization-code request.
type AuthorizationRequest struct {
	ClientID      string
	RedirectURI   string
	Scopes        []string
	State         string
	Nonce         string
	CodeChallenge string // S256
	ACRValues     []string
}

// AuthorizationURL builds the authorization request URL, keeping any query the
// endpoint already has.
func AuthorizationURL(endpoint string, r AuthorizationRequest) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", r.ClientID)
	q.Set("redirect_uri", r.RedirectURI)
	q.Set("scope", strings.Join(r.Scopes, " "))
	q.Set("state", r.State)
	q.Set("nonce", r.Nonce)
	q.Set("code_challenge", r.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	if len(r.ACRValues) > 0 {
		q.Set("acr_values", strings.Join(r.ACRValues, " "))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeRequest is the token request for an authorization code.
type ExchangeRequest struct {
	TokenEndpoint string
	AuthMethod    string
	ClientID      string
	ClientSecret  string
	Code          string
	RedirectURI   string
	CodeVerifier  string
}

// Exchange redeems the code and returns the id_token.
func (c *Client) Exchange(ctx context.Context, r ExchangeRequest) (string, error) {
	if err := c.checkURL(r.TokenEndpoint); err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", r.Code)
	form.Set("redirect_uri", r.RedirectURI)
	form.Set("code_verifier", r.CodeVerifier)
	if r.AuthMethod == AuthMethodClientSecretPost {
		form.Set("client_id", r.ClientID)
		form.Set("client_secret", r.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if r.AuthMethod != AuthMethodClientSecretPost {
		// RFC 6749 2.3.1: form-urlencode both parts before base64.
		req.SetBasicAuth(url.QueryEscape(r.ClientID), url.QueryEscape(r.ClientSecret))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", fmt.Errorf("token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return "", fmt.Errorf("token endpoint returned %d (%s)", resp.StatusCode, e.Error)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return "", errors.New("token response has no id_token")
	}
	return tok.IDToken, nil
}

// Expectations are the sign-in flow's id_token checks.
type Expectations struct {
	// Issuer is the exact iss. Set exactly one of Issuer and IssuerRule.
	Issuer string
	// IssuerRule checks iss when it depends on a claim (EntraIssuer).
	IssuerRule func(*Claims) error
	ClientID   string
	Nonce      string
	// SkipNonce omits the nonce check. Only for a confidential client's
	// authorization-code flow, where the id_token comes server to server from
	// the token endpoint and never through the browser, so the injection the
	// nonce defends against is not possible. Never for an SSO flow that sent
	// a nonce.
	SkipNonce bool
	JWKSURI   string
	// MaxAuthAge, when positive, requires auth_time no older than this: the
	// request asked the provider to authenticate the user again (max_age=0).
	MaxAuthAge time.Duration
}

// Claims are the id_token claims the sign-in flows read.
type Claims struct {
	Email         string   `json:"email"`
	EmailVerified FlexBool `json:"email_verified"`
	// XMSEdov is Entra ID's "email domain owner verified" optional claim; Entra
	// does not send email_verified. It is the defense against a directory
	// that sets someone else's address as a user's mail.
	XMSEdov FlexBool `json:"xms_edov"`
	Name    string   `json:"name"`
	Nonce   string   `json:"nonce"`
	ACR     string   `json:"acr"`
	AMR     []string `json:"amr"`
	AZP     string   `json:"azp"`
	// TID is the Entra directory id; EntraIssuer checks it against iss.
	TID string `json:"tid"`
	// OID is the Entra user's object id: the same for every application in
	// the directory, unlike sub, which is pairwise per application.
	OID string `json:"oid"`
	// SID is the provider's session id (OIDC back-channel logout).
	SID string `json:"sid"`
	// AuthTime is when the provider last authenticated the user.
	AuthTime *jwtv5.NumericDate `json:"auth_time,omitempty"`
	jwtv5.RegisteredClaims
}

// EmailIsVerified reports whether the provider asserts the email is verified.
func (c *Claims) EmailIsVerified() bool { return bool(c.EmailVerified) || bool(c.XMSEdov) }

// FlexBool accepts true/false and "true"/"false" (some providers send strings).
type FlexBool bool

// UnmarshalJSON reads a JSON boolean or its string spelling; anything else is false.
func (b *FlexBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true":
		*b = true
	default:
		*b = false
	}
	return nil
}

// signInLeeway is the clock skew tolerated on an id_token.
const signInLeeway = 2 * time.Minute

// VerifyIDToken verifies an id_token with the shared core (VerifyJWT) and the
// sign-in rules: iat and sub present, azp when present (and required with
// several audiences) equal to the client, the nonce of this flow, the
// provider's issuer rule, and auth_time when a fresh authentication was asked
// for. Every failure is an error; the caller must refuse the sign-in.
func (c *Client) VerifyIDToken(ctx context.Context, raw string, exp Expectations) (*Claims, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("empty id_token")
	}
	if exp.ClientID == "" || (exp.Nonce == "" && !exp.SkipNonce) ||
		(exp.Issuer == "") == (exp.IssuerRule == nil) {
		return nil, errors.New("incomplete expectations")
	}
	claims := &Claims{}
	if err := c.VerifyJWT(ctx, raw, claims, TokenPolicy{
		JWKSURI:               exp.JWKSURI,
		Issuer:                exp.Issuer,
		IssuerCheckedByCaller: exp.IssuerRule != nil,
		Audience:              exp.ClientID,
		Leeway:                signInLeeway,
	}); err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	if claims.IssuedAt == nil {
		return nil, errors.New("id_token: iat is missing")
	}
	if claims.Subject == "" {
		return nil, errors.New("id_token: sub is missing")
	}
	// OIDC Core 3.1.3.7: with several audiences, azp must be present and be us.
	if len(claims.Audience) > 1 && claims.AZP != exp.ClientID {
		return nil, errors.New("id_token: azp does not match the client")
	}
	if claims.AZP != "" && claims.AZP != exp.ClientID {
		return nil, errors.New("id_token: azp does not match the client")
	}
	if !exp.SkipNonce && subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(exp.Nonce)) != 1 {
		return nil, errors.New("id_token: nonce mismatch")
	}
	if exp.IssuerRule != nil {
		if err := exp.IssuerRule(claims); err != nil {
			return nil, fmt.Errorf("id_token: %w", err)
		}
	}
	if exp.MaxAuthAge > 0 {
		if claims.AuthTime == nil {
			return nil, errors.New("id_token: auth_time is missing although a fresh authentication was requested")
		}
		age := c.now().Sub(claims.AuthTime.Time)
		if age > exp.MaxAuthAge+signInLeeway || age < -signInLeeway {
			return nil, errors.New("id_token: the provider did not authenticate the user again")
		}
	}
	return claims, nil
}

func (c *Client) get(ctx context.Context, rawURL string) ([]byte, error) {
	if err := c.checkURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

// NewPKCE returns an RFC 7636 verifier and its S256 challenge.
func NewPKCE() (verifier, challenge string, err error) {
	verifier, err = RandomString(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// RandomString returns n random bytes, base64url-encoded.
func RandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
