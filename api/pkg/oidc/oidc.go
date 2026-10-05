// Package oidc is a small OpenID Connect relying-party client: discovery,
// the authorization-code exchange with PKCE, and id_token verification against
// the provider's JWKS. It is used by the platform administrators' identity
// provider (RFC-022 revision 4).
//
// Every outbound request goes through the http.Client given to NewClient
// (production: httpsec.SafeHTTPClient) after the URL guard (production:
// httpsec.ValidateURL), because the issuer is configured at runtime.
package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	leeway    = 2 * time.Minute
	jwksTTL   = time.Hour
	userAgent = "OpenCTEM-OIDC/1"
	// jwksMinRefresh is the shortest interval between two fetches of one
	// JWKS: a token naming an unknown kid cannot make every request fetch the
	// provider's keys again.
	jwksMinRefresh = 30 * time.Second
)

// signingMethods are the accepted id_token algorithms. HMAC and "none" are
// never accepted.
var signingMethods = []string{"RS256", "RS384", "RS512", "PS256", "ES256"}

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

type jwksEntry struct {
	keys      map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	fetchedAt time.Time
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

// Expectations are the per-flow id_token checks.
type Expectations struct {
	Issuer   string
	ClientID string
	Nonce    string
	JWKSURI  string
}

// Claims are the id_token claims the console uses.
type Claims struct {
	Email         string   `json:"email"`
	EmailVerified flexBool `json:"email_verified"`
	// XMSEdov is Entra ID's "email domain owner verified" optional claim; Entra
	// does not send email_verified.
	XMSEdov flexBool `json:"xms_edov"`
	Name    string   `json:"name"`
	Nonce   string   `json:"nonce"`
	ACR     string   `json:"acr"`
	AMR     []string `json:"amr"`
	AZP     string   `json:"azp"`
	jwtv5.RegisteredClaims
}

// EmailIsVerified reports whether the provider asserts the email is verified.
func (c *Claims) EmailIsVerified() bool { return bool(c.EmailVerified) || bool(c.XMSEdov) }

// flexBool accepts true/false and "true"/"false" (some providers send strings).
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true":
		*b = true
	default:
		*b = false
	}
	return nil
}

// VerifyIDToken verifies the signature against the JWKS and the standard
// claims. Every failure is an error; the caller must refuse the sign-in.
func (c *Client) VerifyIDToken(ctx context.Context, raw string, exp Expectations) (*Claims, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("empty id_token")
	}
	if exp.Nonce == "" || exp.Issuer == "" || exp.ClientID == "" {
		return nil, errors.New("incomplete expectations")
	}
	claims := &Claims{}
	parser := jwtv5.NewParser(
		jwtv5.WithValidMethods(signingMethods),
		jwtv5.WithExpirationRequired(),
		jwtv5.WithIssuedAt(),
		jwtv5.WithLeeway(leeway),
		jwtv5.WithAudience(exp.ClientID),
		jwtv5.WithIssuer(exp.Issuer),
		jwtv5.WithTimeFunc(c.now),
	)
	keyFunc := func(t *jwtv5.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, err := c.key(ctx, exp.JWKSURI, kid)
		if err != nil {
			return nil, err
		}
		switch t.Method.(type) {
		case *jwtv5.SigningMethodRSA, *jwtv5.SigningMethodRSAPSS:
			if _, ok := key.(*rsa.PublicKey); !ok {
				return nil, errors.New("key type does not match alg")
			}
		case *jwtv5.SigningMethodECDSA:
			if _, ok := key.(*ecdsa.PublicKey); !ok {
				return nil, errors.New("key type does not match alg")
			}
		default:
			return nil, errors.New("unsupported alg")
		}
		return key, nil
	}
	if _, err := parser.ParseWithClaims(raw, claims, keyFunc); err != nil {
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
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(exp.Nonce)) != 1 {
		return nil, errors.New("id_token: nonce mismatch")
	}
	return claims, nil
}

// key returns the JWKS key for kid, refetching the JWKS once when the key is
// unknown or the cache is stale. Without a kid, a JWKS with a single key is used.
func (c *Client) key(ctx context.Context, jwksURI, kid string) (any, error) {
	if k, ok := c.cachedKey(jwksURI, kid); ok {
		return k, nil
	}
	if c.recentlyFetched(jwksURI) {
		return nil, fmt.Errorf("no signing key for kid %q", kid)
	}
	if err := c.refreshJWKS(ctx, jwksURI); err != nil {
		return nil, err
	}
	if k, ok := c.cachedKey(jwksURI, kid); ok {
		return k, nil
	}
	return nil, fmt.Errorf("no signing key for kid %q", kid)
}

// recentlyFetched reports whether the JWKS was fetched within
// jwksMinRefresh (and is cached): an unknown kid then fails without a fetch.
func (c *Client) recentlyFetched(jwksURI string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.jwks[jwksURI]
	return ok && c.now().Sub(e.fetchedAt) < jwksMinRefresh
}

func (c *Client) cachedKey(jwksURI, kid string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.jwks[jwksURI]
	if !ok || c.now().Sub(e.fetchedAt) > jwksTTL {
		return nil, false
	}
	if kid == "" {
		if len(e.keys) == 1 {
			for _, k := range e.keys {
				return k, true
			}
		}
		return nil, false
	}
	k, ok := e.keys[kid]
	return k, ok
}

func (c *Client) refreshJWKS(ctx context.Context, jwksURI string) error {
	body, err := c.get(ctx, jwksURI)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.jwks[jwksURI] = &jwksEntry{keys: keys, fetchedAt: c.now()}
	c.mu.Unlock()
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWKS(body []byte) (map[string]any, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("jwks: invalid document")
	}
	out := map[string]any{}
	for i, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = fmt.Sprintf("#%d", i)
		}
		switch k.Kty {
		case "RSA":
			if pk, err := rsaKey(k.N, k.E); err == nil {
				out[kid] = pk
			}
		case "EC":
			if pk, err := ecKey(k.Crv, k.X, k.Y); err == nil {
				out[kid] = pk
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no usable signing keys")
	}
	return out, nil
}

func rsaKey(nStr, eStr string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil || len(n) == 0 {
		return nil, errors.New("bad modulus")
	}
	eb, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil || len(eb) == 0 {
		return nil, errors.New("bad exponent")
	}
	e := new(big.Int).SetBytes(eb)
	if e.BitLen() == 0 || e.BitLen() > 31 {
		return nil, errors.New("bad exponent")
	}
	pk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(e.Int64())}
	if pk.N.BitLen() < 2048 {
		return nil, errors.New("rsa key too small")
	}
	return pk, nil
}

func ecKey(crv, xStr, yStr string) (*ecdsa.PublicKey, error) {
	if crv != "P-256" {
		return nil, errors.New("unsupported curve")
	}
	x, err := ecCoordinate(xStr)
	if err != nil {
		return nil, err
	}
	y, err := ecCoordinate(yStr)
	if err != nil {
		return nil, err
	}
	// SEC 1 uncompressed point; the parser rejects points not on the curve.
	b := make([]byte, 0, 1+2*p256CoordinateSize)
	b = append(b, 4)
	b = append(b, x...)
	b = append(b, y...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
}

const p256CoordinateSize = 32

// ecCoordinate decodes a JWK P-256 coordinate and left-pads it to 32 bytes.
func ecCoordinate(raw string) ([]byte, error) {
	v, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(v) == 0 || len(v) > p256CoordinateSize {
		return nil, errors.New("invalid P-256 coordinate length")
	}
	out := make([]byte, p256CoordinateSize)
	copy(out[p256CoordinateSize-len(v):], v)
	return out, nil
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
