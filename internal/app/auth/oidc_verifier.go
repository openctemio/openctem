package auth

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/api/pkg/logger"
)

// oidcVerifier verifies OIDC id_token signatures against a provider's published
// JWKS, caching keys per JWKS URL. It is safe for concurrent use.
//
// id_token verification is the defense that proves a token was minted by the
// expected IdP for *this* login flow: RS256 signature against the provider's
// JWKS, audience == our client_id, exp/nbf/iat (with leeway), the nonce we put
// in the authorize request, and a provider-specific issuer check.
type oidcVerifier struct {
	httpClient *http.Client
	logger     *logger.Logger
	leeway     time.Duration
	cacheTTL   time.Duration

	mu    sync.Mutex
	cache map[string]*jwksEntry // keyed by JWKS URL
	now   func() time.Time      // overridable in tests
}

type jwksEntry struct {
	keys      map[string]*rsa.PublicKey // kid -> key
	fetchedAt time.Time
}

func newOIDCVerifier(client *http.Client, log *logger.Logger) *oidcVerifier {
	return &oidcVerifier{
		httpClient: client,
		logger:     log,
		leeway:     2 * time.Minute,
		cacheTTL:   1 * time.Hour,
		cache:      make(map[string]*jwksEntry),
		now:        time.Now,
	}
}

// idTokenExpectations carries the per-flow checks applied to an id_token.
type idTokenExpectations struct {
	jwksURL  string
	audience string // must equal the client_id used in the flow
	nonce    string // must equal the id_token's nonce claim
	// validateIssuer is provider-specific because some issuers are
	// tenant-dependent (e.g. Entra's issuer embeds the directory id).
	validateIssuer func(issuer, tid string) error
}

// oidcClaims holds the standard + provider claims we read from an id_token.
type oidcClaims struct {
	Nonce string `json:"nonce"`
	TID   string `json:"tid"`
	Email string `json:"email"`
	jwtv5.RegisteredClaims
}

// verify validates the id_token and returns its claims. Every check is
// fail-closed: any failure returns an error and the caller must reject login.
func (v *oidcVerifier) verify(ctx context.Context, idToken string, exp idTokenExpectations) (*oidcClaims, error) {
	if strings.TrimSpace(idToken) == "" {
		return nil, errors.New("empty id_token")
	}
	if exp.nonce == "" {
		return nil, errors.New("missing expected nonce")
	}

	claims := &oidcClaims{}
	parser := jwtv5.NewParser(
		jwtv5.WithValidMethods([]string{"RS256"}),
		jwtv5.WithExpirationRequired(),
		jwtv5.WithLeeway(v.leeway),
		jwtv5.WithAudience(exp.audience),
	)

	keyFunc := func(t *jwtv5.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		return v.keyForKID(ctx, exp.jwksURL, kid)
	}

	if _, err := parser.ParseWithClaims(idToken, claims, keyFunc); err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	// Nonce binds the token to our authorize request (replay/injection guard).
	// Constant-time to avoid leaking the nonce via comparison timing.
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(exp.nonce)) != 1 {
		return nil, errors.New("id_token nonce mismatch")
	}

	if exp.validateIssuer != nil {
		if err := exp.validateIssuer(claims.Issuer, claims.TID); err != nil {
			return nil, err
		}
	}

	return claims, nil
}

// keyForKID returns the RSA public key for kid, fetching/refreshing the JWKS
// when the key is unknown or the cache has expired.
func (v *oidcVerifier) keyForKID(ctx context.Context, jwksURL, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("id_token missing kid header")
	}
	if key, ok := v.cachedKey(jwksURL, kid); ok {
		return key, nil
	}
	if err := v.refresh(ctx, jwksURL); err != nil {
		return nil, err
	}
	if key, ok := v.cachedKey(jwksURL, kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("no signing key for kid %q", kid)
}

func (v *oidcVerifier) cachedKey(jwksURL, kid string) (*rsa.PublicKey, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, ok := v.cache[jwksURL]
	if !ok || v.now().Sub(entry.fetchedAt) > v.cacheTTL {
		return nil, false
	}
	key, ok := entry.keys[kid]
	return key, ok
}

// refresh fetches and caches the JWKS at jwksURL.
func (v *oidcVerifier) refresh(ctx context.Context, jwksURL string) error {
	if jwksURL == "" {
		return errors.New("empty jwks url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("fetch jwks: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.cache[jwksURL] = &jwksEntry{keys: keys, fetchedAt: v.now()}
	v.mu.Unlock()
	return nil
}

// jwk is a single RSA signing key from a JWKS document.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func parseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	out := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pk, err := jwkToRSA(k.N, k.E)
		if err != nil {
			continue
		}
		out[k.Kid] = pk
	}
	if len(out) == 0 {
		return nil, errors.New("jwks contained no usable RSA signing keys")
	}
	return out, nil
}

func jwkToRSA(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("empty rsa key material")
	}
	e := new(big.Int).SetBytes(eBytes)
	// A public exponent never legitimately exceeds 32 bits; bound it before the
	// int conversion (gosec G115) and reject anything implausible.
	if e.BitLen() == 0 || e.BitLen() > 31 {
		return nil, errors.New("invalid rsa public exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
}

// entraIssuerValidator returns an issuer validator for Microsoft Entra ID. The
// v2 issuer is https://login.microsoftonline.com/{tid}/v2.0 where {tid} is the
// token's directory id; for single-tenant configs the directory must match the
// configured tenant, while multi-tenant authorities (common/organizations/
// consumers) accept any directory (the email domain allow-list still applies).
func entraIssuerValidator(configuredTenant string) func(issuer, tid string) error {
	return func(issuer, tid string) error {
		if tid == "" {
			return errors.New("id_token missing tid claim")
		}
		expected := "https://login.microsoftonline.com/" + tid + "/v2.0"
		if !strings.EqualFold(issuer, expected) {
			return errors.New("id_token issuer mismatch")
		}
		switch strings.ToLower(strings.TrimSpace(configuredTenant)) {
		case "", "common", "organizations", "consumers":
			return nil
		default:
			if !strings.EqualFold(tid, configuredTenant) {
				return errors.New("id_token tenant mismatch")
			}
			return nil
		}
	}
}
