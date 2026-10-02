package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	"github.com/openctemio/api/pkg/logger"
)

const (
	testKID      = "test-key-1"
	testTenantID = "11111111-1111-1111-1111-111111111111"
	testClientID = "client-abc"
	testNonce    = "nonce-xyz"
)

func testIssuer(tid string) string {
	return "https://login.microsoftonline.com/" + tid + "/v2.0"
}

// jwksServer serves a JWKS document for the given public key under testKID.
func jwksServer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := map[string]any{
		"keys": []map[string]string{
			{"kty": "RSA", "kid": testKID, "use": "sig", "n": n, "e": e},
		},
	}
	body, _ := json.Marshal(doc)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

// signIDToken mints an RS256 id_token with testKID in the header.
func signIDToken(t *testing.T, key *rsa.PrivateKey, claims oidcClaims) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return signed
}

func validClaims() oidcClaims {
	return oidcClaims{
		Nonce: testNonce,
		TID:   testTenantID,
		Email: "user@example.com",
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    testIssuer(testTenantID),
			Audience:  jwtv5.ClaimStrings{testClientID},
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(time.Now()),
		},
	}
}

func newTestVerifier(t *testing.T) *oidcVerifier {
	t.Helper()
	return newOIDCVerifier(&http.Client{Timeout: 5 * time.Second}, logger.NewNop())
}

func entraExpectations(jwksURL string) idTokenExpectations {
	return idTokenExpectations{
		jwksURL:        jwksURL,
		audience:       testClientID,
		nonce:          testNonce,
		validateIssuer: entraIssuerValidator(testTenantID),
	}
}

func TestOIDCVerify_ValidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	idToken := signIDToken(t, key, validClaims())

	claims, err := v.verify(context.Background(), idToken, entraExpectations(srv.URL))
	if err != nil {
		t.Fatalf("verify returned error for a valid token: %v", err)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", claims.Email)
	}
}

func TestOIDCVerify_NonceMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	c := validClaims()
	c.Nonce = "attacker-nonce"
	idToken := signIDToken(t, key, c)

	if _, err := v.verify(context.Background(), idToken, entraExpectations(srv.URL)); err == nil {
		t.Fatal("expected error for nonce mismatch, got nil")
	}
}

func TestOIDCVerify_WrongAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	c := validClaims()
	c.Audience = jwtv5.ClaimStrings{"some-other-client"}
	idToken := signIDToken(t, key, c)

	if _, err := v.verify(context.Background(), idToken, entraExpectations(srv.URL)); err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
}

func TestOIDCVerify_Expired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	c := validClaims()
	// Well outside the 2-minute leeway.
	c.ExpiresAt = jwtv5.NewNumericDate(time.Now().Add(-30 * time.Minute))
	c.IssuedAt = jwtv5.NewNumericDate(time.Now().Add(-60 * time.Minute))
	idToken := signIDToken(t, key, c)

	if _, err := v.verify(context.Background(), idToken, entraExpectations(srv.URL)); err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestOIDCVerify_WrongSigningKey(t *testing.T) {
	signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwksKey, _ := rsa.GenerateKey(rand.Reader, 2048) // JWKS publishes a different key
	srv := jwksServer(t, &jwksKey.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	idToken := signIDToken(t, signKey, validClaims())

	if _, err := v.verify(context.Background(), idToken, entraExpectations(srv.URL)); err == nil {
		t.Fatal("expected error for signature mismatch, got nil")
	}
}

func TestOIDCVerify_IssuerMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	c := validClaims()
	c.Issuer = "https://login.microsoftonline.com/evil/v2.0" // does not match tid
	idToken := signIDToken(t, key, c)

	if _, err := v.verify(context.Background(), idToken, entraExpectations(srv.URL)); err == nil {
		t.Fatal("expected error for issuer mismatch, got nil")
	}
}

func TestOIDCVerify_SingleTenantDirectoryMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	// Token from a different (consistent) directory: iss matches its own tid,
	// but our config is pinned to testTenantID, so it must be rejected.
	otherTID := "22222222-2222-2222-2222-222222222222"
	c := validClaims()
	c.TID = otherTID
	c.Issuer = testIssuer(otherTID)
	idToken := signIDToken(t, key, c)

	if _, err := v.verify(context.Background(), idToken, entraExpectations(srv.URL)); err == nil {
		t.Fatal("expected error for single-tenant directory mismatch, got nil")
	}
}

func TestOIDCVerify_MultiTenantAcceptsAnyDirectory(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	otherTID := "33333333-3333-3333-3333-333333333333"
	c := validClaims()
	c.TID = otherTID
	c.Issuer = testIssuer(otherTID)
	idToken := signIDToken(t, key, c)

	exp := idTokenExpectations{
		jwksURL:        srv.URL,
		audience:       testClientID,
		nonce:          testNonce,
		validateIssuer: entraIssuerValidator("common"), // multi-tenant authority
	}
	if _, err := v.verify(context.Background(), idToken, exp); err != nil {
		t.Fatalf("multi-tenant verify rejected a consistent token: %v", err)
	}
}

func TestOIDCVerify_RejectsNoneAlg(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	v := newTestVerifier(t)
	// Forge an unsigned token (alg=none) — must be rejected by WithValidMethods.
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodNone, validClaims())
	tok.Header["kid"] = testKID
	idToken, err := tok.SignedString(jwtv5.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}

	if _, err := v.verify(context.Background(), idToken, entraExpectations(srv.URL)); err == nil {
		t.Fatal("expected error for alg=none token, got nil")
	}
}

func TestOIDCVerify_EmptyTokenAndNonce(t *testing.T) {
	v := newTestVerifier(t)
	if _, err := v.verify(context.Background(), "", entraExpectations("http://unused")); err == nil {
		t.Fatal("expected error for empty id_token")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idToken := signIDToken(t, key, validClaims())
	exp := entraExpectations("http://unused")
	exp.nonce = ""
	if _, err := v.verify(context.Background(), idToken, exp); err == nil {
		t.Fatal("expected error for empty expected nonce")
	}
}

func TestEntraIssuerValidator(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		issuer     string
		tid        string
		wantErr    bool
	}{
		{"single-tenant match", testTenantID, testIssuer(testTenantID), testTenantID, false},
		{"single-tenant dir mismatch", testTenantID, testIssuer("other"), "other", true},
		{"issuer/tid inconsistent", testTenantID, testIssuer("x"), testTenantID, true},
		{"missing tid", testTenantID, testIssuer(testTenantID), "", true},
		{"common accepts any", "common", testIssuer("anydir"), "anydir", false},
		{"empty accepts any", "", testIssuer("anydir"), "anydir", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := entraIssuerValidator(tc.configured)(tc.issuer, tc.tid)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	body := []byte(`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","n":"` + n + `","e":"` + e + `"}]}`)

	keys, err := parseJWKS(body)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if _, ok := keys["k1"]; !ok {
		t.Error("expected key k1 in parsed JWKS")
	}

	if _, err := parseJWKS([]byte(`{"keys":[]}`)); err == nil {
		t.Error("expected error for JWKS with no usable keys")
	}
	if _, err := parseJWKS([]byte(`not json`)); err == nil {
		t.Error("expected error for malformed JWKS")
	}
}

func TestProviderJWKSURL(t *testing.T) {
	// Mirrors AuthEndpoints' tenant defaulting.
	cases := map[string]string{
		"":           "https://login.microsoftonline.com/common/discovery/v2.0/keys",
		testTenantID: "https://login.microsoftonline.com/" + testTenantID + "/discovery/v2.0/keys",
	}
	for tid, want := range cases {
		got := identityproviderdom.ProviderEntraID.JWKSURL(tid)
		if got != want {
			t.Errorf("JWKSURL(%q) = %q, want %q", tid, got, want)
		}
	}
	if got := identityproviderdom.ProviderOkta.JWKSURL(""); got != "" {
		t.Errorf("Okta JWKSURL with empty tenant = %q, want empty", got)
	}
}
