package dpop

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const tokenURL = "https://openctem.example/oauth/token"

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

type signer struct {
	alg string
	key any
	jwk map[string]any
}

func newES256(t *testing.T) signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pad := func(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }
	return signer{alg: "ES256", key: k, jwk: map[string]any{
		"kty": "EC", "crv": "P-256", "x": b64.EncodeToString(pad(k.X.Bytes())), "y": b64.EncodeToString(pad(k.Y.Bytes())),
	}}
}

func newEdDSA(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{alg: "EdDSA", key: priv, jwk: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64.EncodeToString(pub)}}
}

func (s signer) proof(t *testing.T, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	method := jwt.GetSigningMethod(s.alg)
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = s.jwk
	for k, v := range header {
		if v == nil {
			delete(tok.Header, k)
		} else {
			tok.Header[k] = v
		}
	}
	out, err := tok.SignedString(s.key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func claims(extra map[string]any) jwt.MapClaims {
	c := jwt.MapClaims{"htm": "POST", "htu": tokenURL, "iat": now.Unix(), "jti": "j-1"}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func TestVerifyAcceptsBothAlgorithms(t *testing.T) {
	for _, s := range []signer{newES256(t), newEdDSA(t)} {
		p, err := Verify(s.proof(t, claims(nil), nil), Expect{Method: "POST", URL: tokenURL, Now: now})
		if err != nil {
			t.Fatalf("%s: %v", s.alg, err)
		}
		if p.JKT == "" || p.JTI != "j-1" {
			t.Fatalf("%s: proof %+v", s.alg, p)
		}
		// Same key, same thumbprint.
		p2, _ := Verify(s.proof(t, claims(map[string]any{"jti": "j-2"}), nil), Expect{Method: "POST", URL: tokenURL, Now: now})
		if p2.JKT != p.JKT {
			t.Fatalf("%s: thumbprint not stable", s.alg)
		}
	}
}

// RFC 7638 §3.1 example thumbprint for an RSA key is not applicable here;
// check the EC canonical form against a known vector instead.
func TestThumbprintKnownEd25519(t *testing.T) {
	// RFC 8037 appendix A.3: thumbprint of the example Ed25519 key.
	_, jkt, err := publicKey(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}, "EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	if jkt != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint %s", jkt)
	}
}

func TestVerifyRefusals(t *testing.T) {
	s := newES256(t)
	token := "octm_at_example"
	sum := sha256.Sum256([]byte(token))
	ath := b64.EncodeToString(sum[:])
	other := newEdDSA(t)
	cases := map[string]struct {
		proof  string
		expect Expect
	}{
		"wrong method": {s.proof(t, claims(map[string]any{"htm": "GET"}), nil), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"wrong url":    {s.proof(t, claims(map[string]any{"htu": "https://evil.example/oauth/token"}), nil), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"old":          {s.proof(t, claims(map[string]any{"iat": now.Add(-2 * time.Minute).Unix()}), nil), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"future":       {s.proof(t, claims(map[string]any{"iat": now.Add(2 * time.Minute).Unix()}), nil), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"no jti":       {s.proof(t, claims(map[string]any{"jti": nil}), nil), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"no iat":       {s.proof(t, claims(map[string]any{"iat": nil}), nil), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"typ":          {s.proof(t, claims(nil), map[string]any{"typ": "JWT"}), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"no jwk":       {s.proof(t, claims(nil), map[string]any{"jwk": nil}), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"private jwk":  {s.proof(t, claims(nil), map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": s.jwk["x"], "y": s.jwk["y"], "d": "AAAA"}}), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"key swapped":  {s.proof(t, claims(nil), map[string]any{"jwk": other.jwk}), Expect{Method: "POST", URL: tokenURL, Now: now}},
		"missing ath":  {s.proof(t, claims(nil), nil), Expect{Method: "POST", URL: tokenURL, Now: now, AccessToken: token}},
		"wrong ath":    {s.proof(t, claims(map[string]any{"ath": b64.EncodeToString([]byte("not the hash of this token"))}), nil), Expect{Method: "POST", URL: tokenURL, Now: now, AccessToken: token}},
		"garbage":      {"a.b.c", Expect{Method: "POST", URL: tokenURL, Now: now}},
		"empty":        {"", Expect{Method: "POST", URL: tokenURL, Now: now}},
	}
	for name, tc := range cases {
		if _, err := Verify(tc.proof, tc.expect); !errors.Is(err, ErrInvalidProof) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// alg none / HS256 are refused by the method list.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, claims(nil))
	hs.Header["typ"] = "dpop+jwt"
	hs.Header["jwk"] = s.jwk
	str, _ := hs.SignedString([]byte("secret"))
	if _, err := Verify(str, Expect{Method: "POST", URL: tokenURL, Now: now}); err == nil {
		t.Error("HS256 proof accepted")
	}
	// With the right ath it passes.
	if _, err := Verify(s.proof(t, claims(map[string]any{"ath": ath}), nil), Expect{Method: "POST", URL: tokenURL, Now: now, AccessToken: token}); err != nil {
		t.Errorf("valid ath refused: %v", err)
	}
}

func TestSameURL(t *testing.T) {
	for _, ok := range [][2]string{
		{"https://OpenCTEM.example/api/v1/mcp", "https://openctem.example/api/v1/mcp"},
		{"https://openctem.example:443/api/v1/mcp/", "https://openctem.example/api/v1/mcp"},
		{"https://openctem.example/api/v1/mcp?x=1", "https://openctem.example/api/v1/mcp"},
	} {
		if !sameURL(ok[0], ok[1]) {
			t.Errorf("%v differ", ok)
		}
	}
	for _, bad := range [][2]string{
		{"http://openctem.example/api/v1/mcp", "https://openctem.example/api/v1/mcp"},
		{"https://openctem.example/api/v1/mcp2", "https://openctem.example/api/v1/mcp"},
		{"https://openctem.example:8443/api/v1/mcp", "https://openctem.example/api/v1/mcp"},
		{"/api/v1/mcp", "https://openctem.example/api/v1/mcp"},
	} {
		if sameURL(bad[0], bad[1]) {
			t.Errorf("%v match", bad)
		}
	}
}
