// Package dpop verifies OAuth 2.0 Demonstrating Proof of Possession proofs
// (RFC 9449): a JWT the client signs with a private key for each request,
// so a token bound to that key is useless to anyone who only copied the
// token. Used by the MCP authorization server and resource server
// (docs/rfcs/RFC-062-mcp-authorization.md §9).
package dpop

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Accepted signature algorithms.
var Algorithms = []string{"ES256", "EdDSA"} //nolint:gochecknoglobals // fixed algorithm list

// Bounds of a proof.
const (
	// MaxSkew is how far a proof's iat may be from the server clock.
	MaxSkew = 60 * time.Second
	// ReplayWindow is how long a jti must be remembered: any older proof
	// fails the iat check anyway.
	ReplayWindow = 2 * MaxSkew
	maxProofLen  = 4096
	maxJTILen    = 128
)

// ErrInvalidProof is every proof failure; the wrapped text says why (for
// logs, never for the client).
var ErrInvalidProof = errors.New("invalid DPoP proof")

var b64 = base64.RawURLEncoding

// Proof is a verified proof.
type Proof struct {
	// JKT is the RFC 7638 SHA-256 thumbprint of the proof's public key.
	JKT string
	// JTI is the proof's unique id (to be remembered for ReplayWindow).
	JTI string
	IAT time.Time
}

// Expect is what the proof must say.
type Expect struct {
	Method string
	URL    string
	// AccessToken, when set, must be hashed into the proof's ath claim
	// (requests to the resource server).
	AccessToken string
	Now         time.Time
}

func fail(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidProof, fmt.Sprintf(format, a...))
}

// Verify checks a DPoP proof (the DPoP header value) against e.
func Verify(proof string, e Expect) (*Proof, error) {
	if proof == "" || len(proof) > maxProofLen || strings.Count(proof, ".") != 2 {
		return nil, fail("malformed")
	}
	var jkt string
	parser := jwt.NewParser(jwt.WithValidMethods(Algorithms), jwt.WithoutClaimsValidation())
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(proof, claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != "dpop+jwt" {
			return nil, fail("typ must be dpop+jwt")
		}
		raw, ok := t.Header["jwk"].(map[string]any)
		if !ok {
			return nil, fail("no jwk header")
		}
		key, thumb, kerr := publicKey(raw, t.Method.Alg())
		if kerr != nil {
			return nil, kerr
		}
		jkt = thumb
		return key, nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidProof) {
			return nil, err
		}
		return nil, fail("signature: %v", err)
	}
	if htm, _ := claims["htm"].(string); htm != e.Method {
		return nil, fail("htm does not match")
	}
	htu, _ := claims["htu"].(string)
	if !sameURL(htu, e.URL) {
		return nil, fail("htu does not match")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" || len(jti) > maxJTILen {
		return nil, fail("jti missing or too long")
	}
	iatF, ok := claims["iat"].(float64)
	if !ok {
		return nil, fail("iat missing")
	}
	iat := time.Unix(int64(iatF), 0)
	if d := e.Now.Sub(iat); d > MaxSkew || d < -MaxSkew {
		return nil, fail("iat outside the allowed window")
	}
	if e.AccessToken != "" {
		sum := sha256.Sum256([]byte(e.AccessToken))
		if ath, _ := claims["ath"].(string); ath != b64.EncodeToString(sum[:]) {
			return nil, fail("ath does not match the access token")
		}
	}
	return &Proof{JKT: jkt, JTI: jti, IAT: iat}, nil
}

// publicKey reads a public JWK for alg and returns it with its thumbprint.
// A JWK carrying private key material is refused.
func publicKey(jwk map[string]any, alg string) (any, string, error) {
	if _, has := jwk["d"]; has {
		return nil, "", fail("jwk carries a private key")
	}
	str := func(k string) string { s, _ := jwk[k].(string); return s }
	switch alg {
	case "ES256":
		if str("kty") != "EC" || str("crv") != "P-256" {
			return nil, "", fail("ES256 needs an EC P-256 key")
		}
		xb, err1 := b64.DecodeString(str("x"))
		yb, err2 := b64.DecodeString(str("y"))
		if err1 != nil || err2 != nil || len(xb) != 32 || len(yb) != 32 {
			return nil, "", fail("bad EC coordinates")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) { //nolint:staticcheck // explicit point validation of untrusted input
			return nil, "", fail("EC point not on the curve")
		}
		// RFC 7638 §3.2: required members, lexicographic order.
		canon := `{"crv":"P-256","kty":"EC","x":"` + str("x") + `","y":"` + str("y") + `"}`
		sum := sha256.Sum256([]byte(canon))
		return pub, b64.EncodeToString(sum[:]), nil
	case "EdDSA":
		if str("kty") != "OKP" || str("crv") != "Ed25519" {
			return nil, "", fail("EdDSA needs an OKP Ed25519 key")
		}
		xb, err := b64.DecodeString(str("x"))
		if err != nil || len(xb) != ed25519.PublicKeySize {
			return nil, "", fail("bad Ed25519 key")
		}
		canon := `{"crv":"Ed25519","kty":"OKP","x":"` + str("x") + `"}`
		sum := sha256.Sum256([]byte(canon))
		return ed25519.PublicKey(xb), b64.EncodeToString(sum[:]), nil
	}
	return nil, "", fail("unsupported alg")
}

// sameURL compares an htu claim with the request URL (RFC 9449 §4.3): no
// query or fragment, scheme and host case-insensitive, default ports and a
// trailing slash ignored.
func sameURL(htu, want string) bool {
	a, err1 := url.Parse(htu)
	b, err2 := url.Parse(want)
	if err1 != nil || err2 != nil || a.Host == "" {
		return false
	}
	norm := func(u *url.URL) string {
		host := strings.ToLower(u.Hostname())
		port := u.Port()
		scheme := strings.ToLower(u.Scheme)
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			port = ""
		}
		if port != "" {
			host += ":" + port
		}
		return scheme + "://" + host + strings.TrimSuffix(u.EscapedPath(), "/")
	}
	return norm(a) == norm(b)
}
