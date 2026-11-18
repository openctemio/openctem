package oidc

// Pasted signing keys: a JWKS document an administrator copied from the CI
// provider, used instead of fetching the provider's keys. A verification with
// a pasted key set never makes a network call
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Limits on a pasted JWKS document.
const (
	MaxPastedJWKSSize = 64 << 10
	MaxPastedKeys     = 10
	maxPastedKIDLen   = 200

	algRS256 = "RS256"
	algES256 = "ES256"
)

// ErrPastedKeyUnknown means the token names a key id that is not in the
// pasted key set: the provider probably rotated its keys.
var ErrPastedKeyUnknown = errors.New("token signing key is not among the pasted keys")

// privateJWKParams are the JWK members that carry private or symmetric key
// material (RFC 7518 sections 6.2.2, 6.3.2 and 6.4.1). A pasted document with
// any of them is refused: it is a secret, and a symmetric key could never
// verify a CI token anyway.
var privateJWKParams = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// PastedKey is one key of a pasted set, as shown to an administrator.
type PastedKey struct {
	KID string `json:"kid"`
	// Alg is the algorithm the key verifies: RS256 or ES256.
	Alg string `json:"alg"`
}

// StaticKeySet is a parsed, validated pasted key set.
type StaticKeySet struct {
	keys map[string]staticKey
}

type staticKey struct {
	key any // *rsa.PublicKey | *ecdsa.PublicKey
	alg string
}

// ParseStaticJWKS validates a pasted JWKS document and returns its keys. It
// accepts {"keys":[...]} with 1 to MaxPastedKeys keys, each with a unique
// kid, use absent or "sig", and either an RSA key of at least 2048 bits (alg
// RS256 or absent) or an EC P-256 key (alg ES256 or absent). A key carrying
// private material is refused. Every error message is safe to show the
// administrator who pasted the document.
func ParseStaticJWKS(doc []byte) (*StaticKeySet, error) {
	if len(bytes.TrimSpace(doc)) == 0 {
		return nil, errors.New("the signing keys document is empty")
	}
	if len(doc) > MaxPastedJWKSSize {
		return nil, fmt.Errorf("the signing keys document is larger than %d KiB", MaxPastedJWKSSize>>10)
	}
	var raw struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(doc, &raw); err != nil {
		return nil, errors.New(`the signing keys are not valid JSON: paste the whole document, an object with a "keys" list`)
	}
	if len(raw.Keys) == 0 {
		return nil, errors.New(`the signing keys document has no keys: paste the whole document, an object with a "keys" list`)
	}
	if len(raw.Keys) > MaxPastedKeys {
		return nil, fmt.Errorf("the signing keys document has %d keys; at most %d are accepted", len(raw.Keys), MaxPastedKeys)
	}
	set := &StaticKeySet{keys: make(map[string]staticKey, len(raw.Keys))}
	for i, members := range raw.Keys {
		k, err := parsePastedKey(members)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i+1, err)
		}
		if _, dup := set.keys[k.kid]; dup {
			return nil, fmt.Errorf("key %d: the key id %q appears twice", i+1, k.kid)
		}
		set.keys[k.kid] = staticKey{key: k.key, alg: k.alg}
	}
	return set, nil
}

type parsedPastedKey struct {
	kid, alg string
	key      any
}

func parsePastedKey(members map[string]json.RawMessage) (parsedPastedKey, error) {
	for _, p := range privateJWKParams {
		if _, ok := members[p]; ok {
			return parsedPastedKey{}, fmt.Errorf("it carries private key material (%q): paste only the public keys "+
				"the provider publishes", p)
		}
	}
	str := func(name string) (string, error) {
		v, ok := members[name]
		if !ok {
			return "", nil
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return "", fmt.Errorf("%q must be a string", name)
		}
		return s, nil
	}
	var k jwk
	var alg string
	for name, dst := range map[string]*string{"kty": &k.Kty, "kid": &k.Kid, "use": &k.Use, "n": &k.N, "e": &k.E,
		"crv": &k.Crv, "x": &k.X, "y": &k.Y, "alg": &alg} {
		s, err := str(name)
		if err != nil {
			return parsedPastedKey{}, err
		}
		*dst = s
	}
	switch {
	case k.Kid == "":
		return parsedPastedKey{}, errors.New("it has no key id (kid)")
	case len(k.Kid) > maxPastedKIDLen || strings.ContainsFunc(k.Kid, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return parsedPastedKey{}, errors.New("its key id (kid) is not valid")
	case k.Use != "" && k.Use != "sig":
		return parsedPastedKey{}, fmt.Errorf("its use is %q; only signing keys (use \"sig\") are accepted", k.Use)
	}
	out := parsedPastedKey{kid: k.Kid}
	switch k.Kty {
	case "RSA":
		if alg != "" && alg != algRS256 {
			return parsedPastedKey{}, fmt.Errorf("its algorithm %q is not accepted; an RSA key must be RS256", alg)
		}
		pk, err := rsaKey(k.N, k.E)
		if err != nil {
			return parsedPastedKey{}, fmt.Errorf("it is not a valid RSA public key of at least 2048 bits (%v)", err)
		}
		out.key, out.alg = pk, algRS256
	case "EC":
		if alg != "" && alg != algES256 {
			return parsedPastedKey{}, fmt.Errorf("its algorithm %q is not accepted; an EC key must be ES256", alg)
		}
		pk, err := ecKey(k.Crv, k.X, k.Y)
		if err != nil {
			return parsedPastedKey{}, errors.New("it is not a valid P-256 public key")
		}
		out.key, out.alg = pk, algES256
	default:
		return parsedPastedKey{}, fmt.Errorf("its key type %q is not accepted; only RSA and EC P-256 keys are", k.Kty)
	}
	return out, nil
}

// Keys lists the set's key ids and algorithms, sorted by kid.
func (s *StaticKeySet) Keys() []PastedKey {
	if s == nil {
		return nil
	}
	out := make([]PastedKey, 0, len(s.keys))
	for kid, k := range s.keys {
		out = append(out, PastedKey{KID: kid, Alg: k.alg})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KID < out[j].KID })
	return out
}

// KIDs lists the set's key ids, sorted.
func (s *StaticKeySet) KIDs() []string {
	keys := s.Keys()
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.KID
	}
	return out
}

// lookup returns the key for kid and the one algorithm it verifies. A token
// without a kid uses the only key of a one-key set.
func (s *StaticKeySet) lookup(kid string) (staticKey, bool) {
	if s == nil {
		return staticKey{}, false
	}
	if kid == "" {
		if len(s.keys) == 1 {
			for _, k := range s.keys {
				return k, true
			}
		}
		return staticKey{}, false
	}
	k, ok := s.keys[kid]
	return k, ok
}

// algorithms are the algorithms the set's keys verify.
func (s *StaticKeySet) algorithms() []string {
	var out []string
	for _, k := range s.keys {
		if !slices.Contains(out, k.alg) {
			out = append(out, k.alg)
		}
	}
	return out
}
