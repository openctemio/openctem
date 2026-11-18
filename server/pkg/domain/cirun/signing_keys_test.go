package cirun

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func testJWKS(t *testing.T, mutate func(keys []map[string]any) []map[string]any) string {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ek.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	keys := []map[string]any{
		{"kty": "RSA", "kid": "gitlab-1", "use": "sig", "alg": "RS256", "n": b64(rk.N.Bytes()), "e": b64(big.NewInt(int64(rk.E)).Bytes())},
		{"kty": "EC", "kid": "gitlab-2", "crv": "P-256", "x": b64(pt[1:33]), "y": b64(pt[33:])},
	}
	if mutate != nil {
		keys = mutate(keys)
	}
	doc, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return string(doc)
}

func gitlabTrust(source KeySource, keys string) TrustConfig {
	c := TrustConfig{TenantID: shared.NewID(), Name: "self-managed", Provider: ProviderGitLab,
		Issuer: "https://gitlab.example.com", Rules: Rules{Owners: []string{"acme"}}, KeySource: source, SigningKeys: keys}
	c.Normalize()
	return c
}

func TestTrustSigningKeysAccepted(t *testing.T) {
	doc := testJWKS(t, nil)
	c := gitlabTrust(KeySourcePasted, doc)
	if err := c.Validate(); err != nil {
		t.Fatalf("pasted keys refused: %v", err)
	}
	set, err := c.PastedKeys()
	if err != nil || set == nil {
		t.Fatalf("PastedKeys = %v, %v", set, err)
	}
	if got := strings.Join(c.SigningKeyIDs(), ","); got != "gitlab-1,gitlab-2" {
		t.Fatalf("kids = %q", got)
	}
	// Fetch mode ignores stored keys at verification time.
	c.KeySource = KeySourceFetch
	if set, err := c.PastedKeys(); set != nil || err != nil {
		t.Fatalf("fetch mode returned pasted keys: %v, %v", set, err)
	}
}

func TestTrustKeySourceDefaultsToFetch(t *testing.T) {
	c := gitlabTrust("", "  ")
	if c.KeySource != KeySourceFetch || c.SigningKeys != "" {
		t.Fatalf("normalized = %q %q", c.KeySource, c.SigningKeys)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("default configuration refused: %v", err)
	}
}

func TestTrustSigningKeysRefusals(t *testing.T) {
	set := func(k map[string]any, name string, v any) map[string]any { k[name] = v; return k }
	cases := map[string]struct {
		source KeySource
		keys   string
		want   string
	}{
		"unknown source":        {"sensor", "", "key_source"},
		"pasted without keys":   {KeySourcePasted, "", "paste the provider's signing keys"},
		"invalid json":          {KeySourcePasted, "{keys:", "valid JSON"},
		"empty key list":        {KeySourcePasted, `{"keys":[]}`, "no keys"},
		"invalid even in fetch": {KeySourceFetch, `{"keys":[]}`, "no keys"},
		"private d": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			k[0] = set(k[0], "d", "AQAB")
			return k
		}), "private key material"},
		"private qi": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			k[0] = set(k[0], "qi", "AQAB")
			return k
		}), "private key material"},
		"symmetric k": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			return append(k, map[string]any{"kty": "oct", "kid": "h", "k": "c2VjcmV0"})
		}), "private key material"},
		"duplicate kid": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			k[1]["kid"] = "gitlab-1"
			return k
		}), "appears twice"},
		"missing kid": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			delete(k[1], "kid")
			return k
		}), "no key id"},
		"use enc": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			k[0]["use"] = "enc"
			return k
		}), "signing keys"},
		"rsa alg RS384": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			k[0]["alg"] = "RS384"
			return k
		}), "RS256"},
		"ec alg ES512": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			k[1]["alg"] = "ES512"
			return k
		}), "ES256"},
		"ec curve P-384": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			k[1]["crv"] = "P-384"
			return k
		}), "P-256"},
		"too many keys": {KeySourcePasted, testJWKS(t, func(k []map[string]any) []map[string]any {
			out := []map[string]any{}
			for i := range 11 {
				c := map[string]any{}
				for n, v := range k[0] {
					c[n] = v
				}
				c["kid"] = "k" + string(rune('a'+i))
				out = append(out, c)
			}
			return out
		}), "at most 10"},
		"too large": {KeySourcePasted, `{"keys":[],"x":"` + strings.Repeat("a", 64<<10) + `"}`, "64 KiB"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := gitlabTrust(tc.source, tc.keys)
			err := c.Validate()
			if err == nil {
				t.Fatal("configuration accepted")
			}
			if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q, want a validation error saying %q", err, tc.want)
			}
		})
	}
}

// A stored document that no longer parses fails closed: no key set, an error.
func TestTrustPastedKeysFailClosed(t *testing.T) {
	c := TrustConfig{KeySource: KeySourcePasted, SigningKeys: "{"}
	if set, err := c.PastedKeys(); err == nil || set != nil {
		t.Fatalf("broken stored keys gave %v, %v", set, err)
	}
	if ids := c.SigningKeyIDs(); len(ids) != 0 {
		t.Fatalf("kids of a broken document = %v", ids)
	}
}
