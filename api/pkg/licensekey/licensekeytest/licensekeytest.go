// Package licensekeytest signs license files for tests.
//
// TEST KEYS ONLY. Every key here is derived from a public seed, so anyone
// can sign with it: no build may ever trust these roots (pkg/licensekey's
// roots_test.go fails if one is embedded, and tests/unit refuses an import
// of this package from production code).
package licensekeytest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/licensekey"
)

func key(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("openctem licensekeytest PUBLIC TEST KEY, never trusted: " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// Root is the test root (signs key sets).
func Root() ed25519.PrivateKey { return key("root") }

// OtherRoot is a second test root (an untrusted or next root).
func OtherRoot() ed25519.PrivateKey { return key("other-root") }

// IssuingKey returns test issuing key n (signs licenses).
func IssuingKey(n int) ed25519.PrivateKey { return key(fmt.Sprintf("issuing-%d", n)) }

// Public returns the public half of k.
func Public(k ed25519.PrivateKey) ed25519.PublicKey {
	pub, _ := k.Public().(ed25519.PublicKey)
	return pub
}

// Verifier trusts the test root only.
func Verifier() *licensekey.Verifier { return licensekey.NewVerifier(Public(Root())) }

// Claims returns valid claims: an enterprise license granting every
// registered key, valid from now-1d for one year, 14 days of grace.
func Claims(now time.Time) licensekey.Claims {
	grace := 14
	now = now.UTC().Truncate(time.Second)
	return licensekey.Claims{
		Schema: licensekey.Schema, ID: "lic_TEST0001", CustomerID: "cus_TEST0001",
		Type: licensekey.TypeEnterprise, Licensee: licensekey.Licensee{Name: "Example Org"},
		IssuedAt: now.Add(-24 * time.Hour), NotBefore: now.Add(-24 * time.Hour), ExpiresAt: now.Add(365 * 24 * time.Hour),
		GraceDays: &grace, Entitlements: limits.GrantKeys(),
		Meters: map[string]int64{"assets": 10000},
		Issuer: licensekey.Issuer{Name: "Example Issuer", PortalURL: "https://portal.example.test"},
	}
}

// KeySet describes a key set to sign.
type KeySet struct {
	Root     ed25519.PrivateKey
	Version  uint64
	IssuedAt time.Time
	NotAfter time.Time
	Keys     []ed25519.PublicKey
	Revoked  licensekey.Revocations
}

// DefaultKeySet is version 1 by the test root listing issuing key 0, valid
// two years around now.
func DefaultKeySet(now time.Time) KeySet {
	now = now.UTC().Truncate(time.Second)
	return KeySet{Root: Root(), Version: 1, IssuedAt: now.Add(-30 * 24 * time.Hour),
		NotAfter: now.Add(2 * 365 * 24 * time.Hour), Keys: []ed25519.PublicKey{Public(IssuingKey(0))}}
}

// KeySetPayload returns the key set JSON payload (unsigned).
func (k KeySet) KeySetPayload() []byte {
	root := Public(k.Root)
	ks := licensekey.KeySet{Kind: licensekey.KeySetKind, Version: k.Version, IssuedAt: k.IssuedAt, NotAfter: k.NotAfter,
		Revoked: k.Revoked, RootKeyID: jobsign.KeyID(root), RootPublicKey: base64.StdEncoding.EncodeToString(root)}
	for _, p := range k.Keys {
		ks.Keys = append(ks.Keys, jobsign.NewPublicKey(p))
	}
	b, err := json.Marshal(ks)
	if err != nil {
		panic(err)
	}
	return b
}

// Sign returns the signed key set envelope.
func (k KeySet) Sign() []byte {
	return Envelope(k.Root, licensekey.KeySetPayloadType, k.KeySetPayload())
}

// Envelope signs payload as a DSSE envelope.
func Envelope(priv ed25519.PrivateKey, payloadType string, payload []byte) []byte {
	b, err := feedsign.Sign(priv, payloadType, payload)
	if err != nil {
		panic(err)
	}
	return b
}

// ClaimsPayload returns the JSON payload of c.
func ClaimsPayload(c licensekey.Claims) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return b
}

// Assemble builds a license file from two envelopes.
func Assemble(license, keyset []byte) []byte {
	b, err := json.Marshal(licensekey.File{License: license, KeySet: keyset})
	if err != nil {
		panic(err)
	}
	return b
}

// File signs c with issuing key 0 under the default key set.
func File(now time.Time, c licensekey.Claims) []byte {
	return Assemble(Envelope(IssuingKey(0), licensekey.PayloadType, ClaimsPayload(c)), DefaultKeySet(now).Sign())
}

// DefaultKeySetKeyID is the key id of issuing key 0.
func DefaultKeySetKeyID() string { return jobsign.KeyID(Public(IssuingKey(0))) }
