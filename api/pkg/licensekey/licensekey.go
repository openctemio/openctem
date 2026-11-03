// Package licensekey verifies the signed license file of a self-managed
// installation, offline, and computes its state at an effective time
// (design: docs/rfcs/RFC-145-enterprise-license-and-entitlements.md).
//
// A license file holds two DSSE envelopes (Ed25519): a key set signed by a
// root compiled into this build (roots.go, never overridable by environment
// or configuration), and the license claims signed by an issuing key listed
// in that key set. A license only adds grant keys from the registry in
// pkg/domain/limits; nothing here can deny or cap a Community feature.
//
// The package is pure: no database, no clock, no network. The caller passes
// the stored key-set high-water mark, the revocations of the newest key set
// it has seen, the installation id and the effective time.
package licensekey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Format constants. The schema stays v1 until 1.0.
const (
	Schema            = "openctem.io/license/v1"
	PayloadType       = "application/vnd.openctem.license+json"
	KeySetPayloadType = "application/vnd.openctem.license.keyset+json"
	KeySetKind        = "openctem.license.keyset/v1"

	// MaxFileBytes bounds the license file (JSON form, after base64 decoding).
	MaxFileBytes = 64 << 10
	// maxInputBytes bounds the raw input: the base64 form of MaxFileBytes
	// plus room for line breaks.
	maxInputBytes = (MaxFileBytes+2)/3*4 + 4<<10

	// MaxKeySetKeys bounds the issuing keys of one key set.
	MaxKeySetKeys = 8
	// MaxKeySetValidity bounds a key set's not_after - issued_at.
	MaxKeySetValidity = 3*365*24*time.Hour + 24*time.Hour
	// MaxTerm bounds a license's expires_at - not_before.
	MaxTerm = MaxKeySetValidity
	// MaxGraceDays bounds grace_days.
	MaxGraceDays = 90
	// ExpiringWindow is how long before expires_at a license is expiring.
	ExpiringWindow = 30 * 24 * time.Hour

	maxSignatures  = 4
	maxRevocations = 1024
)

// Verification errors. Reason maps each to a stable reason code (audit).
var (
	ErrTooLarge           = errors.New("license file is too large")
	ErrMalformed          = errors.New("license file is malformed")
	ErrNoTrustedRoot      = errors.New("this build trusts no license root")
	ErrUntrustedRoot      = errors.New("key set is not signed by a trusted root")
	ErrBadSignature       = errors.New("bad signature")
	ErrKeySetRollback     = errors.New("key set rolled back")
	ErrRevoked            = errors.New("license or issuing key is revoked")
	ErrInvalidClaims      = errors.New("license claims are invalid")
	ErrUnknownEntitlement = errors.New("license names an unknown entitlement")
	ErrBindingMismatch    = errors.New("license is bound to other installations")
)

// Reason returns the stable reason code of a verification error ("" for nil).
func Reason(err error) string {
	for _, r := range []struct {
		err  error
		code string
	}{
		{ErrTooLarge, "too_large"}, {ErrMalformed, "malformed"}, {ErrNoTrustedRoot, "no_trusted_root"},
		{ErrUntrustedRoot, "untrusted_root"}, {ErrBadSignature, "bad_signature"},
		{ErrKeySetRollback, "keyset_rollback"}, {ErrRevoked, "revoked"}, {ErrInvalidClaims, "invalid_claims"},
		{ErrUnknownEntitlement, "unknown_entitlement"}, {ErrBindingMismatch, "binding_mismatch"},
	} {
		if errors.Is(err, r.err) {
			return r.code
		}
	}
	if err != nil {
		return "invalid"
	}
	return ""
}

// File is the license file: two DSSE envelopes. Unknown keys are refused.
type File struct {
	License json.RawMessage `json:"license"`
	KeySet  json.RawMessage `json:"keyset"`
}

// Revocations lists revoked license ids and issuing key ids. A key set
// carries the ones its issuer knows of; the newest key set an installation
// has seen revokes for every license it verifies later.
type Revocations struct {
	LicenseIDs []string `json:"license_ids,omitempty"`
	KeyIDs     []string `json:"key_ids,omitempty"`
}

func (r Revocations) hasLicense(id string) bool { return contains(r.LicenseIDs, id) }
func (r Revocations) hasKey(id string) bool     { return contains(r.KeyIDs, id) }

// KeySet lists the issuing keys a root allows.
type KeySet struct {
	Kind          string              `json:"kind"`
	Version       uint64              `json:"version"`
	IssuedAt      time.Time           `json:"issued_at"`
	NotAfter      time.Time           `json:"not_after"`
	Keys          []jobsign.PublicKey `json:"keys"`
	Revoked       Revocations         `json:"revoked"`
	RootKeyID     string              `json:"root_keyid"`
	RootPublicKey string              `json:"root_public_key"`
}

// License is a verified license.
type License struct {
	Claims
	// File is the license file in its JSON form: what is stored.
	File []byte
	// KeyID is the issuing key that signed the claims.
	KeyID string
	// KeySet is the key set the file carried (its version is the next
	// high-water mark, its revocations apply to later verifications).
	KeySet KeySet
}

// Options are the stored inputs of a verification.
type Options struct {
	// MinKeySetVersion is the highest key-set version verified before; an
	// older key set is a rollback.
	MinKeySetVersion uint64
	// Revoked are the revocations of the newest key set seen before.
	Revoked Revocations
	// InstallationID is this installation's id; a bound license must list it.
	InstallationID string
}

// envelope is a DSSE envelope, decoded strictly.
type envelope = scannertemplate.Envelope

// Verifier verifies license files against a fixed set of roots.
type Verifier struct {
	roots      map[string]ed25519.PublicKey
	minVersion uint64
	revoked    Revocations
}

// Default returns the verifier of this build: the roots compiled into
// roots.go and nothing else. It is the only verifier production code uses.
func Default() *Verifier {
	v := &Verifier{roots: map[string]ed25519.PublicKey{}, minVersion: embeddedMinKeySetVersion, revoked: embeddedRevoked}
	for _, r := range embeddedRoots {
		raw, err := base64.StdEncoding.DecodeString(r)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue // roots_test.go fails the build on such an entry
		}
		v.roots[jobsign.KeyID(raw)] = ed25519.PublicKey(raw)
	}
	return v
}

// NewVerifier returns a verifier trusting the given roots. Tests and the
// issuer's own tooling only: tests/unit refuses a call from production code,
// so a deployment can never be pointed at another root.
func NewVerifier(roots ...ed25519.PublicKey) *Verifier {
	v := &Verifier{roots: map[string]ed25519.PublicKey{}, minVersion: embeddedMinKeySetVersion}
	for _, r := range roots {
		if len(r) == ed25519.PublicKeySize {
			v.roots[jobsign.KeyID(r)] = r
		}
	}
	return v
}

// RootKeyIDs lists the key ids of the trusted roots.
func (v *Verifier) RootKeyIDs() []string {
	out := make([]string, 0, len(v.roots))
	for id := range v.roots {
		out = append(out, id)
	}
	return out
}

// Verify checks a license file (JSON or one-line base64) and returns the
// license. It does not look at the clock: the state comes from StateAt.
func (v *Verifier) Verify(input []byte, opts Options) (*License, error) {
	if len(v.roots) == 0 {
		return nil, ErrNoTrustedRoot
	}
	raw, err := decodeInput(input)
	if err != nil {
		return nil, err
	}
	var f File
	if err := decodeStrict(raw, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(f.License) == 0 || len(f.KeySet) == 0 {
		return nil, fmt.Errorf("%w: license and keyset are required", ErrMalformed)
	}
	ks, err := v.verifyKeySet(f.KeySet, opts.MinKeySetVersion)
	if err != nil {
		return nil, err
	}
	env, err := openEnvelope(f.License, PayloadType)
	if err != nil {
		return nil, err
	}
	revoked := func(keyID string) bool {
		return ks.Revoked.hasKey(keyID) || opts.Revoked.hasKey(keyID) || v.revoked.hasKey(keyID)
	}
	signer, sawRevoked := "", false
	for _, k := range ks.Keys {
		pub, err := k.Decode()
		if err != nil || !feedsign.VerifiedBy(env, pub) {
			continue
		}
		if revoked(k.KeyID) {
			sawRevoked = true
			continue
		}
		signer = k.KeyID
		break
	}
	switch {
	case signer == "" && sawRevoked:
		return nil, fmt.Errorf("%w: issuing key", ErrRevoked)
	case signer == "":
		return nil, fmt.Errorf("%w: license is not signed by a key of the key set", ErrBadSignature)
	}
	var c Claims
	if err := decodeStrict(env.Payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if ks.Revoked.hasLicense(c.ID) || opts.Revoked.hasLicense(c.ID) || v.revoked.hasLicense(c.ID) {
		return nil, fmt.Errorf("%w: license %s", ErrRevoked, c.ID)
	}
	if c.IssuedAt.Before(ks.IssuedAt.Add(-feedsign.MaxClockSkew)) || c.ExpiresAt.After(ks.NotAfter) {
		return nil, fmt.Errorf("%w: license term outside its key set", ErrInvalidClaims)
	}
	if !c.BoundTo(opts.InstallationID) {
		return nil, ErrBindingMismatch
	}
	return &License{Claims: c, File: raw, KeyID: signer, KeySet: *ks}, nil
}

func (v *Verifier) verifyKeySet(raw []byte, minVersion uint64) (*KeySet, error) {
	env, err := openEnvelope(raw, KeySetPayloadType)
	if err != nil {
		return nil, err
	}
	var ks KeySet
	if err := decodeStrict(env.Payload, &ks); err != nil {
		return nil, fmt.Errorf("%w: key set: %v", ErrMalformed, err)
	}
	root, trusted := v.roots[ks.RootKeyID]
	if !trusted {
		return nil, fmt.Errorf("%w: %s", ErrUntrustedRoot, ks.RootKeyID)
	}
	if ks.RootPublicKey != base64.StdEncoding.EncodeToString(root) {
		return nil, fmt.Errorf("%w: root_public_key is not the trusted root", ErrUntrustedRoot)
	}
	if !feedsign.VerifiedBy(env, root) {
		return nil, fmt.Errorf("%w: key set", ErrBadSignature)
	}
	floor := max(minVersion, v.minVersion)
	switch {
	case ks.Kind != KeySetKind:
		return nil, fmt.Errorf("%w: key set kind %q", ErrMalformed, ks.Kind)
	case ks.Version == 0:
		return nil, fmt.Errorf("%w: key set version 0", ErrMalformed)
	case ks.Version < floor:
		return nil, fmt.Errorf("%w: version %d is below %d", ErrKeySetRollback, ks.Version, floor)
	case ks.IssuedAt.IsZero() || !ks.NotAfter.After(ks.IssuedAt) || ks.NotAfter.Sub(ks.IssuedAt) > MaxKeySetValidity:
		return nil, fmt.Errorf("%w: key set validity", ErrMalformed)
	case len(ks.Keys) == 0 || len(ks.Keys) > MaxKeySetKeys:
		return nil, fmt.Errorf("%w: key set lists 1 to %d keys", ErrMalformed, MaxKeySetKeys)
	case len(ks.Revoked.LicenseIDs) > maxRevocations || len(ks.Revoked.KeyIDs) > maxRevocations:
		return nil, fmt.Errorf("%w: key set revokes too many ids", ErrMalformed)
	}
	seen := map[string]bool{}
	for _, k := range ks.Keys {
		if _, err := k.Decode(); err != nil || k.KeyID == ks.RootKeyID || seen[k.KeyID] {
			return nil, fmt.Errorf("%w: key set key %s", ErrMalformed, k.KeyID)
		}
		seen[k.KeyID] = true
	}
	return &ks, nil
}

// openEnvelope decodes a DSSE envelope of the expected payload type, with a
// bounded number of signatures (each costs a verification).
func openEnvelope(raw []byte, payloadType string) (*envelope, error) {
	var env envelope
	if err := decodeStrict(raw, &env); err != nil {
		return nil, fmt.Errorf("%w: envelope: %v", ErrMalformed, err)
	}
	switch {
	case env.PayloadType != payloadType:
		return nil, fmt.Errorf("%w: payload type %q, want %q", ErrMalformed, env.PayloadType, payloadType)
	case len(env.Payload) == 0:
		return nil, fmt.Errorf("%w: empty payload", ErrMalformed)
	case len(env.Signatures) == 0 || len(env.Signatures) > maxSignatures:
		return nil, fmt.Errorf("%w: 1 to %d signatures", ErrMalformed, maxSignatures)
	}
	return &env, nil
}

// decodeInput returns the JSON form of the input: as given, or decoded from
// base64 (standard alphabet, padded or not, line breaks allowed).
func decodeInput(input []byte) ([]byte, error) {
	if len(input) > maxInputBytes {
		return nil, ErrTooLarge
	}
	s := bytes.TrimSpace(input)
	if len(s) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrMalformed)
	}
	if s[0] != '{' {
		compact := bytes.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, s)
		enc := base64.StdEncoding
		if len(compact)%4 != 0 {
			enc = base64.RawStdEncoding
		}
		if enc.DecodedLen(len(compact)) > MaxFileBytes+3 {
			return nil, ErrTooLarge
		}
		dec := make([]byte, enc.DecodedLen(len(compact)))
		n, err := enc.Decode(dec, compact)
		if err != nil {
			return nil, fmt.Errorf("%w: neither JSON nor base64", ErrMalformed)
		}
		if n > MaxFileBytes {
			return nil, ErrTooLarge
		}
		s = bytes.TrimSpace(dec[:n])
		if len(s) == 0 || s[0] != '{' {
			return nil, fmt.Errorf("%w: base64 does not hold a JSON object", ErrMalformed)
		}
	}
	if len(s) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	return s, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
