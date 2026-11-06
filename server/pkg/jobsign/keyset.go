package jobsign

// Key sets (RFC-040 §5.6 point 2, K3): an offline root key signs a short,
// versioned, expiring list of the online signer keys a sensor may accept.
// Rotating or revoking an online key is a new key set with a higher
// version; no sensor is paired again. Format and ceremony:
// docs/architecture/job-signing.md ("Key sets and the offline root").

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
)

// KeySetPayloadType is the DSSE payload type of a key set.
const KeySetPayloadType = "application/vnd.openctem.keyset.v1+json"

// KeySetKind is the key set kind (v1).
const KeySetKind = "openctem.keyset/v1"

// Key set limits.
const (
	// MaxKeySetValidity caps not_after - issued_at.
	MaxKeySetValidity = 30 * 24 * time.Hour
	// MaxKeySetBytes caps a key set envelope (JSON).
	MaxKeySetBytes = 64 << 10
	// MaxKeySetKeys caps the online keys of one key set.
	MaxKeySetKeys = 16
)

// Key set refusal reasons (KeySetError.Reason). A sensor uses the same
// names.
const (
	KeySetReasonMalformed   = "malformed"
	KeySetReasonPayloadType = "payload_type"
	KeySetReasonKind        = "kind"
	KeySetReasonRoot        = "root"
	KeySetReasonSignature   = "bad_signature"
	KeySetReasonKeys        = "keys"
	KeySetReasonVersion     = "version"
	KeySetReasonValidity    = "validity"
	KeySetReasonExpired     = "expired"
	KeySetReasonNotYetValid = "not_yet_valid"
)

// KeySetError is a key set that is refused.
type KeySetError struct {
	Reason string
	Detail string
}

func (e *KeySetError) Error() string { return "key set refused (" + e.Reason + "): " + e.Detail }

func keySetErr(reason, format string, args ...any) error {
	return &KeySetError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// KeySet is the signed key set document. It is serialized once, field
// order as declared, and those bytes are the DSSE payload; a verifier
// parses the payload bytes it received and never re-encodes them.
type KeySet struct {
	Kind string `json:"kind"`
	// Version is strictly increasing across the key sets of one root; a
	// sensor never accepts a lower version than one it accepted before.
	Version  uint64    `json:"version"`
	IssuedAt time.Time `json:"issued_at"`
	// NotAfter is when the key set expires: at most MaxKeySetValidity
	// after IssuedAt.
	NotAfter time.Time `json:"not_after"`
	// Keys are the online signer keys a sensor accepts job signatures from.
	Keys []PublicKey `json:"keys"`
	// RootKeyID is the id of the root key that signs the key set; it is the
	// value a sensor pins.
	RootKeyID string `json:"root_keyid"`
	// RootPublicKey is the root's raw 32-byte Ed25519 key, standard base64,
	// so a sensor that pinned only RootKeyID can check the signature. Its
	// recomputed id must be RootKeyID.
	RootPublicKey string `json:"root_public_key"`
}

// HasKey reports whether the key set lists keyID.
func (ks *KeySet) HasKey(keyID string) bool {
	for _, k := range ks.Keys {
		if k.KeyID == keyID {
			return true
		}
	}
	return false
}

// SignKeySet builds and signs a key set with the root key: version >= 1,
// valid from issuedAt (truncated to the second, UTC) for validity (at most
// MaxKeySetValidity), listing keys (1 to MaxKeySetKeys, distinct, never the
// root itself). It returns the envelope (JSON) and the document.
func SignKeySet(root ed25519.PrivateKey, version uint64, issuedAt time.Time, validity time.Duration, keys []ed25519.PublicKey) ([]byte, *KeySet, error) {
	if len(root) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("key set: an Ed25519 root key is required")
	}
	rootPub, _ := root.Public().(ed25519.PublicKey)
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	ks := &KeySet{
		Kind: KeySetKind, Version: version, IssuedAt: issuedAt, NotAfter: issuedAt.Add(validity),
		Keys: make([]PublicKey, 0, len(keys)), RootKeyID: KeyID(rootPub),
		RootPublicKey: base64.StdEncoding.EncodeToString(rootPub),
	}
	for _, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			return nil, nil, keySetErr(KeySetReasonKeys, "a key is not a 32-byte Ed25519 key")
		}
		ks.Keys = append(ks.Keys, NewPublicKey(k))
	}
	if err := ks.check(); err != nil {
		return nil, nil, err
	}
	payload, err := json.Marshal(ks)
	if err != nil {
		return nil, nil, err
	}
	env, err := json.Marshal(scannertemplate.Envelope{
		PayloadType: KeySetPayloadType,
		Payload:     payload,
		Signatures: []scannertemplate.EnvelopeSignature{{
			KeyID: ks.RootKeyID,
			Sig:   ed25519.Sign(root, scannertemplate.PreAuthEncoding(KeySetPayloadType, payload)),
		}},
	})
	if err != nil {
		return nil, nil, err
	}
	return env, ks, nil
}

// check validates the document's own fields (not its signature, not the
// clock).
func (ks *KeySet) check() error {
	if ks.Kind != KeySetKind {
		return keySetErr(KeySetReasonKind, "kind %q, want %q", ks.Kind, KeySetKind)
	}
	if ks.Version == 0 {
		return keySetErr(KeySetReasonVersion, "version must be 1 or more")
	}
	if ks.IssuedAt.IsZero() || !ks.NotAfter.After(ks.IssuedAt) || ks.NotAfter.Sub(ks.IssuedAt) > MaxKeySetValidity {
		return keySetErr(KeySetReasonValidity, "not_after must be after issued_at and at most %s later", MaxKeySetValidity)
	}
	rootRaw, err := base64.StdEncoding.DecodeString(ks.RootPublicKey)
	if err != nil || len(rootRaw) != ed25519.PublicKeySize || KeyID(rootRaw) != ks.RootKeyID {
		return keySetErr(KeySetReasonRoot, "root_public_key is not the 32-byte Ed25519 key of root_keyid")
	}
	if len(ks.Keys) == 0 || len(ks.Keys) > MaxKeySetKeys {
		return keySetErr(KeySetReasonKeys, "a key set lists 1 to %d keys, not %d", MaxKeySetKeys, len(ks.Keys))
	}
	seen := map[string]bool{}
	for _, k := range ks.Keys {
		if _, err := k.Decode(); err != nil {
			return keySetErr(KeySetReasonKeys, "%v", err)
		}
		if seen[k.KeyID] {
			return keySetErr(KeySetReasonKeys, "key %s is listed twice", k.KeyID)
		}
		if k.KeyID == ks.RootKeyID {
			return keySetErr(KeySetReasonKeys, "the root key must stay offline: it cannot be an online key")
		}
		seen[k.KeyID] = true
	}
	return nil
}

// ParseKeySet checks a key set envelope's form and that it is signed by
// the root it names, and returns the document and its exact payload bytes.
// It does not check the clock or a pinned root: VerifyKeySet does.
func ParseKeySet(envelope []byte) (*KeySet, []byte, error) {
	if len(envelope) == 0 || len(envelope) > MaxKeySetBytes {
		return nil, nil, keySetErr(KeySetReasonMalformed, "envelope is empty or over %d bytes", MaxKeySetBytes)
	}
	var env scannertemplate.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, nil, keySetErr(KeySetReasonMalformed, "envelope: %v", err)
	}
	if env.PayloadType != KeySetPayloadType {
		return nil, nil, keySetErr(KeySetReasonPayloadType, "payload type %q, want %q", env.PayloadType, KeySetPayloadType)
	}
	var ks KeySet
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ks); err != nil {
		return nil, nil, keySetErr(KeySetReasonMalformed, "key set: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, keySetErr(KeySetReasonMalformed, "key set: trailing data")
	}
	if err := ks.check(); err != nil {
		return nil, nil, err
	}
	rootRaw, _ := base64.StdEncoding.DecodeString(ks.RootPublicKey)
	pae := scannertemplate.PreAuthEncoding(env.PayloadType, env.Payload)
	for _, s := range env.Signatures {
		if s.KeyID == ks.RootKeyID && ed25519.Verify(rootRaw, pae, s.Sig) {
			return &ks, env.Payload, nil
		}
	}
	return nil, nil, keySetErr(KeySetReasonSignature, "not signed by its root %s", ks.RootKeyID)
}

// VerifyKeySet checks a key set envelope against the pinned root key id
// (the trust anchor; "" accepts the root the key set names, for the signer's
// own sanity check only) and the clock: issued_at no later than now +
// MaxClockSkew, not_after later than now - MaxClockSkew. Version
// monotonicity is the caller's (it keeps the last accepted version).
func VerifyKeySet(envelope []byte, pinnedRoot string, now time.Time) (*KeySet, []byte, error) {
	ks, payload, err := ParseKeySet(envelope)
	if err != nil {
		return nil, nil, err
	}
	if pinnedRoot != "" && ks.RootKeyID != pinnedRoot {
		return nil, nil, keySetErr(KeySetReasonRoot, "signed by root %s, the pinned root is %s", ks.RootKeyID, pinnedRoot)
	}
	if ks.IssuedAt.After(now.Add(MaxClockSkew)) {
		return nil, nil, keySetErr(KeySetReasonNotYetValid, "issued at %s, after this clock (%s)",
			ks.IssuedAt.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if !ks.NotAfter.After(now.Add(-MaxClockSkew)) {
		return nil, nil, keySetErr(KeySetReasonExpired, "expired at %s", ks.NotAfter.Format(time.RFC3339))
	}
	return ks, payload, nil
}
