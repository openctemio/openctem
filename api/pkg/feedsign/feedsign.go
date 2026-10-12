// Package feedsign verifies the signed bundles that platform feeds publish
// (the program feed of RFC-065 §16; the same envelope as the vulnerability
// feed of RFC-066 §5.5): DSSE envelopes signed with Ed25519, an offline root
// that signs an expiring, versioned key set, and online keys from that key
// set that sign the bundle's pointer and manifests. Each feed names its own
// payload types; the cryptography and the checks are shared.
package feedsign

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
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Bounds.
const (
	MaxKeySetValidity = 180 * 24 * time.Hour
	MaxKeySetBytes    = 64 << 10
	MaxKeySetKeys     = 8
	MaxClockSkew      = 5 * time.Minute
)

// KeySet lists the online keys an offline root allows.
type KeySet struct {
	Kind          string              `json:"kind"`
	Version       uint64              `json:"version"`
	IssuedAt      time.Time           `json:"issued_at"`
	NotAfter      time.Time           `json:"not_after"`
	Keys          []jobsign.PublicKey `json:"keys"`
	RootKeyID     string              `json:"root_keyid"`
	RootPublicKey string              `json:"root_public_key"`
}

// KeySetType names a feed's key set: its payload type and kind.
type KeySetType struct {
	PayloadType string
	Kind        string
}

// VerifyKeySet checks a key set envelope: signed by its root, the root is
// the pinned one, valid at now, version not below minVersion (a key set
// cannot be rolled back to bring a revoked key back).
func VerifyKeySet(envelope []byte, typ KeySetType, pinnedRoot string, minVersion uint64, now time.Time) (*KeySet, error) {
	env, err := Open(envelope, typ.PayloadType, MaxKeySetBytes)
	if err != nil {
		return nil, err
	}
	var ks KeySet
	if err := DecodeStrict(env.Payload, &ks); err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	switch {
	case ks.Kind != typ.Kind:
		return nil, fmt.Errorf("key set: kind %q", ks.Kind)
	case ks.Version == 0 || ks.Version < minVersion:
		return nil, fmt.Errorf("key set: version %d is below %d (rolled back)", ks.Version, minVersion)
	case pinnedRoot == "" || ks.RootKeyID != pinnedRoot:
		return nil, fmt.Errorf("key set: signed by root %s, the pinned root is %q", ks.RootKeyID, pinnedRoot)
	case ks.IssuedAt.IsZero() || !ks.NotAfter.After(ks.IssuedAt) || ks.NotAfter.Sub(ks.IssuedAt) > MaxKeySetValidity:
		return nil, errors.New("key set: validity")
	case ks.IssuedAt.After(now.Add(MaxClockSkew)) || !ks.NotAfter.After(now.Add(-MaxClockSkew)):
		return nil, fmt.Errorf("key set: not valid at %s", now.UTC().Format(time.RFC3339))
	case len(ks.Keys) == 0 || len(ks.Keys) > MaxKeySetKeys:
		return nil, fmt.Errorf("key set: 1 to %d keys", MaxKeySetKeys)
	}
	root, err := base64.StdEncoding.DecodeString(ks.RootPublicKey)
	if err != nil || len(root) != ed25519.PublicKeySize || jobsign.KeyID(root) != ks.RootKeyID {
		return nil, errors.New("key set: root_public_key is not the key of root_keyid")
	}
	if !VerifiedBy(env, root) {
		return nil, errors.New("key set: bad root signature")
	}
	for _, k := range ks.Keys {
		if _, err := k.Decode(); err != nil || k.KeyID == ks.RootKeyID {
			return nil, fmt.Errorf("key set: key %s", k.KeyID)
		}
	}
	return &ks, nil
}

// Open decodes an envelope of the expected payload type and size.
func Open(envelope []byte, payloadType string, maxBytes int) (*scannertemplate.Envelope, error) {
	if len(envelope) == 0 || len(envelope) > maxBytes {
		return nil, fmt.Errorf("envelope empty or over %d bytes", maxBytes)
	}
	var env scannertemplate.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	if env.PayloadType != payloadType {
		return nil, fmt.Errorf("payload type %q, want %q", env.PayloadType, payloadType)
	}
	return &env, nil
}

// VerifiedBy reports whether pub signed the envelope.
func VerifiedBy(env *scannertemplate.Envelope, pub ed25519.PublicKey) bool {
	id := jobsign.KeyID(pub)
	pae := scannertemplate.PreAuthEncoding(env.PayloadType, env.Payload)
	for _, s := range env.Signatures {
		if s.KeyID == id && ed25519.Verify(pub, pae, s.Sig) {
			return true
		}
	}
	return false
}

// VerifyWith checks that a key of the key set signed the envelope and
// decodes its payload strictly into v.
func VerifyWith(ks *KeySet, raw []byte, payloadType string, maxBytes int, v any) error {
	env, err := Open(raw, payloadType, maxBytes)
	if err != nil {
		return err
	}
	for _, k := range ks.Keys {
		if pub, err := k.Decode(); err == nil && VerifiedBy(env, pub) {
			return DecodeStrict(env.Payload, v)
		}
	}
	return errors.New("not signed by a key of the key set")
}

// DecodeStrict decodes one JSON value, refusing unknown fields and
// trailing data.
func DecodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// Sign signs payload as a DSSE envelope (collectors and tests).
func Sign(priv ed25519.PrivateKey, payloadType string, payload []byte) ([]byte, error) {
	pub, _ := priv.Public().(ed25519.PublicKey)
	env := scannertemplate.Envelope{PayloadType: payloadType, Payload: payload,
		Signatures: []scannertemplate.EnvelopeSignature{{KeyID: jobsign.KeyID(pub),
			Sig: ed25519.Sign(priv, scannertemplate.PreAuthEncoding(payloadType, payload))}}}
	return json.Marshal(env)
}
