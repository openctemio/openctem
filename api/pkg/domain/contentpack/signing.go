package contentpack

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
)

// StatementPayloadType is the DSSE payload type of a pack statement.
const StatementPayloadType = "application/vnd.openctem.content-pack+json"

// StatementKind is the kind of a pack statement (v1).
const StatementKind = "openctem.content-pack/v1"

// HKDF labels. The content key family is separate from every other key the
// platform holds (job signing, template manifests, the sensor CA): its
// master is APP_CONTENT_SIGNING_KEY, or derived from APP_ENCRYPTION_KEY
// under its own label, and each tenant's key is derived under another.
const (
	contentKeyInfo           = "openctem.content-signing-key/v1:tenant:"
	platformKeyInfo          = "openctem.content-signing-key/v1:platform"
	masterFromEncryptionInfo = "openctem.content-signing-master/v1"
)

// Statement is what the platform signs for a pack: who it belongs to, what
// it is and the digest of its canonical archive. A sensor verifies it with
// the tenant's content key before it mounts the pack, and checks the
// archive against Digest.
type Statement struct {
	Kind string `json:"kind"`
	// Scope is "platform" for a platform pack (signed with the platform
	// content key, TenantID empty); empty for a tenant pack.
	Scope     string    `json:"scope,omitempty"`
	TenantID  string    `json:"tenant_id"`
	PackID    string    `json:"pack_id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Content   string    `json:"content_kind"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Files     int       `json:"files"`
	Tier      Tier      `json:"tier"`
	CreatedAt time.Time `json:"created_at"`
}

// Signer derives each tenant's content-signing key (Ed25519) from one
// 32-byte master secret. A tenant's key signs only its packs, so a pack
// signed for one tenant never verifies with another tenant's key.
type Signer struct {
	master []byte
}

// NewSigner returns a signer over a 32-byte master (APP_CONTENT_SIGNING_KEY).
func NewSigner(master []byte) (*Signer, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("content signing master key must be 32 bytes, got %d", len(master))
	}
	return &Signer{master: append([]byte(nil), master...)}, nil
}

// NewSignerFromEncryptionKey derives the master from the credentials
// encryption key under the content label, for deployments that set no
// APP_CONTENT_SIGNING_KEY.
func NewSignerFromEncryptionKey(encryptionKey []byte) (*Signer, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(encryptionKey))
	}
	master, err := hkdf.Key(sha256.New, encryptionKey, nil, masterFromEncryptionInfo, 32)
	if err != nil {
		return nil, err
	}
	return NewSigner(master)
}

func (s *Signer) tenantKey(tenantID string) (ed25519.PrivateKey, error) {
	if tenantID == "" {
		return nil, errors.New("tenant id is required")
	}
	seed, err := hkdf.Key(sha256.New, s.master, nil, contentKeyInfo+tenantID, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKey is tenantID's content-signing public key and its id: what the
// tenant's sensors pin.
func (s *Signer) PublicKey(tenantID string) (ed25519.PublicKey, string, error) {
	priv, err := s.tenantKey(tenantID)
	if err != nil {
		return nil, "", err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return pub, scannertemplate.KeyID(pub), nil
}

func (s *Signer) platformKey() (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, s.master, nil, platformKeyInfo, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PlatformPublicKey is the platform content-signing public key and its id:
// what every sensor pins to verify platform packs.
func (s *Signer) PlatformPublicKey() (ed25519.PublicKey, string, error) {
	priv, err := s.platformKey()
	if err != nil {
		return nil, "", err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return pub, scannertemplate.KeyID(pub), nil
}

// SignPlatform signs st as a platform pack (scope platform, no tenant) with
// the platform content key.
func (s *Signer) SignPlatform(st Statement) ([]byte, error) {
	st.Scope, st.TenantID = "platform", ""
	priv, err := s.platformKey()
	if err != nil {
		return nil, err
	}
	return seal(st, priv)
}

// Sign signs st with the key of st.TenantID and returns the DSSE envelope
// (JSON) carrying the exact signed bytes.
func (s *Signer) Sign(st Statement) ([]byte, error) {
	if st.Kind == "" {
		st.Kind = StatementKind
	}
	if st.PackID == "" || ValidateDigest(st.Digest) != nil {
		return nil, errors.New("statement needs a pack id and a digest")
	}
	if st.Scope != "" {
		return nil, errors.New("a tenant statement has no scope")
	}
	priv, err := s.tenantKey(st.TenantID)
	if err != nil {
		return nil, err
	}
	return seal(st, priv)
}

func seal(st Statement, priv ed25519.PrivateKey) ([]byte, error) {
	if st.Kind == "" {
		st.Kind = StatementKind
	}
	if st.PackID == "" || ValidateDigest(st.Digest) != nil {
		return nil, errors.New("statement needs a pack id and a digest")
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return json.Marshal(scannertemplate.Envelope{
		PayloadType: StatementPayloadType,
		Payload:     payload,
		Signatures: []scannertemplate.EnvelopeSignature{{
			KeyID: scannertemplate.KeyID(pub),
			Sig:   ed25519.Sign(priv, scannertemplate.PreAuthEncoding(StatementPayloadType, payload)),
		}},
	})
}

// Verify checks an envelope against pub and returns its statement. It is
// what a sensor does; the platform uses it to check what it stored.
func Verify(envelope []byte, pub ed25519.PublicKey) (*Statement, error) {
	var env scannertemplate.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("content pack signature: %w", err)
	}
	if env.PayloadType != StatementPayloadType {
		return nil, errors.New("content pack signature: wrong payload type")
	}
	want := scannertemplate.KeyID(pub)
	ok := false
	for _, sig := range env.Signatures {
		if sig.KeyID == want && ed25519.Verify(pub, scannertemplate.PreAuthEncoding(env.PayloadType, env.Payload), sig.Sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("content pack signature: not signed by this key")
	}
	var st Statement
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		return nil, fmt.Errorf("content pack signature: %w", err)
	}
	if st.Kind != StatementKind {
		return nil, errors.New("content pack signature: unknown statement kind")
	}
	return &st, nil
}
