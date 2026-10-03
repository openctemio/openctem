package scannertemplate

// Custom template signatures for sensors. Design and threat model:
// docs/rfcs/RFC-038-sensor-tool-settings.md, "Custom template trust".
//
// When a command with custom templates leaves for a sensor, the platform
// signs one manifest for the whole set (tenant, sensor, command, issue and
// expiry times, and the id, name, type and SHA-256 of every template, in
// order) with an Ed25519 key derived for the tenant. The manifest travels in
// a DSSE envelope: the exact signed bytes and a payload type, the signature
// over DSSE's pre-authentication encoding. The sensor (sdk-go
// core.TemplateVerifier) verifies it against the tenant key its operator
// pinned before it parses it, so a template the platform did not validate
// and sign for that command never reaches a scanner.
// TestManifestEnvelopeVector pins this side and sdk-go's to the same bytes.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ManifestPayloadType is the DSSE payload type of a template manifest.
const ManifestPayloadType = "application/vnd.openctem.template-manifest+json"

// ManifestKind is the kind of a template manifest (v1).
const ManifestKind = "openctem.template-manifest/v1"

// ManifestTTL is how long a signed manifest is valid: a sensor refuses an
// expired one, so a captured command cannot be replayed later.
const ManifestTTL = time.Hour

// tenantKeyInfo is the HKDF info prefix of a tenant's signing seed.
const tenantKeyInfo = "openctem.template-signing-key/v1:"

// masterFromEncryptionInfo derives the master from APP_ENCRYPTION_KEY when no
// dedicated APP_TEMPLATE_SIGNING_KEY is set.
const masterFromEncryptionInfo = "openctem.template-signing-master/v1"

// Manifest is the signed description of one command's custom templates. Its
// JSON form must match sdk-go core.TemplateManifest field for field: the
// sensor refuses unknown fields.
type Manifest struct {
	Kind      string             `json:"kind"`
	TenantID  string             `json:"tenant_id"`
	SensorID  string             `json:"sensor_id,omitempty"`
	CommandID string             `json:"command_id"`
	IssuedAt  time.Time          `json:"issued_at"`
	ExpiresAt time.Time          `json:"expires_at"`
	Templates []ManifestTemplate `json:"templates"`
}

// ManifestTemplate is one template in a Manifest.
type ManifestTemplate struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TemplateType string `json:"template_type"`
	SHA256       string `json:"sha256"` // hex, of the decoded content
}

// NewManifestTemplate describes one template by its id, name, type (as sent
// to the sensor) and decoded content.
func NewManifestTemplate(id, name, templateType string, content []byte) ManifestTemplate {
	sum := sha256.Sum256(content)
	return ManifestTemplate{ID: id, Name: name, TemplateType: templateType, SHA256: hex.EncodeToString(sum[:])}
}

// Envelope is a DSSE envelope (sdk-go core.SignedEnvelope).
type Envelope struct {
	PayloadType string              `json:"payloadType"`
	Payload     []byte              `json:"payload"`
	Signatures  []EnvelopeSignature `json:"signatures"`
}

// EnvelopeSignature is one signature of an Envelope.
type EnvelopeSignature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// PreAuthEncoding is DSSE v1's PAE: "DSSEv1 <len(type)> <type> <len(body)>
// <body>", lengths in ASCII decimal.
func PreAuthEncoding(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// KeyID names a public key: the first 16 hex characters of its SHA-256
// (sdk-go core.TemplateKeyID).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Keyring derives each tenant's template-signing key from one 32-byte
// master secret. A tenant's key signs only that tenant's templates, and a
// sensor pins only its own tenant's public key, so a template signed for one
// tenant does not verify on another tenant's sensor.
type Keyring struct {
	master []byte
}

// NewKeyring returns a keyring over a 32-byte master secret
// (APP_TEMPLATE_SIGNING_KEY).
func NewKeyring(master []byte) (*Keyring, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("template signing master key must be 32 bytes, got %d", len(master))
	}
	return &Keyring{master: append([]byte(nil), master...)}, nil
}

// NewKeyringFromEncryptionKey derives the master from the credentials
// encryption key (domain-separated with HKDF), for deployments that set no
// dedicated APP_TEMPLATE_SIGNING_KEY.
func NewKeyringFromEncryptionKey(encryptionKey []byte) (*Keyring, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(encryptionKey))
	}
	master, err := hkdf.Key(sha256.New, encryptionKey, nil, masterFromEncryptionInfo, 32)
	if err != nil {
		return nil, err
	}
	return NewKeyring(master)
}

// tenantKey is tenantID's signing key.
func (k *Keyring) tenantKey(tenantID string) (ed25519.PrivateKey, error) {
	if tenantID == "" {
		return nil, errors.New("tenant id is required")
	}
	seed, err := hkdf.Key(sha256.New, k.master, nil, tenantKeyInfo+tenantID, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKey is tenantID's template-signing public key and its id: what an
// operator pins on the tenant's sensors (SENSOR_TEMPLATE_SIGNING_KEYS).
func (k *Keyring) PublicKey(tenantID string) (ed25519.PublicKey, string, error) {
	priv, err := k.tenantKey(tenantID)
	if err != nil {
		return nil, "", err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return pub, KeyID(pub), nil
}

// Seal signs m with the key of m.TenantID and returns the envelope that
// carries the exact signed bytes.
func (k *Keyring) Seal(m Manifest) (*Envelope, error) {
	if m.Kind == "" {
		m.Kind = ManifestKind
	}
	if m.CommandID == "" {
		return nil, errors.New("manifest needs a command id")
	}
	priv, err := k.tenantKey(m.TenantID)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &Envelope{
		PayloadType: ManifestPayloadType,
		Payload:     payload,
		Signatures: []EnvelopeSignature{{
			KeyID: KeyID(pub),
			Sig:   ed25519.Sign(priv, PreAuthEncoding(ManifestPayloadType, payload)),
		}},
	}, nil
}
