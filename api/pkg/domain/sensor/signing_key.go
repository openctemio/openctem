package sensor

// Key-bound sensor identity (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md,
// RFC-032 E4/E5): the sensor holds an Ed25519 private key, the platform keeps
// the public key, and every request is signed (pkg/sensorsig). No bearer
// secret exists for such a sensor.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AuthKind is how a sensor authenticates.
type AuthKind string

const (
	// AuthKindBearer is an API key (octs_, legacy rda_) in Authorization or
	// X-API-Key.
	AuthKindBearer AuthKind = "bearer"
	// AuthKindKeyBound is the sensor's own Ed25519 key with RFC 9421
	// request signatures.
	AuthKindKeyBound AuthKind = "key_bound"
)

// OrBearer is the kind, bearer when unset.
func (k AuthKind) OrBearer() AuthKind {
	if k == AuthKindKeyBound {
		return k
	}
	return AuthKindBearer
}

// KeyBound reports whether the sensor signs its requests.
func (s *Sensor) KeyBound() bool { return s != nil && s.AuthKind == AuthKindKeyBound }

// KeyBoundHashPrefix starts the api_key_hash placeholder of a key-bound
// sensor. A stored key hash is lower-case hex, so no presented key can ever
// hash to a value with this prefix.
const KeyBoundHashPrefix = "!kb:"

// KeyBoundHashPlaceholder is a unique, unmatchable api_key_hash for a
// key-bound sensor (the column is NOT NULL UNIQUE).
func KeyBoundHashPlaceholder() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return KeyBoundHashPrefix + hex.EncodeToString(b[:])
}

// SigningKeyStatus is the state of a registered public key.
type SigningKeyStatus string

const (
	// SigningKeyPending: registered by an approved pairing, not yet
	// confirmed by the sensor. It authenticates nothing.
	SigningKeyPending SigningKeyStatus = "pending"
	// SigningKeyActive authenticates the sensor's requests.
	SigningKeyActive SigningKeyStatus = "active"
	// SigningKeyRevoked never authenticates again.
	SigningKeyRevoked SigningKeyStatus = "revoked"
)

// Reasons recorded when a key is revoked.
const (
	KeyRevokedRepaired    = "repaired"
	KeyRevokedAdmin       = "revoked_by_admin"
	KeyRevokedUnconfirmed = "pairing_not_confirmed"
	KeyRevokedSensor      = "sensor_revoked"
)

// SigningKey is one public key of a sensor.
type SigningKey struct {
	ID            shared.ID
	TenantID      shared.ID
	SensorID      shared.ID
	Thumbprint    string // RFC 7638 thumbprint, the keyid of every signature
	PublicKey     []byte // raw Ed25519 public key (32 bytes)
	Status        SigningKeyStatus
	CreatedAt     time.Time
	ActivatedAt   *time.Time
	RevokedAt     *time.Time
	RevokedReason string
	LastUsedAt    *time.Time
	LastUsedIP    net.IP
}

// SigningKeyRepository stores sensors' public keys.
type SigningKeyRepository interface {
	// GetActiveByThumbprint returns the active key with this thumbprint,
	// whatever its tenant (the keyid of a request is the only thing known
	// before authentication). shared.ErrNotFound for any other state.
	GetActiveByThumbprint(ctx context.Context, thumbprint string) (*SigningKey, error)
	// ListBySensor returns every key of a sensor, newest first.
	ListBySensor(ctx context.Context, tenantID, sensorID shared.ID) ([]*SigningKey, error)
	// RecordUse stamps the key's last use.
	RecordUse(ctx context.Context, thumbprint string, ip net.IP, at time.Time) error
	// Revoke revokes one key of a sensor (tenant-scoped); false when it was
	// not active or pending.
	Revoke(ctx context.Context, tenantID, sensorID, keyID shared.ID, reason string, at time.Time) (bool, error)
	// RevokeAllForSensor revokes every pending or active key of a sensor.
	RevokeAllForSensor(ctx context.Context, tenantID, sensorID shared.ID, reason string, at time.Time) (int64, error)
}

// NonceStore remembers request nonces for the signature window.
type NonceStore interface {
	// Use records nonce for keyID and reports whether it was new.
	Use(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error)
}

// IdentityPolicyRepository stores the organization's sensor identity
// policy (RFC-052 D-4): whether new bearer-key sensors may be created.
type IdentityPolicyRepository interface {
	BearerKeysAllowed(ctx context.Context, tenantID shared.ID) (bool, error)
	SetBearerKeysAllowed(ctx context.Context, tenantID shared.ID, allowed bool) (changed bool, err error)
}

// ErrBearerKeysDisabled refuses a bearer-key sensor in an organization that
// requires key-bound identity.
var ErrBearerKeysDisabled = shared.NewDomainError("BEARER_KEYS_DISABLED",
	"this organization requires key-bound identity: pair the sensor instead of creating a key", shared.ErrForbidden)
