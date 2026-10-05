package sensor

// Key-bound authentication (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §4.3): a request signed with a sensor's registered Ed25519 key. The HTTP
// layer parses and verifies the signature (pkg/sensorsig); this file resolves
// the key to its sensor, applies the sensor's status, spends the nonce and
// records the use.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// NonceTTL is how long a spent nonce is remembered: the longest window a
// signature may claim plus the clock skew on both ends.
const NonceTTL = sensorsig.MaxWindow + 2*sensorsig.MaxClockSkew

// errSignedUnauthorized is the one error every key-bound refusal returns.
var errSignedUnauthorized = shared.NewDomainError("UNAUTHORIZED", "invalid signature", shared.ErrUnauthorized)

// SetSigningKeyRepository wires the store of sensors' public keys. Without
// it every signed request is refused.
func (s *SensorService) SetSigningKeyRepository(repo sensordom.SigningKeyRepository) {
	s.signingKeys = repo
}

// SetNonceStore wires the shared nonce store (Redis). Without it nonces are
// remembered per replica (memoryNonceStore), which still refuses a replay to
// the same replica.
func (s *SensorService) SetNonceStore(store sensordom.NonceStore) {
	s.nonces = store
}

// SigningKeys is the store of sensors' public keys (nil when not wired).
func (s *SensorService) SigningKeys() sensordom.SigningKeyRepository { return s.signingKeys }

// SigningIdentity resolves an RFC 9421 keyid to its active key and sensor.
// The sensor's admin status applies as for a bearer key: revoked is always
// refused, disabled passes as paused only when allowPaused. Every refusal is
// the same unauthorized error.
func (s *SensorService) SigningIdentity(ctx context.Context, keyID string, allowPaused bool) (SensorIdentity, ed25519.PublicKey, error) {
	if s.signingKeys == nil {
		return SensorIdentity{}, nil, errSignedUnauthorized
	}
	k, err := s.signingKeys.GetActiveByThumbprint(ctx, keyID)
	if err != nil || len(k.PublicKey) != ed25519.PublicKeySize {
		return SensorIdentity{}, nil, errSignedUnauthorized
	}
	a, err := s.repo.GetByTenantAndID(ctx, k.TenantID, k.SensorID)
	if err != nil || a == nil || !a.KeyBound() {
		return SensorIdentity{}, nil, errSignedUnauthorized
	}
	paused, err := checkSensorStatus(a, allowPaused)
	if err != nil {
		return SensorIdentity{}, nil, errSignedUnauthorized
	}
	kid := k.ID
	return SensorIdentity{Sensor: a, Paused: paused, signingKeyID: &kid, keyThumbprint: k.Thumbprint}, ed25519.PublicKey(k.PublicKey), nil
}

// UseNonce spends a request nonce of keyID. A nonce seen before (within
// NonceTTL) is refused. When the shared store fails, the per-replica store
// decides and the failure is logged: refusing every sensor request while
// Redis restarts would be worse than a replay window limited to other
// replicas.
func (s *SensorService) UseNonce(ctx context.Context, keyID, nonce string) error {
	if s.nonces != nil {
		fresh, err := s.nonces.Use(ctx, keyID, nonce, NonceTTL)
		if err == nil {
			if !fresh {
				return errSignedUnauthorized
			}
			// Remember it locally too, so the fallback knows it.
			_, _ = s.localNonces().Use(ctx, keyID, nonce, NonceTTL)
			return nil
		}
		s.logger.Warn("sensor nonce store unavailable; using the per-replica store", "error", err)
	}
	fresh, _ := s.localNonces().Use(ctx, keyID, nonce, NonceTTL)
	if !fresh {
		return errSignedUnauthorized
	}
	return nil
}

// RecordSignedUse marks the sensor seen and the key used from clientIP, off
// the request path (as recordKeyUseAsync does for bearer keys).
func (s *SensorService) RecordSignedUse(id SensorIdentity, clientIP string) {
	if id.Sensor == nil || id.Paused {
		return
	}
	thumb := id.keyThumbprint
	var keyUsage func(context.Context, string)
	if s.signingKeys != nil && thumb != "" {
		at := s.now()
		keyUsage = func(ctx context.Context, ip string) {
			if err := s.signingKeys.RecordUse(ctx, thumb, net.ParseIP(ip), at); err != nil {
				s.logger.Debug("failed to record sensor key use", "error", err)
			}
		}
	}
	s.recordKeyUseAsync(id.Sensor, clientIP, keyUsage)
}

// KeyBound reports whether the identity authenticated with a signature.
func (id SensorIdentity) KeyBound() bool { return id.signingKeyID != nil }

// localNonces is the per-replica nonce store, created on first use.
func (s *SensorService) localNonces() *memoryNonceStore {
	s.nonceOnce.Do(func() { s.memNonces = newMemoryNonceStore(100_000) })
	return s.memNonces
}

// memoryNonceStore remembers nonces in memory, bounded: when full, expired
// entries are swept, and if it is still full the request is refused (fail
// closed rather than forget a nonce inside its window).
type memoryNonceStore struct {
	mu   sync.Mutex
	max  int
	seen map[string]time.Time
	now  func() time.Time
}

func newMemoryNonceStore(maxEntries int) *memoryNonceStore {
	return &memoryNonceStore{max: maxEntries, seen: map[string]time.Time{}, now: time.Now}
}

var errNonceStoreFull = errors.New("nonce store full")

func (m *memoryNonceStore) Use(_ context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	k := keyID + "\x00" + nonce
	if exp, ok := m.seen[k]; ok && now.Before(exp) {
		return false, nil
	}
	if len(m.seen) >= m.max {
		for key, exp := range m.seen {
			if !now.Before(exp) {
				delete(m.seen, key)
			}
		}
		if len(m.seen) >= m.max {
			return false, errNonceStoreFull
		}
	}
	m.seen[k] = now.Add(ttl)
	return true, nil
}
