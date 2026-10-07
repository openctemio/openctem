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

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"

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

// RecordEvents writes events to the sensors' timelines (best effort), for
// services outside this package (pairing, grants).
func (s *SensorService) RecordEvents(ctx context.Context, events []sensordom.Event) {
	s.recordEvents(ctx, events)
}

// SetIdentityPolicyRepository wires the organization's identity policy
// (RFC-052 D-4). Without it bearer-key sensors may always be created.
func (s *SensorService) SetIdentityPolicyRepository(repo sensordom.IdentityPolicyRepository) {
	s.identityPolicy = repo
}

// BearerKeysAllowed reports whether tenantID may create bearer-key sensors.
func (s *SensorService) BearerKeysAllowed(ctx context.Context, tenantID shared.ID) (bool, error) {
	if s.identityPolicy == nil {
		return true, nil
	}
	return s.identityPolicy.BearerKeysAllowed(ctx, tenantID)
}

// SetStepUpGate wires step-up re-authentication for widening the identity
// policy (docs/architecture/step-up-reauth.md).
func (s *SensorService) SetStepUpGate(g shared.RecentAuthGate) { s.stepUp = g }

// SetBearerKeysAllowed changes the policy and audits a change at high
// severity. The caller checked the permission: requiring key-bound identity
// narrows (sensors:grant:narrow), allowing bearer keys widens
// (sensors:grant:widen). Widening also needs the acting user's recent
// re-authentication (step-up); narrowing stays one click.
func (s *SensorService) SetBearerKeysAllowed(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, allowed bool) error {
	if s.identityPolicy == nil {
		return shared.NewDomainError("UNAVAILABLE", "identity policy not available", shared.ErrValidation)
	}
	if allowed && s.stepUp != nil {
		current, err := s.identityPolicy.BearerKeysAllowed(ctx, tenantID)
		if err != nil {
			return err
		}
		if !current {
			if err := s.stepUp.RequireRecentAuth(ctx, actx.ActorID); err != nil {
				return err
			}
		}
	}
	changed, err := s.identityPolicy.SetBearerKeysAllowed(ctx, tenantID, allowed)
	if err != nil || !changed {
		return err
	}
	msg := "Sensors must use key-bound identity (pairing); no new API keys can be created"
	if allowed {
		msg = "New sensors may again be created with an API key (bearer key)"
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionSensorIdentityPolicySet, audit.ResourceTypeSensor, tenantID.String()).
		WithMessage(msg).WithSeverity(audit.SeverityHigh).WithMetadata("bearer_keys_allowed", allowed))
	return nil
}

// logAudit writes an audit event (best effort).
func (s *SensorService) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.auditService == nil {
		return
	}
	s.warnAudit(s.auditService.LogEvent(ctx, actx, ev), string(ev.Action), ev.ResourceID)
}

// ListSigningKeys returns a sensor's public keys (tenant-scoped).
func (s *SensorService) ListSigningKeys(ctx context.Context, tenantID, sensorID shared.ID) ([]*sensordom.SigningKey, error) {
	if s.signingKeys == nil {
		return nil, nil
	}
	if _, err := s.repo.GetByTenantAndID(ctx, tenantID, sensorID); err != nil {
		return nil, err
	}
	return s.signingKeys.ListBySensor(ctx, tenantID, sensorID)
}

// RevokeSigningKey revokes one key of a sensor of the tenant, effective on
// the sensor's next request, and audits it. Another tenant's sensor or key
// is shared.ErrNotFound.
func (s *SensorService) RevokeSigningKey(ctx context.Context, actx auditapp.AuditContext, tenantID, sensorID, keyID shared.ID) error {
	if s.signingKeys == nil {
		return shared.ErrNotFound
	}
	a, err := s.repo.GetByTenantAndID(ctx, tenantID, sensorID)
	if err != nil {
		return err
	}
	ok, err := s.signingKeys.Revoke(ctx, tenantID, sensorID, keyID, sensordom.KeyRevokedAdmin, s.now())
	if err != nil {
		return err
	}
	if !ok {
		return shared.ErrNotFound
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionSensorKeyRevoked, audit.ResourceTypeSensor, sensorID.String()).
		WithResourceName(a.Name).WithMessage("Revoked a signing key of sensor "+a.Name).
		WithSeverity(audit.SeverityHigh).WithMetadata("key_id", keyID.String()))
	return nil
}
