package sensor

// Self-binding of a signing key by a bearer-key sensor
// (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §4.8): a sensor
// that authenticates with an API key generates an Ed25519 key, proves it
// holds it, and the platform makes the same sensor key-bound in one
// transaction, retiring every API key of the sensor. One way: no bearer key
// is ever minted for a key-bound sensor again.
//
// No privilege is gained: the sensor row, its tenant, grant, zones and trust
// level are unchanged; only how it authenticates changes. A stolen API key
// could bind an attacker's key instead of the sensor's own; the legitimate
// sensor then fails at its next request, the bind is audited at high
// severity, notified on the sensor's timeline, and the administrator
// revokes the key or the sensor and re-pairs. An organization that wants an
// administrator to approve every key turns self-binding off
// (KeyBindRequiresApproval) and re-pairs its bearer sensors instead.

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// KeyBindProofContext prefixes the message a sensor signs to prove it holds
// the key it binds.
const KeyBindProofContext = "openctem-sensor-key-bind/v1"

// KeyBindProofWindow bounds how far the proof's timestamp may be from now.
const KeyBindProofWindow = 5 * time.Minute

// KeyBindProofMessage is the message a sensor signs with the key it binds:
// the context, the key's thumbprint and the RFC 3339 timestamp, newline
// separated.
func KeyBindProofMessage(thumbprint, issuedAt string) []byte {
	return []byte(KeyBindProofContext + "\n" + thumbprint + "\n" + issuedAt)
}

// KeyBindInput is a bind request.
type KeyBindInput struct {
	PublicKey []byte // raw Ed25519 public key
	Proof     []byte // signature of KeyBindProofMessage
	IssuedAt  string // RFC 3339, the signed timestamp
	ClientIP  string
}

// KeyBindResult is what the sensor needs to sign its next requests.
type KeyBindResult struct {
	SensorID shared.ID
	TenantID shared.ID
	Name     string
	KeyID    string // the thumbprint, the keyid of every signature
}

// errKeyBindProof: the proof did not verify or is outside the window.
var errKeyBindProof = shared.NewDomainError("KEY_BIND_PROOF", "the proof of possession is invalid or stale", shared.ErrValidation)

// SupportsKeyBind reports whether bearer-key sensors can bind a signing key
// here (the key store is wired).
func (s *SensorService) SupportsKeyBind() bool { return s.signingKeys != nil }

// KeyBindRequiresApproval reports the tenant's key bind policy (false
// without a policy store).
func (s *SensorService) KeyBindRequiresApproval(ctx context.Context, tenantID shared.ID) (bool, error) {
	if s.identityPolicy == nil {
		return false, nil
	}
	return s.identityPolicy.KeyBindRequiresApproval(ctx, tenantID)
}

// SetKeyBindRequiresApproval changes the key bind policy and audits a
// change. Allowing self-binding again needs a recent re-authentication
// (step-up); requiring approval stays one click. The caller checked the
// permission (narrow to require, widen to allow).
func (s *SensorService) SetKeyBindRequiresApproval(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, required bool) error {
	if s.identityPolicy == nil {
		return shared.NewDomainError("UNAVAILABLE", "identity policy not available", shared.ErrValidation)
	}
	if !required && s.stepUp != nil {
		current, err := s.identityPolicy.KeyBindRequiresApproval(ctx, tenantID)
		if err != nil {
			return err
		}
		if current {
			if err := s.stepUp.RequireRecentAuth(ctx, actx.ActorID); err != nil {
				return err
			}
		}
	}
	changed, err := s.identityPolicy.SetKeyBindRequiresApproval(ctx, tenantID, required)
	if err != nil || !changed {
		return err
	}
	msg := "Bearer-key sensors may bind their own signing key (audited)"
	if required {
		msg = "Bearer-key sensors may not bind their own signing key: an administrator re-pairs them"
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionSensorIdentityPolicySet, audit.ResourceTypeSensor, tenantID.String()).
		WithMessage(msg).WithSeverity(audit.SeverityHigh).WithMetadata("key_bind_requires_approval", required))
	return nil
}

// BindSigningKey binds in.PublicKey to the bearer-key sensor of id (the
// identity its API key authenticated). The tenant and sensor come from id
// only.
func (s *SensorService) BindSigningKey(ctx context.Context, id SensorIdentity, in KeyBindInput) (*KeyBindResult, error) {
	a := id.Sensor
	if a == nil || a.TenantID == nil {
		return nil, shared.NewDomainError("UNAUTHORIZED", "no authenticated sensor", shared.ErrUnauthorized)
	}
	tenantID := *a.TenantID
	refuse := func(reason string, err error) (*KeyBindResult, error) {
		s.auditKeyBind(ctx, a, in.ClientIP, "", reason, err)
		return nil, err
	}
	if s.signingKeys == nil {
		return nil, shared.NewDomainError("UNAVAILABLE", "key binding not available", shared.ErrValidation)
	}
	// A key-bound sensor, a paused one or a platform sensor never binds.
	if a.KeyBound() || id.KeyBound() || id.Paused || a.IsPlatformSensor || a.Status != sensordom.SensorStatusActive {
		return refuse("not an active bearer-key sensor", sensordom.ErrKeyBindConflict)
	}
	required, err := s.KeyBindRequiresApproval(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if required {
		return refuse("the organization requires an administrator's approval", sensordom.ErrKeyBindNeedsApproval)
	}
	if len(in.PublicKey) != ed25519.PublicKeySize {
		return refuse("malformed public key", errKeyBindProof)
	}
	pub := ed25519.PublicKey(in.PublicKey)
	thumb := sensorsig.Thumbprint(pub)
	at, err := time.Parse(time.RFC3339, in.IssuedAt)
	now := s.now()
	if err != nil || at.Before(now.Add(-KeyBindProofWindow)) || at.After(now.Add(KeyBindProofWindow)) ||
		!ed25519.Verify(pub, KeyBindProofMessage(thumb, in.IssuedAt), in.Proof) {
		return refuse("invalid or stale proof of possession", errKeyBindProof)
	}
	key := &sensordom.SigningKey{ID: shared.NewID(), TenantID: tenantID, SensorID: a.ID, Thumbprint: thumb,
		PublicKey: append([]byte(nil), pub...), Status: sensordom.SigningKeyActive}
	retired, err := s.signingKeys.BindToBearerSensor(ctx, key, now)
	if err != nil {
		return refuse("the sensor changed or the key is registered", err)
	}
	s.recordEvents(ctx, []sensordom.Event{sensordom.NewEvent(tenantID, a.ID, sensordom.EventKeyBound, now,
		"The sensor bound its own signing key; its API keys are retired",
		map[string]any{"key_fingerprint": pairing.KeyFingerprint(thumb), "source_ip": in.ClientIP, "retired_api_keys": retired})})
	s.auditKeyBind(ctx, a, in.ClientIP, thumb, "", nil)
	s.notifyStatus(a)
	return &KeyBindResult{SensorID: a.ID, TenantID: tenantID, Name: a.Name, KeyID: thumb}, nil
}

// auditKeyBind records a bind or a refused bind at high severity: a bind
// changes how the sensor authenticates, and a stolen API key binding a
// foreign key must be visible.
func (s *SensorService) auditKeyBind(ctx context.Context, a *sensordom.Sensor, ip, thumb, reason string, err error) {
	actx := auditapp.AuditContext{TenantID: a.TenantID.String(), ActorEmail: sensorAuditSystemActor, ActorIP: ip}
	if err != nil {
		s.logAudit(ctx, actx, auditapp.NewFailureEvent(audit.ActionSensorKeyBindRefused, audit.ResourceTypeSensor, a.ID.String(), err).
			WithResourceName(a.Name).WithSeverity(audit.SeverityHigh).
			WithMessage(fmt.Sprintf("Sensor '%s' tried to bind its own signing key: refused (%s)", a.Name, reason)).
			WithMetadata("source_ip", ip))
		return
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionSensorKeyBound, audit.ResourceTypeSensor, a.ID.String()).
		WithResourceName(a.Name).WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Sensor '%s' bound its own signing key %s from %s; its API keys are retired", a.Name, pairing.KeyFingerprint(thumb), ip)).
		WithMetadata("key_fingerprint", pairing.KeyFingerprint(thumb)).WithMetadata("source_ip", ip))
}
