package sensorpairing

// Shared sensor enrollment (docs/rfcs/RFC-100-shared-sensors.md §7). A super
// administrator issues a single-use instance enrollment token in the console
// (after a fresh authenticator code, with a reason), or the install's
// bootstrap tool registers one; it lives at most an hour and only its keyed
// hash is stored. A sensor that starts pairing with it runs the same
// key-bound exchange as every pairing (its own Ed25519 key, the platform's
// signed answer, the nonce commitment, a signed confirmation), and once it
// reveals its nonce the request is approved as a shared sensor: scope
// instance, no tenant, trust level trusted and the least-privilege grant the
// sensors insert trigger writes. The token is the administrator's approval,
// so no second approval is asked; it never yields a tenant context.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
)

// ErrEnrollmentRefused is the one answer for an instance enrollment token
// that is malformed, unknown, expired or already used.
var ErrEnrollmentRefused = errors.New("enrollment refused")

const (
	// MinInstanceTokenTTL and sensordom.MaxInstanceTokenTTL bound a token's
	// lifetime.
	MinInstanceTokenTTL = 5 * time.Minute
	maxTokenReason      = 1000
	// instanceTokenBodyLen is the width of a token after its prefix: the
	// random part and the checksum of a minted token, or the random part of
	// one the install generated (which has no checksum: the checksum only
	// helps secret scanners and is not a control).
	instanceTokenBodyLen = sensorkey.RandomLen + sensorkey.ChecksumLen
	sharedSensorPrefix   = "shared-sensor-"
	actorBootstrap       = "bootstrap"
	actorSensor          = "sensor"
)

// AdminAuditWriter writes console audit rows (admin.AuditLogRepository).
type AdminAuditWriter interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// SetAdminAudit wires the console audit log; shared sensor enrollment
// records there (it has no tenant).
func (s *Service) SetAdminAudit(a AdminAuditWriter) { s.adminAudit = a }

// IssueInstanceTokenInput describes a new token.
type IssueInstanceTokenInput struct {
	// Actor is the super administrator; nil for the install's bootstrap
	// tool.
	Actor     *admin.AdminUser
	Name      string
	Reason    string
	TTL       time.Duration
	IP        string
	UserAgent string
}

// IssuedInstanceToken is the answer: Token is shown once and never stored.
type IssuedInstanceToken struct {
	ID        shared.ID
	Token     string
	Name      string
	ExpiresAt time.Time
}

// IssueInstanceToken mints a single-use instance enrollment token. The
// caller has checked the role and the console step-up.
func (s *Service) IssueInstanceToken(ctx context.Context, in IssueInstanceTokenInput) (*IssuedInstanceToken, error) {
	token, err := sensorkey.New(sensorkey.PrefixEnrollmentToken)
	if err != nil {
		return nil, err
	}
	return s.storeInstanceToken(ctx, token, in)
}

// RegisterInstanceToken stores a token the install generated (octe_ and 49
// letters or digits), so a bundled sensor can be given it before the
// platform runs. Same lifetime, audit and single use as an issued one.
func (s *Service) RegisterInstanceToken(ctx context.Context, token string, in IssueInstanceTokenInput) (*IssuedInstanceToken, error) {
	if !wellFormedInstanceToken(token) {
		return nil, fmt.Errorf("%w: the token must be %s followed by %d letters or digits", shared.ErrValidation,
			sensorkey.PrefixEnrollmentToken, instanceTokenBodyLen)
	}
	return s.storeInstanceToken(ctx, token, in)
}

func (s *Service) storeInstanceToken(ctx context.Context, token string, in IssueInstanceTokenInput) (*IssuedInstanceToken, error) {
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || len(reason) > maxTokenReason {
		return nil, fmt.Errorf("%w: a reason of 1 to %d characters is required", shared.ErrValidation, maxTokenReason)
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = sensordom.MaxInstanceTokenTTL
	}
	if ttl < MinInstanceTokenTTL || ttl > sensordom.MaxInstanceTokenTTL {
		return nil, fmt.Errorf("%w: the lifetime must be between %s and %s", shared.ErrValidation,
			MinInstanceTokenTTL, sensordom.MaxInstanceTokenTTL)
	}
	now := s.now().UTC().Truncate(time.Second)
	t := &sensordom.InstanceEnrollmentToken{ID: shared.NewID(), TokenHash: s.instanceTokenHash(token),
		Name: sanitizeName(in.Name), Reason: reason, CreatedByEmail: actorBootstrap, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if in.Actor != nil {
		id := in.Actor.ID()
		t.CreatedBy, t.CreatedByEmail = &id, in.Actor.Email()
	}
	if err := s.repo.CreateInstanceToken(ctx, t); err != nil {
		return nil, err
	}
	s.writeAdminAudit(ctx, in.Actor, t.CreatedByEmail, admin.AuditActionInstanceTokenCreate,
		admin.ResourceTypeInstanceEnrollmentToken, &t.ID, t.Name, in.IP, in.UserAgent,
		map[string]any{"reason": reason, "expires_at": t.ExpiresAt, "name": t.Name})
	return &IssuedInstanceToken{ID: t.ID, Token: token, Name: t.Name, ExpiresAt: t.ExpiresAt}, nil
}

// instanceTokenHash is the keyed hash a token is stored and looked up under.
func (s *Service) instanceTokenHash(token string) string {
	m := hmac.New(sha256.New, s.codeKey)
	m.Write([]byte("openctem/instance-enrollment-token/v1\x00"))
	m.Write([]byte(token))
	return hex.EncodeToString(m.Sum(nil))
}

// wellFormedInstanceToken checks the shape only (prefix, width, alphabet).
func wellFormedInstanceToken(token string) bool {
	body, ok := strings.CutPrefix(token, sensorkey.PrefixEnrollmentToken)
	if !ok || len(body) != instanceTokenBodyLen {
		return false
	}
	for _, c := range body {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// startInstance spends the token and records the request bound to it.
func (s *Service) startInstance(ctx context.Context, token string, p *sensordom.Pairing) error {
	if !wellFormedInstanceToken(token) {
		s.log.Warn("shared sensor enrollment refused: malformed token", "source_ip", p.SourceIP)
		return ErrEnrollmentRefused
	}
	hash := s.instanceTokenHash(token)
	t, ok, err := s.repo.StartWithInstanceTokenUnscoped(ctx, hash, p, s.now())
	if err != nil {
		return err
	}
	// The row was found by its hash; compare again in constant time.
	if !ok || !hmac.Equal([]byte(t.TokenHash), []byte(hash)) {
		s.log.Warn("shared sensor enrollment refused: unknown, expired or used token", "source_ip", p.SourceIP)
		return ErrEnrollmentRefused
	}
	s.writeAdminAudit(ctx, nil, actorSensor, admin.AuditActionInstanceTokenRedeem,
		admin.ResourceTypeInstanceEnrollmentToken, &t.ID, t.Name, ipString(p), "",
		map[string]any{"pairing_id": p.ID.String(), "key_fingerprint": pairing.KeyFingerprint(p.Thumbprint),
			"host_facts": p.HostFacts})
	return nil
}

// approveInstance approves a revealed token-bound request as a shared
// sensor. A request already approved (a retried reveal) is left alone.
func (s *Service) approveInstance(ctx context.Context, p *sensordom.Pairing) error {
	now := s.now()
	name := sanitizeName(firstNonEmpty(p.RequestedName, p.HostFacts.Name, p.HostFacts.Hostname))
	if name == "" {
		name = sharedSensorPrefix + p.Thumbprint[:8]
	}
	res, err := s.repo.ApproveInstanceUnscoped(ctx, sensordom.InstanceApproval{
		PairingID: p.ID, Now: now, ConfirmBy: now.Add(ConfirmWindow), SensorID: shared.NewID(), KeyID: shared.NewID(),
		Name: name, Type: sensordom.SensorTypeWorker, Hostname: p.HostFacts.Hostname, OS: p.HostFacts.OS,
		Arch: p.HostFacts.Arch, Version: p.HostFacts.SensorVersion,
	})
	if errors.Is(err, sensordom.ErrPairingNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s.writeAdminAudit(ctx, nil, actorSensor, admin.AuditActionSharedSensorEnrolled, admin.ResourceTypeSensor,
		&res.SensorID, name, ipString(res.Pairing), "",
		map[string]any{"pairing_id": p.ID.String(), "instance_token_id": p.InstanceTokenID.String(),
			"key_fingerprint": pairing.KeyFingerprint(p.Thumbprint), "sas": res.Pairing.SAS, "host_facts": p.HostFacts})
	return nil
}

func ipString(p *sensordom.Pairing) string {
	if p == nil || p.SourceIP == nil {
		return ""
	}
	return p.SourceIP.String()
}

// writeAdminAudit writes one console audit row (high severity), detached
// from the request so a client that disconnects cannot drop it.
func (s *Service) writeAdminAudit(ctx context.Context, actor *admin.AdminUser, email, action, resourceType string,
	id *shared.ID, name, ip, ua string, body map[string]any) {
	if s.adminAudit == nil {
		s.log.Warn("shared sensor enrollment: no console audit log", "action", action)
		return
	}
	b := admin.NewAuditLogBuilder(actor, action).Resource(resourceType, id, name).Context(ip, ua).
		Request("", "", body).Response(200).High()
	entry := b.Build()
	if actor == nil {
		entry.AdminEmail = email
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.adminAudit.Create(actx, entry); err != nil {
		s.log.Error("shared sensor enrollment: write console audit", "action", action, "error", err)
	}
}
