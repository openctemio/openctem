package sensorpairing

// Organization enrollment tokens (docs/architecture/sensor-pairing.md,
// "Enrollment tokens"). An organization administrator (sensors:approve,
// step-up, checked by the route) issues a token for unattended installs:
// Kubernetes, Terraform, many hosts. It has the shape of an instance token
// (octe_ and 49 letters or digits); the sensor sends it with
// enrollment_scope "organization" (SENSOR_ENROLLMENT_TOKEN), so a token is
// only ever looked up as the kind the operator configured.
//
// A sensor that starts pairing with it runs the same key-bound exchange as
// every pairing. The request belongs to the token's tenant from the start
// (never to anything the sensor says), takes the token's presets (zones,
// grant profile, sensor type, labels) and, once the sensor reveals its
// nonce, is approved in the name of the token's creator; with "require
// approval" it waits for an administrator instead. Every enrolled sensor
// starts at trust level New (no credentials, no push ingest, passive work
// only), so a leaked token yields no more than that, in the preset zones,
// until it expires, runs out of uses or is revoked.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
)

const (
	maxEnrollmentTokensListed = 200
	maxPendingListed          = 100
	maxLabelValue             = 128
	maxGrantProfileLen        = 64
	actorEnrollment           = "sensor (enrollment token)"
)

var labelKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,62}$`)

// SetEnrollmentTokens wires the organization enrollment token store
// (postgres.SensorPairingRepository). Without it every token is looked up
// as an instance token only, and the token routes answer 404.
func (s *Service) SetEnrollmentTokens(r sensordom.EnrollmentTokenRepository) { s.tokens = r }

// EnrollmentEnabled reports whether organization enrollment tokens are wired.
func (s *Service) EnrollmentEnabled() bool { return s.tokens != nil }

// CreateEnrollmentTokenInput describes a new organization enrollment token.
type CreateEnrollmentTokenInput struct {
	Name            string
	TTL             time.Duration
	MaxUses         int
	RequireApproval bool
	SensorType      sensordom.SensorType
	GrantProfile    string
	ZoneIDs         []shared.ID
	Labels          map[string]string
	AllowedCIDRs    []string
}

// EnrollmentTokenView is what an administrator sees of a token; Token is set
// only in the answer to its creation (shown once, never stored).
type EnrollmentTokenView struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Token           string            `json:"token,omitempty"`
	TokenHint       string            `json:"token_hint"`
	State           string            `json:"state"`
	MaxUses         int               `json:"max_uses"`
	UseCount        int               `json:"use_count"`
	RequireApproval bool              `json:"require_approval"`
	SensorType      string            `json:"sensor_type"`
	GrantProfile    string            `json:"grant_profile,omitempty"`
	ZoneIDs         []string          `json:"zone_ids"`
	Labels          map[string]string `json:"labels"`
	AllowedCIDRs    []string          `json:"allowed_cidrs"`
	CreatedBy       string            `json:"created_by,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	LastUsedAt      *time.Time        `json:"last_used_at,omitempty"`
	LastUsedFrom    string            `json:"last_used_from,omitempty"`
	RevokedAt       *time.Time        `json:"revoked_at,omitempty"`
}

func (s *Service) tokenView(t *sensordom.EnrollmentToken) *EnrollmentTokenView {
	v := &EnrollmentTokenView{ID: t.ID.String(), Name: t.Name, TokenHint: t.TokenHint, State: t.State(s.now()),
		MaxUses: t.MaxUses, UseCount: t.UseCount, RequireApproval: t.RequireApproval, SensorType: string(t.SensorType),
		GrantProfile: t.GrantProfile, ZoneIDs: make([]string, 0, len(t.ZoneIDs)), Labels: t.Labels,
		AllowedCIDRs: make([]string, 0, len(t.AllowedCIDRs)), CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt}
	for _, z := range t.ZoneIDs {
		v.ZoneIDs = append(v.ZoneIDs, z.String())
	}
	for _, p := range t.AllowedCIDRs {
		v.AllowedCIDRs = append(v.AllowedCIDRs, p.String())
	}
	if v.Labels == nil {
		v.Labels = map[string]string{}
	}
	if t.CreatedBy != nil {
		v.CreatedBy = t.CreatedBy.String()
	}
	if t.LastUsedFrom != nil {
		v.LastUsedFrom = t.LastUsedFrom.String()
	}
	return v
}

// enrollmentTokenHash is the keyed hash an organization token is stored and
// looked up under (a label of its own: an instance token's hash never
// matches it).
func (s *Service) enrollmentTokenHash(token string) string {
	m := hmac.New(sha256.New, s.codeKey)
	m.Write([]byte("openctem/sensor-enrollment-token/v1\x00"))
	m.Write([]byte(token))
	return hex.EncodeToString(m.Sum(nil))
}

// CreateEnrollmentToken mints a token for the actor's tenant. The route has
// checked sensors:approve and the step-up window.
func (s *Service) CreateEnrollmentToken(ctx context.Context, actor Actor, in CreateEnrollmentTokenInput) (*EnrollmentTokenView, error) {
	if s.tokens == nil {
		return nil, ErrNotFound
	}
	t, err := s.validateTokenInput(ctx, actor, in)
	if err != nil {
		return nil, err
	}
	token, err := sensorkey.New(sensorkey.PrefixEnrollmentToken)
	if err != nil {
		return nil, err
	}
	t.TokenHash, t.TokenHint = s.enrollmentTokenHash(token), token[len(token)-4:]
	if err := s.tokens.CreateEnrollmentToken(ctx, t); err != nil {
		return nil, err
	}
	approval := "automatic"
	if t.RequireApproval {
		approval = "required"
	}
	msg := fmt.Sprintf("Created sensor enrollment token %q: %d uses, expires %s, approval %s",
		t.Name, t.MaxUses, t.ExpiresAt.Format(time.RFC3339), approval)
	s.logAudit(ctx, s.auditContext(actor), auditapp.NewSuccessEvent(auditdom.ActionSensorEnrollmentTokenCreated,
		auditdom.ResourceTypeSensor, t.ID.String()).WithResourceName(t.Name).WithMessage(msg).
		WithSeverity(auditdom.SeverityHigh).WithMetadata("max_uses", t.MaxUses).
		WithMetadata("expires_at", t.ExpiresAt).WithMetadata("require_approval", t.RequireApproval).
		WithMetadata("grant_profile", t.GrantProfile).WithMetadata("zone_ids", t.ZoneIDs).
		WithMetadata("allowed_cidrs", prefixStrings(t.AllowedCIDRs)).WithMetadata("token_hint", t.TokenHint))
	s.notifyAdmins(ctx, actor.TenantID, "Sensor enrollment token created: "+t.Name, msg+" (by "+actor.Email+")", "high")
	v := s.tokenView(t)
	v.Token = token
	return v, nil
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func (s *Service) validateTokenInput(ctx context.Context, actor Actor, in CreateEnrollmentTokenInput) (*sensordom.EnrollmentToken, error) {
	invalid := func(msg string) error { return fmt.Errorf("%w: %s", shared.ErrValidation, msg) }
	name := sanitizeName(in.Name)
	if name == "" {
		return nil, invalid("a name is required")
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = sensordom.DefaultEnrollmentTokenTTL
	}
	if ttl < sensordom.MinEnrollmentTokenTTL || ttl > sensordom.MaxEnrollmentTokenTTL {
		return nil, invalid("the lifetime must be between 1 hour and 30 days")
	}
	uses := in.MaxUses
	if uses == 0 {
		uses = sensordom.DefaultEnrollmentTokenUses
	}
	if uses < 1 || uses > sensordom.MaxEnrollmentTokenUses {
		return nil, invalid("max uses must be between 1 and 1000")
	}
	typ := in.SensorType
	if typ == "" {
		typ = sensordom.SensorTypeWorker
	}
	if !typ.IsValid() {
		return nil, invalid("unknown sensor type")
	}
	profile := strings.TrimSpace(in.GrantProfile)
	if len(profile) > maxGrantProfileLen || (profile != "" && s.hook != nil && !s.hook.ValidProfile(profile)) {
		return nil, invalid("unknown grant profile")
	}
	if len(in.Labels) > sensordom.MaxEnrollmentTokenLabels {
		return nil, invalid("at most 20 labels")
	}
	labels := make(map[string]string, len(in.Labels))
	for k, v := range in.Labels {
		if !labelKeyRE.MatchString(k) || len(v) > maxLabelValue || cleanFact(v) != v {
			return nil, invalid("labels are lower-case keys and printable values of at most 128 characters")
		}
		labels[k] = v
	}
	if len(in.AllowedCIDRs) > sensordom.MaxEnrollmentTokenCIDRs {
		return nil, invalid("at most 20 source ranges")
	}
	cidrs := make([]netip.Prefix, 0, len(in.AllowedCIDRs))
	for _, c := range in.AllowedCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, invalid("source ranges are CIDRs, e.g. 203.0.113.0/24")
		}
		cidrs = append(cidrs, p.Masked())
	}
	zones := dedupIDs(in.ZoneIDs)
	ok, err := s.tokens.ZonesInTenant(ctx, actor.TenantID, zones)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, invalid("unknown scan zone")
	}
	now := s.now().UTC().Truncate(time.Second)
	uid := actor.UserID
	return &sensordom.EnrollmentToken{ID: shared.NewID(), TenantID: actor.TenantID, Name: name, MaxUses: uses,
		RequireApproval: in.RequireApproval, SensorType: typ, GrantProfile: profile, ZoneIDs: zones, Labels: labels,
		AllowedCIDRs: cidrs, CreatedBy: &uid, CreatedAt: now, ExpiresAt: now.Add(ttl)}, nil
}

func dedupIDs(ids []shared.ID) []shared.ID {
	out := make([]shared.ID, 0, len(ids))
	seen := map[shared.ID]bool{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// ListEnrollmentTokens returns the actor's tenant's tokens (never a token).
func (s *Service) ListEnrollmentTokens(ctx context.Context, actor Actor) ([]*EnrollmentTokenView, error) {
	if s.tokens == nil {
		return nil, ErrNotFound
	}
	ts, err := s.tokens.ListEnrollmentTokens(ctx, actor.TenantID, maxEnrollmentTokensListed)
	if err != nil {
		return nil, err
	}
	out := make([]*EnrollmentTokenView, 0, len(ts))
	for _, t := range ts {
		out = append(out, s.tokenView(t))
	}
	return out, nil
}

// RevokeEnrollmentToken stops a token of the actor's tenant at once. Sensors
// it already enrolled keep their identity (revoke them one by one).
func (s *Service) RevokeEnrollmentToken(ctx context.Context, actor Actor, id shared.ID) (*EnrollmentTokenView, error) {
	if s.tokens == nil {
		return nil, ErrNotFound
	}
	t, err := s.tokens.RevokeEnrollmentToken(ctx, actor.TenantID, id, actor.UserID, s.now())
	if err != nil {
		return nil, ErrNotFound
	}
	s.logAudit(ctx, s.auditContext(actor), auditapp.NewSuccessEvent(auditdom.ActionSensorEnrollmentTokenRevoked,
		auditdom.ResourceTypeSensor, t.ID.String()).WithResourceName(t.Name).
		WithMessage(fmt.Sprintf("Revoked sensor enrollment token %q after %d of %d uses", t.Name, t.UseCount, t.MaxUses)).
		WithSeverity(auditdom.SeverityMedium).WithMetadata("token_hint", t.TokenHint))
	return s.tokenView(t), nil
}

// ListPending returns the requests of the actor's tenant that wait for an
// administrator: token-bound requests of tokens that require approval, and
// expectations a sensor attached to.
func (s *Service) ListPending(ctx context.Context, actor Actor) ([]*View, error) {
	if s.tokens == nil {
		return []*View{}, nil
	}
	ps, err := s.tokens.ListPendingForTenant(ctx, actor.TenantID, s.now(), maxPendingListed)
	if err != nil {
		return nil, err
	}
	out := make([]*View, 0, len(ps))
	for _, p := range ps {
		out = append(out, s.view(ctx, actor, p))
	}
	return out, nil
}

// startEnrollment spends an organization token and records the request.
// Every unusable token (malformed, unknown, expired, used up, revoked, from
// a source outside its ranges, of a creator who left) is ErrEnrollmentRefused.
func (s *Service) startEnrollment(ctx context.Context, token string, p *sensordom.Pairing) error {
	if s.tokens == nil || !wellFormedInstanceToken(token) {
		s.log.Warn("sensor enrollment refused: malformed token or no token store", "source_ip", p.SourceIP)
		return ErrEnrollmentRefused
	}
	hash := s.enrollmentTokenHash(token)
	p.RequestedName = sanitizeName(firstNonEmpty(p.HostFacts.Name, p.HostFacts.Hostname))
	t, refusal, err := s.tokens.StartWithEnrollmentTokenUnscoped(ctx, hash, p, s.now())
	if err != nil {
		return err
	}
	// The row was found by its hash; compare again in constant time.
	if t == nil || !hmac.Equal([]byte(t.TokenHash), []byte(hash)) {
		s.log.Warn("sensor enrollment refused: unknown token", "source_ip", p.SourceIP)
		return ErrEnrollmentRefused
	}
	if refusal != sensordom.EnrollmentOK {
		s.log.Warn("sensor enrollment refused", "reason", string(refusal), "source_ip", p.SourceIP)
		s.logAudit(ctx, auditapp.AuditContext{TenantID: t.TenantID.String(), ActorEmail: actorEnrollment, ActorIP: ipString(p)},
			auditapp.NewFailureEvent(auditdom.ActionSensorEnrollmentRefused, auditdom.ResourceTypeSensor, t.ID.String(),
				errors.New(string(refusal))).WithResourceName(t.Name).
				WithMessage(fmt.Sprintf("A sensor was refused enrollment with token %q (%s)", t.Name, refusal)).
				WithSeverity(auditdom.SeverityMedium).WithMetadata("reason", string(refusal)).
				WithMetadata("key_fingerprint", pairing.KeyFingerprint(p.Thumbprint)).
				WithMetadata("host_facts", auditHostFacts(p.HostFacts)))
		return ErrEnrollmentRefused
	}
	return nil
}

// approveEnrollment runs when a token-bound request revealed its nonce: it
// approves the request in the token creator's name with the token's
// presets, or, for a token that requires approval, tells the
// administrators a sensor waits. A request already approved is left alone.
func (s *Service) approveEnrollment(ctx context.Context, p *sensordom.Pairing) error {
	if s.tokens == nil || p.TenantID == nil {
		return nil
	}
	t, err := s.tokens.GetEnrollmentTokenUnscoped(ctx, *p.EnrollmentTokenID)
	if err != nil || t.TenantID != *p.TenantID {
		return ErrNotFound
	}
	name := sanitizeName(firstNonEmpty(p.RequestedName, p.HostFacts.Name, p.HostFacts.Hostname))
	if name == "" {
		name = "sensor-" + p.Thumbprint[:8]
	}
	from := ipString(p)
	if t.RequireApproval {
		s.notifyAdmins(ctx, t.TenantID, "Sensor waits for approval: "+name,
			fmt.Sprintf("Sensor %q enrolled with token %q from %s; fingerprint %s. Compare it and approve under Sensors > Enrollment tokens.",
				name, t.Name, from, p.SAS), "high")
		return nil
	}
	if t.CreatedBy == nil {
		return ErrEnrollmentRefused
	}
	now := s.now()
	profile := t.GrantProfile
	if s.hook != nil && profile == "" {
		profile = s.hook.DefaultProfileFor(t.SensorType)
	}
	approval := sensordom.PairingApproval{
		PairingID: p.ID, TenantID: t.TenantID, ApprovedBy: *t.CreatedBy, Now: now, ConfirmBy: now.Add(ConfirmWindow),
		SensorID: shared.NewID(), Name: name, Type: t.SensorType, Hostname: p.HostFacts.Hostname, OS: p.HostFacts.OS,
		Arch: p.HostFacts.Arch, Version: p.HostFacts.SensorVersion, ZoneIDs: t.ZoneIDs, KeyID: shared.NewID(),
	}
	var grant func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error
	if s.hook != nil {
		grant = s.hook.OnApproved(t.TenantID, profile, t.ZoneIDs, *t.CreatedBy)
	}
	approval.OnApproved = withLabels(grant, t.TenantID, t.Labels)
	res, err := s.repo.Approve(ctx, approval, nil)
	if errors.Is(err, sensordom.ErrPairingNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("Sensor %q enrolled with token %q from %s; fingerprint %s (%s), grant profile %s",
		name, t.Name, from, res.Pairing.SAS, pairing.KeyFingerprint(p.Thumbprint), profile)
	s.logAudit(ctx, auditapp.AuditContext{TenantID: t.TenantID.String(), ActorEmail: actorEnrollment, ActorIP: from},
		auditapp.NewSuccessEvent(auditdom.ActionSensorEnrolled, auditdom.ResourceTypeSensor, res.SensorID.String()).
			WithResourceName(name).WithMessage(msg).WithSeverity(auditdom.SeverityHigh).
			WithMetadata("pairing_id", p.ID.String()).WithMetadata("enrollment_token_id", t.ID.String()).
			WithMetadata("enrollment_token", t.Name).WithMetadata("sas", res.Pairing.SAS).
			WithMetadata("key_fingerprint", pairing.KeyFingerprint(p.Thumbprint)).
			WithMetadata("host_facts", auditHostFacts(p.HostFacts)).WithMetadata("grant_profile", profile))
	s.notifyAdmins(ctx, t.TenantID, "Sensor enrolled: "+name, msg, "high")
	return nil
}

// withLabels runs grant, then sets the token's labels on the new sensor, in
// the approval transaction.
func withLabels(grant func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error,
	tenantID shared.ID, labels map[string]string) func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error {
	return func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error {
		if grant != nil {
			if err := grant(ctx, tx, sensorID, repair); err != nil {
				return err
			}
		}
		if len(labels) == 0 {
			return nil
		}
		b, err := json.Marshal(labels)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE sensors SET labels = COALESCE(labels, '{}'::jsonb) || $3::jsonb
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), sensorID.String(), b)
		return err
	}
}
