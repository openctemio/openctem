// Package sensorpairing is interactive sensor pairing
// (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §4): a sensor that
// holds only the platform URL asks to pair with its own Ed25519 key, both
// sides show a short authentication string (SAS), and an administrator binds
// the key to the organization after comparing it, re-authenticating and
// ticking "the fingerprint matches". No secret is ever handled by a person.
package sensorpairing

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// Limits (RFC-052 §4.4).
const (
	// DefaultMaxOpen caps open default-mode requests platform-wide.
	DefaultMaxOpen = 1000
	// ConfirmWindow is how long an approved pairing waits for the sensor.
	ConfirmWindow = 10 * time.Minute
	// PurgeAfter is how long finished rows are kept (the audit log keeps
	// the record for ever).
	PurgeAfter = 30 * 24 * time.Hour
	// PollSeconds is the poll interval the platform advises.
	PollSeconds = 3
	// LookupFailureLimit failed lookups per user per LookupFailureWindow
	// lock lookups for that user for the rest of the window.
	LookupFailureLimit  = 20
	LookupFailureWindow = time.Hour

	maxHostFact  = 128
	maxNameLen   = 128
	sweepEvery   = time.Minute
	codeAttempts = 4
)

// Errors the handlers map. Every "not found" case is ErrNotFound, whatever
// the reason (uniform answers).
var (
	ErrNotFound            = sensordom.ErrPairingNotFound
	ErrCapacity            = sensordom.ErrPairingCapacity
	ErrInvalid             = errors.New("invalid pairing request")
	ErrFingerprintRequired = errors.New("the fingerprint must be confirmed")
	ErrLookupLocked        = errors.New("too many failed lookups")
	ErrStepUpRequired      = authapp.ErrStepUpRequired
	ErrStepUpFailed        = authapp.ErrStepUpFailed
)

// StepUpVerifier re-authenticates the approving user (auth.AuthService).
type StepUpVerifier interface {
	VerifyStepUp(ctx context.Context, userID, sessionID string, proof authapp.StepUpProof) error
	StepUpMethodFor(ctx context.Context, userID string) (authapp.StepUpMethod, error)
}

// AdminDirectory lists a tenant's active owners and administrators.
type AdminDirectory interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// InAppNotifier sends one in-app notification.
type InAppNotifier interface {
	Notify(ctx context.Context, p notificationdom.NotificationParams) error
}

// EventRecorder writes sensor timeline events.
type EventRecorder interface {
	RecordEvents(ctx context.Context, events []sensordom.Event)
}

// SensorLookup confirms that a re-pair target is a sensor of the tenant.
type SensorLookup interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sensordom.Sensor, error)
}

// ApprovalHook runs inside the approval transaction (the grant, RFC-052
// §5); ValidProfile says whether a profile may be chosen for a new sensor.
type ApprovalHook interface {
	ValidProfile(profile string) bool
	DefaultProfile() string
	OnApproved(tenantID shared.ID, profile string, zones []shared.ID, approvedBy shared.ID) func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error
}

// Actor is the authenticated user acting on the user plane.
type Actor struct {
	TenantID  shared.ID
	UserID    shared.ID
	SessionID string
	Email     string
	IP        string
	UserAgent string
}

// Service runs pairing.
type Service struct {
	repo     sensordom.PairingRepository
	sensors  SensorLookup
	events   EventRecorder
	audit    *auditapp.AuditService
	stepUp   StepUpVerifier
	admins   AdminDirectory
	notifier InAppNotifier
	hook     ApprovalHook
	log      *logger.Logger

	platformKey ed25519.PrivateKey
	codeKey     []byte
	maxOpen     int
	now         func() time.Time

	sweepMu   sync.Mutex
	lastSweep time.Time

	lookupMu       sync.Mutex
	lookupFailures map[shared.ID][]time.Time
}

// NewService builds the pairing service. secret derives the platform
// pairing key (APP_ENCRYPTION_KEY); codePepper keys the code hashes (the
// sensor-key pepper).
func NewService(repo sensordom.PairingRepository, sensors SensorLookup, secret, codePepper string, log *logger.Logger) (*Service, error) {
	key, err := DerivePlatformKey(secret)
	if err != nil {
		return nil, err
	}
	if codePepper == "" {
		return nil, fmt.Errorf("%w: pairing needs a code pepper", shared.ErrValidation)
	}
	return &Service{repo: repo, sensors: sensors, log: log.With("service", "sensor-pairing"),
		platformKey: key, codeKey: []byte(codePepper), maxOpen: DefaultMaxOpen, now: time.Now,
		lookupFailures: map[shared.ID][]time.Time{}}, nil
}

// SetAudit, SetStepUp, SetNotifications, SetEvents, SetApprovalHook wire the
// collaborators. Without a step-up verifier every approval is refused.
func (s *Service) SetAudit(a *auditapp.AuditService) { s.audit = a }
func (s *Service) SetStepUp(v StepUpVerifier)        { s.stepUp = v }
func (s *Service) SetNotifications(d AdminDirectory, n InAppNotifier) {
	s.admins, s.notifier = d, n
}
func (s *Service) SetEvents(e EventRecorder)      { s.events = e }
func (s *Service) SetApprovalHook(h ApprovalHook) { s.hook = h }
func (s *Service) SetMaxOpen(n int)               { s.maxOpen = n }
func (s *Service) SetClock(now func() time.Time)  { s.now = now }
func (s *Service) PlatformPublicKey() ed25519.PublicKey {
	pub, _ := s.platformKey.Public().(ed25519.PublicKey)
	return pub
}

// DerivePlatformKey derives the platform pairing key from the
// installation's secret (HKDF-SHA256, info
// "openctem/sensor-pairing/platform-key/v1").
func DerivePlatformKey(secret string) (ed25519.PrivateKey, error) {
	if len(secret) < 16 {
		return nil, fmt.Errorf("%w: pairing needs the installation encryption key", shared.ErrValidation)
	}
	seed, err := hkdf.Key(sha256.New, []byte(secret), nil, "openctem/sensor-pairing/platform-key/v1", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// codeHash is the keyed hash a code is stored and looked up under.
func (s *Service) codeHash(code string) string {
	m := hmac.New(sha256.New, s.codeKey)
	m.Write([]byte("openctem/sensor-pairing/code/v1\x00"))
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

// ---------------------------------------------------------------------------
// Sensor plane
// ---------------------------------------------------------------------------

// StartInput is a verified start request: the handler already checked the
// request signature against PublicKey.
type StartInput struct {
	Request   pairing.StartRequest
	PublicKey ed25519.PublicKey
	SourceIP  net.IP
}

// Start records a pairing request and returns the platform's answer. A
// reverse-mode code that matches nothing gets the same answer as one that
// does; the request then never becomes approvable and expires.
func (s *Service) Start(ctx context.Context, in StartInput) (*pairing.StartResponse, error) {
	s.sweep(ctx)
	req := in.Request
	if req.Protocol != pairing.Version || len(in.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	commitment, err := pairing.DecodeFixed(req.Commitment, sha256.Size)
	if err != nil {
		return nil, ErrInvalid
	}
	var repair *shared.ID
	if req.SensorID != "" {
		id, err := shared.IDFromString(req.SensorID)
		if err != nil {
			return nil, ErrInvalid
		}
		repair = &id
	}
	var code string
	if req.Code != "" {
		if code, err = pairing.NormalizeCode(req.Code); err != nil {
			return nil, ErrInvalid
		}
	}
	now := s.now()
	open, err := s.repo.CountOpenUnscoped(ctx, now)
	if err != nil {
		return nil, err
	}
	if open >= s.maxOpen {
		s.log.Warn("sensor pairing: open-request cap reached", "open", open)
		return nil, ErrCapacity
	}
	nonce, err := pairing.NewNonce()
	if err != nil {
		return nil, err
	}
	p := &sensordom.Pairing{
		ID: shared.NewID(), Mode: sensordom.PairingForward, Status: sensordom.PairingPending,
		PublicKey: in.PublicKey, Thumbprint: sensorsig.Thumbprint(in.PublicKey), Commitment: commitment,
		PlatformNonce: nonce, HostFacts: sanitizeHostFacts(req.Host), SourceIP: in.SourceIP,
		RepairSensorID: repair, CreatedAt: now, ExpiresAt: now.Add(pairing.TTL).Truncate(time.Second),
	}
	userCode := ""
	switch {
	case code != "":
		ok, err := s.repo.AttachToExpectationUnscoped(ctx, s.codeHash(code), p, now)
		if err != nil {
			return nil, err
		}
		if !ok {
			// Same answer as a match: a request no code can ever reach.
			p.CodeHash = ""
			if err := s.repo.CreateForward(ctx, p); err != nil {
				return nil, err
			}
		}
	default:
		if userCode, err = s.createWithCode(ctx, p); err != nil {
			return nil, err
		}
	}
	pub := s.PlatformPublicKey()
	sig := ed25519.Sign(s.platformKey, pairing.PlatformTranscript(p.ID.String(), p.PublicKey, commitment, pub, nonce, p.ExpiresAt))
	resp := &pairing.StartResponse{
		PairingID: p.ID.String(), PlatformKey: pairing.Encode(pub), PlatformNonce: pairing.Encode(nonce),
		PlatformSignature: pairing.Encode(sig), ExpiresAt: p.ExpiresAt, PollSeconds: PollSeconds,
	}
	if userCode != "" {
		resp.UserCode = pairing.FormatCode(userCode)
	}
	return resp, nil
}

// createWithCode inserts a default-mode request under a fresh code,
// retrying on the (rare) collision with another open code.
func (s *Service) createWithCode(ctx context.Context, p *sensordom.Pairing) (string, error) {
	var lastErr error
	for range codeAttempts {
		code, err := pairing.NewCode()
		if err != nil {
			return "", err
		}
		p.CodeHash = s.codeHash(code)
		if err := s.repo.CreateForward(ctx, p); err != nil {
			if errors.Is(err, shared.ErrConflict) {
				lastErr = err
				continue
			}
			return "", err
		}
		return code, nil
	}
	return "", lastErr
}

// Reveal opens the sensor's commitment and fixes the SAS.
func (s *Service) Reveal(ctx context.Context, id shared.ID, thumbprint string, req pairing.RevealRequest) error {
	p, err := s.repo.GetForKeyUnscoped(ctx, id, thumbprint)
	if err != nil {
		return ErrNotFound
	}
	nonce, err := pairing.DecodeFixed(req.SensorNonce, pairing.NonceSize)
	if err != nil {
		return ErrInvalid
	}
	now := s.now()
	if p.Status != sensordom.PairingPending || !now.Before(p.ExpiresAt) {
		return ErrNotFound
	}
	if p.Revealed() {
		if hmac.Equal(p.SensorNonce, nonce) {
			return nil // a retried reveal
		}
		return ErrNotFound
	}
	if err := pairing.CheckCommitment(p.Commitment, nonce); err != nil {
		return ErrInvalid
	}
	sas := pairing.ComputeSAS(p.PublicKey, s.PlatformPublicKey(), nonce, p.PlatformNonce).String()
	ok, err := s.repo.RevealUnscoped(ctx, id, thumbprint, nonce, sas, now)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	return nil
}

// Status is the sensor's poll.
func (s *Service) Status(ctx context.Context, id shared.ID, thumbprint string) (*pairing.StatusResponse, error) {
	p, err := s.repo.GetForKeyUnscoped(ctx, id, thumbprint)
	if err != nil {
		return nil, ErrNotFound
	}
	now := s.now()
	out := &pairing.StatusResponse{Status: string(p.Status), ExpiresAt: p.ExpiresAt, PollSeconds: PollSeconds}
	switch p.Status {
	case sensordom.PairingPending, sensordom.PairingApproved:
		if !now.Before(p.ExpiresAt) {
			out.Status = pairing.StatusExpired
			return out, nil
		}
	case sensordom.PairingExpecting:
		out.Status = pairing.StatusPending
	}
	if (p.Status == sensordom.PairingApproved || p.Status == sensordom.PairingCompleted) && p.TenantID != nil && p.SensorID != nil {
		ident := &pairing.Identity{SensorID: p.SensorID.String(), TenantID: p.TenantID.String(), Name: p.RequestedName,
			KeyID: p.Thumbprint, Repair: p.RepairSensorID != nil}
		if p.ApprovedAt != nil {
			ident.ApprovedAt = *p.ApprovedAt
		}
		out.Identity = ident
	}
	return out, nil
}

// Confirm checks the sensor's signed statement over its identity and
// activates the key.
func (s *Service) Confirm(ctx context.Context, id shared.ID, thumbprint string, req pairing.ConfirmRequest) (*pairing.StatusResponse, error) {
	p, err := s.repo.GetForKeyUnscoped(ctx, id, thumbprint)
	if err != nil || p.TenantID == nil || p.SensorID == nil {
		return nil, ErrNotFound
	}
	sig, err := pairing.DecodeFixed(req.Signature, ed25519.SignatureSize)
	if err != nil || req.SensorID != p.SensorID.String() || req.KeyID != thumbprint {
		return nil, ErrInvalid
	}
	msg := pairing.ConfirmTranscript(id.String(), p.SensorID.String(), p.TenantID.String(), thumbprint)
	if !ed25519.Verify(ed25519.PublicKey(p.PublicKey), msg, sig) {
		return nil, ErrInvalid
	}
	wasDone := p.Status == sensordom.PairingCompleted
	done, err := s.repo.ConfirmUnscoped(ctx, id, thumbprint, s.now())
	if err != nil {
		return nil, ErrNotFound
	}
	if !wasDone {
		s.onCompleted(ctx, done)
	}
	return s.Status(ctx, id, thumbprint)
}

func (s *Service) onCompleted(ctx context.Context, p *sensordom.Pairing) {
	details := map[string]any{"key_fingerprint": pairing.KeyFingerprint(p.Thumbprint), "sas": p.SAS, "pairing_id": p.ID.String()}
	if p.SourceIP != nil {
		details["source_ip"] = p.SourceIP.String()
	}
	if s.events != nil {
		s.events.RecordEvents(ctx, []sensordom.Event{sensordom.NewEvent(*p.TenantID, *p.SensorID, sensordom.EventPairingCompleted, s.now(),
			"The sensor confirmed its pairing; key "+pairing.KeyFingerprint(p.Thumbprint)+" is active", details)})
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionSensorPairingCompleted, auditdom.ResourceTypeSensor, p.SensorID.String()).
		WithResourceName(p.RequestedName).
		WithMessage("Sensor confirmed its pairing; key " + pairing.KeyFingerprint(p.Thumbprint) + " is active").
		WithSeverity(auditdom.SeverityMedium)
	for k, v := range details {
		ev = ev.WithMetadata(k, v)
	}
	s.logAudit(ctx, auditapp.AuditContext{TenantID: p.TenantID.String(), ActorEmail: "sensor"}, ev)
}

// ---------------------------------------------------------------------------
// User plane
// ---------------------------------------------------------------------------

// View is what an administrator sees of a pairing request.
type View struct {
	ID             string                     `json:"id"`
	Mode           string                     `json:"mode"`
	Status         string                     `json:"status"`
	SAS            string                     `json:"sas,omitempty"`
	KeyFingerprint string                     `json:"key_fingerprint,omitempty"`
	HostFacts      sensordom.PairingHostFacts `json:"host_facts"`
	SourceIP       string                     `json:"source_ip,omitempty"`
	RepairSensorID string                     `json:"repair_sensor_id,omitempty"`
	RepairSensor   string                     `json:"repair_sensor_name,omitempty"`
	SensorID       string                     `json:"sensor_id,omitempty"`
	Code           string                     `json:"code,omitempty"`
	CreatedAt      time.Time                  `json:"created_at"`
	ExpiresAt      time.Time                  `json:"expires_at"`
	// StepUp is what the viewer must present to approve ("totp",
	// "password" or "fresh_sign_in").
	StepUp string `json:"step_up,omitempty"`
}

func (s *Service) view(ctx context.Context, actor Actor, p *sensordom.Pairing) *View {
	v := &View{ID: p.ID.String(), Mode: string(p.Mode), Status: string(p.Status), SAS: p.SAS,
		HostFacts: p.HostFacts, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt}
	if p.Thumbprint != "" {
		v.KeyFingerprint = pairing.KeyFingerprint(p.Thumbprint)
	}
	if p.SourceIP != nil {
		v.SourceIP = p.SourceIP.String()
	}
	if p.SensorID != nil {
		v.SensorID = p.SensorID.String()
	}
	if p.RepairSensorID != nil && s.sensors != nil {
		if sen, err := s.sensors.GetByTenantAndID(ctx, actor.TenantID, *p.RepairSensorID); err == nil && sen != nil {
			v.RepairSensorID, v.RepairSensor = sen.ID.String(), sen.Name
		}
	}
	if (p.Status == sensordom.PairingPending || p.Status == sensordom.PairingExpecting) && !s.now().Before(p.ExpiresAt) {
		v.Status = string(sensordom.PairingExpired)
	}
	if s.stepUp != nil {
		if m, err := s.stepUp.StepUpMethodFor(ctx, actor.UserID.String()); err == nil {
			v.StepUp = string(m)
		}
	}
	return v
}

// Lookup finds the open, revealed default-mode request with code. Unknown,
// expired, used, unrevealed and foreign re-pair codes are all ErrNotFound.
func (s *Service) Lookup(ctx context.Context, actor Actor, code string) (*View, error) {
	if s.lookupLocked(actor.UserID) {
		return nil, ErrLookupLocked
	}
	norm, err := pairing.NormalizeCode(code)
	if err != nil {
		s.lookupFailed(actor.UserID)
		return nil, ErrNotFound
	}
	p, err := s.repo.FindOpenByCodeHash(ctx, s.codeHash(norm), s.now())
	if err != nil {
		s.lookupFailed(actor.UserID)
		return nil, ErrNotFound
	}
	if p.RepairSensorID != nil && !s.sensorInTenant(ctx, actor.TenantID, *p.RepairSensorID) {
		s.lookupFailed(actor.UserID)
		return nil, ErrNotFound
	}
	return s.view(ctx, actor, p), nil
}

// ExpectInput is a reverse-mode request.
type ExpectInput struct {
	Name           string
	ZoneIDs        []shared.ID
	Profile        string
	RepairSensorID *shared.ID
}

// Expect creates a reverse-mode code for the actor's tenant.
func (s *Service) Expect(ctx context.Context, actor Actor, in ExpectInput) (*View, error) {
	if in.RepairSensorID != nil && !s.sensorInTenant(ctx, actor.TenantID, *in.RepairSensorID) {
		return nil, ErrNotFound
	}
	if in.Profile != "" && s.hook != nil && !s.hook.ValidProfile(in.Profile) {
		return nil, ErrInvalid
	}
	now := s.now()
	tid, uid := actor.TenantID, actor.UserID
	p := &sensordom.Pairing{ID: shared.NewID(), Mode: sensordom.PairingReverse, Status: sensordom.PairingExpecting,
		TenantID: &tid, RepairSensorID: in.RepairSensorID, RequestedName: sanitizeName(in.Name),
		RequestedZoneIDs: in.ZoneIDs, RequestedProfile: in.Profile, CreatedBy: &uid,
		CreatedAt: now, ExpiresAt: now.Add(pairing.TTL).Truncate(time.Second)}
	var code string
	for range codeAttempts {
		c, err := pairing.NewCode()
		if err != nil {
			return nil, err
		}
		p.CodeHash = s.codeHash(c)
		err = s.repo.CreateExpectation(ctx, p)
		if errors.Is(err, shared.ErrConflict) {
			continue
		}
		if err != nil {
			return nil, err
		}
		code = c
		break
	}
	if code == "" {
		return nil, ErrCapacity
	}
	s.logAudit(ctx, s.auditContext(actor), auditapp.NewSuccessEvent(auditdom.ActionSensorPairingExpected, auditdom.ResourceTypeSensor, p.ID.String()).
		WithMessage("Created a code to pair a sensor (expect a sensor)").WithSeverity(auditdom.SeverityLow))
	v := s.view(ctx, actor, p)
	v.Code = pairing.FormatCode(code)
	return v, nil
}

// GetExpectation returns a request of the actor's tenant.
func (s *Service) GetExpectation(ctx context.Context, actor Actor, id shared.ID) (*View, error) {
	p, err := s.repo.GetForTenant(ctx, actor.TenantID, id)
	if err != nil {
		return nil, ErrNotFound
	}
	return s.view(ctx, actor, p), nil
}

// ApproveInput is the approval form.
type ApproveInput struct {
	// Code is the code the approver entered (default mode): approval needs
	// it, so knowing a request id alone never lets anyone claim it.
	Code                 string
	FingerprintConfirmed bool
	StepUp               authapp.StepUpProof
	Name                 string
	Type                 sensordom.SensorType
	ZoneIDs              []shared.ID
	Profile              string
}

// Approve binds the request's key to the actor's tenant (a new sensor, or
// the re-paired one). Order of checks: the confirmation box, step-up, then
// the request itself (so an attacker with a stolen session learns nothing
// about codes without the second factor).
func (s *Service) Approve(ctx context.Context, actor Actor, id shared.ID, in ApproveInput) (*View, error) {
	if !in.FingerprintConfirmed {
		return nil, ErrFingerprintRequired
	}
	if s.stepUp == nil {
		return nil, ErrStepUpRequired
	}
	if err := s.stepUp.VerifyStepUp(ctx, actor.UserID.String(), actor.SessionID, in.StepUp); err != nil {
		s.logAudit(ctx, s.auditContext(actor), auditapp.NewFailureEvent(auditdom.ActionSensorPairingApproved, auditdom.ResourceTypeSensor, id.String(), err).
			WithMessage("Sensor pairing approval refused: re-authentication failed").WithSeverity(auditdom.SeverityHigh))
		return nil, err
	}
	if in.Type == "" {
		in.Type = sensordom.SensorTypeWorker
	}
	if !in.Type.IsValid() {
		return nil, ErrInvalid
	}
	if in.Profile != "" && s.hook != nil && !s.hook.ValidProfile(in.Profile) {
		return nil, ErrInvalid
	}
	now := s.now()
	// Read the request as the approver may see it (theirs, or tenantless
	// and reached through its code).
	p, err := s.claimable(ctx, actor, id, in.Code, now)
	if err != nil {
		return nil, err
	}
	// The profile chosen now, else the one the expectation named, else the
	// narrow default.
	profile := firstNonEmpty(in.Profile, p.RequestedProfile)
	if s.hook != nil {
		if profile == "" {
			profile = s.hook.DefaultProfile()
		}
		if !s.hook.ValidProfile(profile) {
			return nil, ErrInvalid
		}
	}
	if p.RepairSensorID != nil && !s.sensorInTenant(ctx, actor.TenantID, *p.RepairSensorID) {
		return nil, ErrNotFound
	}
	name := sanitizeName(in.Name)
	if name == "" {
		name = sanitizeName(firstNonEmpty(p.RequestedName, p.HostFacts.Name, p.HostFacts.Hostname))
	}
	if name == "" {
		name = "sensor-" + p.Thumbprint[:8]
	}
	zones := in.ZoneIDs
	if len(zones) == 0 {
		zones = p.RequestedZoneIDs
	}
	approval := sensordom.PairingApproval{
		PairingID: p.ID, CodeHash: p.CodeHash, TenantID: actor.TenantID, ApprovedBy: actor.UserID, Now: now, ConfirmBy: now.Add(ConfirmWindow),
		SensorID: shared.NewID(), Name: name, Type: in.Type, Hostname: p.HostFacts.Hostname,
		OS: p.HostFacts.OS, Arch: p.HostFacts.Arch, Version: p.HostFacts.SensorVersion, ZoneIDs: zones, KeyID: shared.NewID(),
	}
	if s.hook != nil {
		approval.OnApproved = s.hook.OnApproved(actor.TenantID, profile, zones, actor.UserID)
	}
	res, err := s.repo.Approve(ctx, approval, nil)
	if err != nil {
		if errors.Is(err, sensordom.ErrPairingNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.onApproved(ctx, actor, res, name, profile)
	return s.view(ctx, actor, res.Pairing), nil
}

// claimable reads an open, revealed request the actor may approve: one of
// their tenant (reverse mode), or a tenantless default-mode request whose
// code they entered. The repository's approval re-checks every condition
// under a row lock.
func (s *Service) claimable(ctx context.Context, actor Actor, id shared.ID, code string, now time.Time) (*sensordom.Pairing, error) {
	if p, err := s.repo.GetForTenant(ctx, actor.TenantID, id); err == nil {
		if p.Status == sensordom.PairingPending && p.Revealed() && now.Before(p.ExpiresAt) {
			return p, nil
		}
		return nil, ErrNotFound
	}
	norm, err := pairing.NormalizeCode(code)
	if err != nil {
		return nil, ErrNotFound
	}
	p, err := s.repo.FindOpenByCodeHash(ctx, s.codeHash(norm), now)
	if err != nil || p.ID != id {
		return nil, ErrNotFound
	}
	return p, nil
}

func (s *Service) onApproved(ctx context.Context, actor Actor, res *sensordom.PairingApprovalResult, name, profile string) {
	p := res.Pairing
	action, verb := auditdom.ActionSensorPairingApproved, "paired"
	if res.Repair {
		action, verb = auditdom.ActionSensorRepaired, "re-paired"
	}
	from := "an unknown address"
	if p.SourceIP != nil {
		from = p.SourceIP.String()
	}
	msg := fmt.Sprintf("Sensor %q %s by %s from %s; fingerprint %s (%s), grant profile %s",
		name, verb, actor.Email, from, p.SAS, pairing.KeyFingerprint(p.Thumbprint), profile)
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeSensor, res.SensorID.String()).
		WithResourceName(name).WithMessage(msg).WithSeverity(auditdom.SeverityHigh).
		WithMetadata("pairing_id", p.ID.String()).WithMetadata("sas", p.SAS).
		WithMetadata("key_fingerprint", pairing.KeyFingerprint(p.Thumbprint)).
		WithMetadata("source_ip", from).WithMetadata("host_facts", p.HostFacts).
		WithMetadata("grant_profile", profile).WithMetadata("revoked_keys", res.RevokedKeys)
	s.logAudit(ctx, s.auditContext(actor), ev)
	s.notifyAdmins(ctx, actor.TenantID, "Sensor "+verb+": "+name, msg, "high")
}

// Deny refuses an open request.
func (s *Service) Deny(ctx context.Context, actor Actor, id shared.ID) error {
	p, err := s.repo.Deny(ctx, actor.TenantID, id, actor.UserID, s.now())
	if err != nil {
		return ErrNotFound
	}
	from := ""
	if p.SourceIP != nil {
		from = p.SourceIP.String()
	}
	s.logAudit(ctx, s.auditContext(actor), auditapp.NewSuccessEvent(auditdom.ActionSensorPairingDenied, auditdom.ResourceTypeSensor, p.ID.String()).
		WithMessage("Denied a sensor pairing request; fingerprint "+p.SAS).WithSeverity(auditdom.SeverityMedium).
		WithMetadata("key_fingerprint", pairing.KeyFingerprint(p.Thumbprint)).WithMetadata("source_ip", from))
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *Service) sensorInTenant(ctx context.Context, tenantID, id shared.ID) bool {
	if s.sensors == nil {
		return false
	}
	sen, err := s.sensors.GetByTenantAndID(ctx, tenantID, id)
	return err == nil && sen != nil && !sen.IsPlatformSensor && sen.Status != sensordom.SensorStatusRevoked
}

func (s *Service) auditContext(a Actor) auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: a.TenantID.String(), ActorID: a.UserID.String(), ActorEmail: a.Email,
		ActorIP: a.IP, UserAgent: a.UserAgent, SessionID: a.SessionID}
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.log.Warn("sensor pairing audit failed", "error", err)
	}
}

func (s *Service) notifyAdmins(ctx context.Context, tenantID shared.ID, title, body, severity string) {
	if s.admins == nil || s.notifier == nil {
		return
	}
	ids, err := s.admins.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		s.log.Warn("list admins for sensor notice", "error", err)
		return
	}
	for _, id := range ids {
		uid := id
		if err := s.notifier.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeSensorSecurity, Title: title, Body: body, Severity: severity,
			ResourceType: "sensor", URL: "/sensors",
		}); err != nil {
			s.log.Warn("notify admin of sensor pairing", "error", err)
		}
	}
}

// sweep expires stale requests at most once a minute (opportunistic, on the
// start path; nothing depends on it for correctness: every read checks the
// expiry itself, and a pending key never authenticates).
func (s *Service) sweep(ctx context.Context) {
	s.sweepMu.Lock()
	now := s.now()
	if now.Sub(s.lastSweep) < sweepEvery {
		s.sweepMu.Unlock()
		return
	}
	s.lastSweep = now
	s.sweepMu.Unlock()
	if _, err := s.repo.ExpireForPlatform(ctx, now, now.Add(-PurgeAfter)); err != nil {
		s.log.Warn("sensor pairing sweep failed", "error", err)
	}
}

func (s *Service) lookupLocked(user shared.ID) bool {
	s.lookupMu.Lock()
	defer s.lookupMu.Unlock()
	cut := s.now().Add(-LookupFailureWindow)
	kept := s.lookupFailures[user][:0]
	for _, t := range s.lookupFailures[user] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	s.lookupFailures[user] = kept
	return len(kept) >= LookupFailureLimit
}

func (s *Service) lookupFailed(user shared.ID) {
	s.lookupMu.Lock()
	defer s.lookupMu.Unlock()
	s.lookupFailures[user] = append(s.lookupFailures[user], s.now())
}

// sanitizeHostFacts bounds and cleans the claims a sensor sent.
func sanitizeHostFacts(h pairing.HostFacts) sensordom.PairingHostFacts {
	return sensordom.PairingHostFacts{
		Hostname: cleanFact(h.Hostname), OS: cleanFact(h.OS), Arch: cleanFact(h.Arch),
		SensorVersion: cleanFact(h.SensorVersion), SDKVersion: cleanFact(h.SDKVersion),
		Product: cleanFact(h.Product), InstanceID: sensordom.SanitizeInstanceID(h.InstanceID), Name: sanitizeName(h.Name),
	}
}

// cleanFact keeps printable characters except bidi controls, bounded.
func cleanFact(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if !unicode.IsPrint(r) || unicode.Is(unicode.Bidi_Control, r) {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxHostFact {
			break
		}
	}
	return b.String()
}

func sanitizeName(s string) string {
	s = cleanFact(s)
	if len(s) > maxNameLen {
		s = s[:maxNameLen]
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// PublicKeyFor returns the key a pairing request is bound to, when the
// request exists and was made with the key with this thumbprint.
func (s *Service) PublicKeyFor(ctx context.Context, id shared.ID, thumbprint string) (ed25519.PublicKey, error) {
	p, err := s.repo.GetForKeyUnscoped(ctx, id, thumbprint)
	if err != nil || len(p.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrNotFound
	}
	return ed25519.PublicKey(p.PublicKey), nil
}
