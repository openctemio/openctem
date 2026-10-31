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
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jobsign"
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
	// ErrFingerprintMismatch: the approver picked a fingerprint the host
	// did not show. The request is closed (a coached approver gets one try)
	// and every administrator is told.
	ErrFingerprintMismatch = errors.New("the picked fingerprint is not the sensor's")
	ErrLookupLocked        = errors.New("too many failed lookups")
	// ErrOrganizationMismatch: the approval names another organization than
	// the session's (the approver switched organization after the review).
	ErrOrganizationMismatch = errors.New("the approval names another organization")
	// ErrKeyRegistered: the key was already registered to a sensor (an
	// approval bound it, whatever happened next); a key never pairs twice.
	ErrKeyRegistered = errors.New("the sensor key is already registered")
	// ErrKeyBusy: another open request holds the key (a concurrent start,
	// or one started with an enrollment token).
	ErrKeyBusy        = errors.New("the sensor key has another open pairing request")
	ErrStepUpRequired = authapp.ErrStepUpRequired
	ErrStepUpFailed   = authapp.ErrStepUpFailed
)

// StepUpVerifier re-authenticates the approving user (auth.AuthService).
type StepUpVerifier interface {
	VerifyStepUp(ctx context.Context, userID, sessionID string, proof authapp.StepUpProof) error
	StepUpMethodFor(ctx context.Context, userID string) (authapp.StepUpMethod, error)
}

// TenantDirectory reads an organization's name for the approval screen.
type TenantDirectory interface {
	GetByID(ctx context.Context, id shared.ID) (*tenantdom.Tenant, error)
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
	DefaultProfileFor(t sensordom.SensorType) string
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
	// jobRoot reads the job-signing root the views carry (nil: none).
	jobRoot func(ctx context.Context) string
	// contentKeys are the content-signing keys an approved identity
	// carries (nil: none).
	contentKeys ContentKeySource

	adminAudit AdminAuditWriter
	// tokens stores organization enrollment tokens (nil: none).
	tokens sensordom.EnrollmentTokenRepository
	// tenants names the organization an approval binds to (nil: id only).
	tenants TenantDirectory

	platformKey ed25519.PrivateKey
	codeKey     []byte
	// verifyURL is the console origin the sensor prints with its code
	// ("" prints no link).
	verifyURL string
	maxOpen   int
	now       func() time.Time

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
func (s *Service) SetTenants(t TenantDirectory)   { s.tenants = t }
func (s *Service) SetClock(now func() time.Time)  { s.now = now }

// SetVerificationURL sets the console origin (APP_URL) a sensor prints as
// the page to approve it on. An origin that is not absolute http(s) is
// ignored, so a sensor never prints a link a person cannot open.
func (s *Service) SetVerificationURL(origin string) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if !strings.HasPrefix(origin, "https://") && !strings.HasPrefix(origin, "http://") {
		return
	}
	s.verifyURL = origin
}
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
	// An instance enrollment token enrolls a new shared sensor: never with
	// an expectation code or a re-pair.
	if req.EnrollmentToken != "" && (req.Code != "" || req.SensorID != "") {
		return nil, ErrInvalid
	}
	if req.EnrollmentScope != "" && (req.EnrollmentScope != pairing.EnrollmentScopeOrganization || req.EnrollmentToken == "") {
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
	if req.EnrollmentToken == "" {
		if err := s.releaseKey(ctx, p, code, now); err != nil {
			return nil, err
		}
	}
	userCode := ""
	switch {
	case req.EnrollmentToken != "":
		// The sensor says which kind of token it holds; a token is never
		// used as the other kind (an operator who configured a shared
		// sensor never gets an organization sensor, and the reverse).
		if req.EnrollmentScope == pairing.EnrollmentScopeOrganization {
			if err := s.startEnrollment(ctx, req.EnrollmentToken, p); err != nil {
				return nil, err
			}
		} else if err := s.startInstance(ctx, req.EnrollmentToken, p); err != nil {
			return nil, err
		}
	case code != "":
		if userCode, err = s.startWithCode(ctx, p, code, now); err != nil {
			return nil, err
		}
	default:
		if userCode, err = s.createWithCode(ctx, p); err != nil {
			return nil, keyConflict(err)
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
		if s.verifyURL != "" {
			resp.VerificationURI = s.verifyURL + "/activate"
			resp.VerificationURIComplete = resp.VerificationURI + "?code=" + resp.UserCode
		}
	}
	return resp, nil
}

// startWithCode opens a request under the code the sensor started with, so
// the console command, the sensor's output and the approval link show one
// code. It attaches to the organization's open expectation with that code;
// otherwise the code becomes the request's own (rows of that code past
// their expiry are closed first); a code another open request holds gives
// a new code. The answer has the same shape whether or not the platform
// expected the code, so it tells a guesser nothing.
func (s *Service) startWithCode(ctx context.Context, p *sensordom.Pairing, code string, now time.Time) (string, error) {
	hash := s.codeHash(code)
	ok, err := s.repo.AttachToExpectationUnscoped(ctx, hash, p, now)
	if err != nil {
		return "", err
	}
	if ok {
		return code, nil
	}
	// The console that made the code learns why no sensor arrived: another
	// key holds it, or this key holds another request.
	s.RecordRefusal(ctx, Refusal{Code: code, PublicKey: p.PublicKey, SourceIP: p.SourceIP, Reason: sensordom.RefusalCodeTaken})
	if err := s.repo.ExpireStaleCodeUnscoped(ctx, hash, now); err != nil {
		return "", err
	}
	p.CodeHash = hash
	err = s.repo.CreateForward(ctx, p)
	if err == nil {
		return code, nil
	}
	if !errors.Is(err, shared.ErrConflict) {
		return "", err
	}
	// Another open request holds the code (or, in a race, the key): a new
	// code; a key conflict fails here too and is key-busy.
	fresh, err := s.createWithCode(ctx, p)
	if err != nil {
		return "", keyConflict(err)
	}
	return fresh, nil
}

// releaseKey lets a key that was never approved start again: a sensor
// stopped before its request was approved, or restarted with a new code,
// keeps the key it generated. The key's open requests that nobody approved
// are closed (and audited for their organization); a key that was ever
// registered to a sensor is refused, so an approved key never moves to
// another code, sensor or organization. Only the holder of the private key
// reaches this (the handler verified the request signature with it), so
// nobody can close another sensor's request.
func (s *Service) releaseKey(ctx context.Context, p *sensordom.Pairing, code string, now time.Time) error {
	registered, err := s.repo.KeyRegisteredUnscoped(ctx, p.Thumbprint)
	if err != nil {
		return err
	}
	if registered {
		s.log.Info("sensor pairing refused: key already registered",
			"key_fingerprint", pairing.KeyFingerprint(p.Thumbprint), "source_ip", ipString(p))
		return ErrKeyRegistered
	}
	keep := ""
	if code != "" {
		keep = s.codeHash(code)
	}
	closed, err := s.repo.SupersedeForKeyUnscoped(ctx, p.Thumbprint, keep, now)
	if err != nil {
		return err
	}
	for _, old := range closed {
		s.log.Info("sensor pairing superseded by a new start of the same key", "pairing_id", old.ID.String(),
			"new_pairing_id", p.ID.String(), "key_fingerprint", pairing.KeyFingerprint(p.Thumbprint))
		if old.TenantID == nil {
			continue // a default-mode request nobody claimed: no organization to tell
		}
		s.logAudit(ctx, auditapp.AuditContext{TenantID: old.TenantID.String(), ActorEmail: actorSensor, ActorIP: ipString(p)},
			auditapp.NewSuccessEvent(auditdom.ActionSensorPairingSuperseded, auditdom.ResourceTypeSensor, old.ID.String()).
				WithMessage("A sensor started pairing again with the same key; its earlier request, never approved, was closed").
				WithSeverity(auditdom.SeverityLow).
				WithMetadata("key_fingerprint", pairing.KeyFingerprint(p.Thumbprint)).
				WithMetadata("source_ip", ipString(p)).
				WithMetadata("new_pairing_id", p.ID.String()))
	}
	return nil
}

// keyConflict maps the key's uniqueness conflict (another open request won
// a race for it) to ErrKeyBusy; a code collision never reaches here.
func keyConflict(err error) error {
	if errors.Is(err, shared.ErrConflict) {
		return ErrKeyBusy
	}
	return err
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
	if (p.IsInstance() || p.IsEnrollment()) && p.Status == sensordom.PairingApproved && hmac.Equal(p.SensorNonce, nonce) {
		return nil // a retried reveal of a request the token already approved
	}
	if p.Status != sensordom.PairingPending || !now.Before(p.ExpiresAt) {
		return ErrNotFound
	}
	if p.Revealed() {
		if !hmac.Equal(p.SensorNonce, nonce) {
			return ErrNotFound
		}
		// A retried reveal (approving a token-bound request again is a
		// no-op once it is approved).
	} else {
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
		p.SensorNonce, p.SAS = nonce, sas
	}
	if p.IsInstance() {
		// The token was the administrator's approval.
		return s.approveInstance(ctx, p)
	}
	if p.IsEnrollment() {
		return s.approveEnrollment(ctx, p)
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
	if (p.Status == sensordom.PairingApproved || p.Status == sensordom.PairingCompleted) && bound(p) {
		ident := &pairing.Identity{SensorID: p.SensorID.String(), TenantID: tenantString(p), Name: p.RequestedName,
			KeyID: p.Thumbprint, Repair: p.RepairSensorID != nil}
		if p.IsInstance() {
			ident.Scope = pairing.ScopeInstance
		}
		ident.ContentSigning = s.contentSigning(p)
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
	if err != nil || !bound(p) {
		return nil, ErrNotFound
	}
	sig, err := pairing.DecodeFixed(req.Signature, ed25519.SignatureSize)
	if err != nil || req.SensorID != p.SensorID.String() || req.KeyID != thumbprint {
		return nil, ErrInvalid
	}
	msg := pairing.ConfirmTranscript(id.String(), p.SensorID.String(), tenantString(p), thumbprint)
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

// bound reports whether an approved request names its sensor and owner: a
// tenant, or none for a shared sensor enrolled with an instance token.
func bound(p *sensordom.Pairing) bool {
	return p.SensorID != nil && (p.TenantID != nil) != p.IsInstance()
}

// tenantString is the tenant of the identity ("" for a shared sensor).
func tenantString(p *sensordom.Pairing) string {
	if p.TenantID == nil {
		return ""
	}
	return p.TenantID.String()
}

func (s *Service) onCompleted(ctx context.Context, p *sensordom.Pairing) {
	details := map[string]any{"key_fingerprint": pairing.KeyFingerprint(p.Thumbprint), "sas": p.SAS, "pairing_id": p.ID.String()}
	if p.SourceIP != nil {
		details["source_ip"] = p.SourceIP.String()
	}
	if p.IsInstance() {
		// A shared sensor has no tenant timeline or tenant audit log.
		s.writeAdminAudit(ctx, nil, actorSensor, admin.AuditActionSharedSensorConfirmed, admin.ResourceTypeSensor,
			p.SensorID, p.RequestedName, ipString(p), "", details)
		return
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
	// SourceNetwork classifies SourceIP: "private" (a private, loopback or
	// link-local address: an internal network, or a proxy that hid the
	// sensor's address) or "public".
	SourceNetwork string `json:"source_network,omitempty"`
	// SourceProvider is the edge or hosting provider SourceIP belongs to,
	// when the address classifier knows it.
	SourceProvider string `json:"source_provider,omitempty"`
	// ApproverIP is the address the viewer's own request came from, shown
	// next to SourceIP.
	ApproverIP string `json:"approver_ip,omitempty"`
	// OrganizationID and OrganizationName are the organization an approval
	// binds the sensor to: the session's. The approval must name the same
	// id, so a switch of organization after the review is refused.
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name,omitempty"`
	// LastRefusal is the last refused attempt of a sensor on this code
	// (an open expectation of the organization): why no sensor arrived.
	LastRefusal    *RefusalView `json:"last_refusal,omitempty"`
	RepairSensorID string       `json:"repair_sensor_id,omitempty"`
	RepairSensor   string       `json:"repair_sensor_name,omitempty"`
	SensorID       string       `json:"sensor_id,omitempty"`
	Code           string       `json:"code,omitempty"`
	CreatedAt      time.Time    `json:"created_at"`
	ExpiresAt      time.Time    `json:"expires_at"`
	// StepUp is what the viewer must present to approve ("totp",
	// "password" or "fresh_sign_in").
	StepUp string `json:"step_up,omitempty"`
	// JobSigningRoot is the id of the offline root that signs the job
	// signer's key set ("" without one). The pairing command passes it as
	// SENSOR_JOB_SIGNING_ROOT, so the sensor checks the key set the
	// platform serves against a root it got from the administrator.
	JobSigningRoot string `json:"job_signing_root,omitempty"`
	// FingerprintChoices are three fingerprints, one of them the SAS: the
	// approver picks the one the host shows, and the approval sends it.
	FingerprintChoices []string `json:"fingerprint_choices,omitempty"`
}

// RefusalView is a refused attempt as the console shows it.
type RefusalView struct {
	// Reason: clock_skew, rate_limited, code_taken, key_busy or key_registered.
	Reason             string    `json:"reason"`
	At                 time.Time `json:"at"`
	KeyFingerprint     string    `json:"key_fingerprint,omitempty"`
	SourceIP           string    `json:"source_ip,omitempty"`
	ClockOffsetSeconds *int64    `json:"clock_offset_seconds,omitempty"`
	RetryAfterSeconds  *int64    `json:"retry_after_seconds,omitempty"`
}

func refusalView(r *sensordom.PairingRefusal) *RefusalView {
	v := &RefusalView{Reason: r.Reason, At: r.At}
	v.KeyFingerprint, _ = r.Details["key_fingerprint"].(string)
	v.SourceIP, _ = r.Details["source_ip"].(string)
	if f, ok := r.Details["clock_offset_seconds"].(float64); ok {
		n := int64(f)
		v.ClockOffsetSeconds = &n
	}
	if f, ok := r.Details["retry_after_seconds"].(float64); ok {
		n := int64(f)
		v.RetryAfterSeconds = &n
	}
	return v
}

// ContentKeySource gives the content-signing public keys the platform signs
// packs with (contentpack.Signer).
type ContentKeySource interface {
	PlatformPublicKey() (ed25519.PublicKey, string, error)
	PublicKey(tenantID string) (ed25519.PublicKey, string, error)
}

// SetContentKeys makes an approved identity carry the content-signing keys
// the sensor pins: the platform key, and for an organization sensor its
// organization's key. A shared sensor never gets a tenant key.
func (s *Service) SetContentKeys(k ContentKeySource) { s.contentKeys = k }

// contentSigning is the keys an identity carries, nil without a source or on
// a key error (the sensor then pins none and fetches no content).
func (s *Service) contentSigning(p *sensordom.Pairing) *pairing.ContentSigning {
	if s.contentKeys == nil {
		return nil
	}
	conv := func(pub ed25519.PublicKey) pairing.ContentKey {
		k := jobsign.NewPublicKey(pub)
		return pairing.ContentKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}
	}
	pub, _, err := s.contentKeys.PlatformPublicKey()
	if err != nil {
		s.log.Warn("content signing key not available for a pairing identity", "error", err)
		return nil
	}
	out := &pairing.ContentSigning{Platform: []pairing.ContentKey{conv(pub)}}
	if p.TenantID != nil && !p.IsInstance() {
		tpub, _, err := s.contentKeys.PublicKey(p.TenantID.String())
		if err != nil {
			s.log.Warn("tenant content signing key not available for a pairing identity", "error", err)
			return nil
		}
		out.Tenant = []pairing.ContentKey{conv(tpub)}
	}
	return out
}

// SetJobSigningRoot sets where the views read the job-signing root from
// (signerclient.Client.RootKeyID). Optional.
func (s *Service) SetJobSigningRoot(f func(ctx context.Context) string) { s.jobRoot = f }

func (s *Service) view(ctx context.Context, actor Actor, p *sensordom.Pairing) *View {
	v := &View{ID: p.ID.String(), Mode: string(p.Mode), Status: string(p.Status), SAS: p.SAS,
		HostFacts: p.HostFacts, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt,
		ApproverIP: actor.IP, OrganizationID: actor.TenantID.String()}
	if p.Thumbprint != "" {
		v.KeyFingerprint = pairing.KeyFingerprint(p.Thumbprint)
	}
	if p.SAS != "" {
		v.FingerprintChoices = s.fingerprintChoices(p)
	}
	if p.SourceIP != nil {
		v.SourceIP = p.SourceIP.String()
		v.SourceNetwork, v.SourceProvider = classifySource(p.SourceIP)
	}
	if s.tenants != nil {
		if t, err := s.tenants.GetByID(ctx, actor.TenantID); err == nil && t != nil {
			v.OrganizationName = t.Name()
		}
	}
	if p.SensorID != nil {
		v.SensorID = p.SensorID.String()
	}
	if s.jobRoot != nil {
		v.JobSigningRoot = s.jobRoot(ctx)
	}
	if p.RepairSensorID != nil && s.sensors != nil {
		if sen, err := s.sensors.GetByTenantAndID(ctx, actor.TenantID, *p.RepairSensorID); err == nil && sen != nil {
			v.RepairSensorID, v.RepairSensor = sen.ID.String(), sen.Name
		}
	}
	if p.LastRefusal != nil && p.Mode == sensordom.PairingReverse &&
		(p.Status == sensordom.PairingExpecting || p.Status == sensordom.PairingPending) {
		v.LastRefusal = refusalView(p.LastRefusal)
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
		s.lookupMissed(ctx, actor)
		return nil, ErrNotFound
	}
	hash, now := s.codeHash(norm), s.now()
	p, err := s.repo.FindOpenByCodeHash(ctx, hash, now)
	if err != nil {
		// A request that attached to this organization's own code (the
		// console command carried it): only this organization finds it.
		if p, err = s.repo.FindOpenForTenantByCodeHash(ctx, actor.TenantID, hash, now); err != nil {
			s.lookupMissed(ctx, actor)
			return nil, ErrNotFound
		}
	}
	if p.RepairSensorID != nil && !s.sensorInTenant(ctx, actor.TenantID, *p.RepairSensorID) {
		s.lookupMissed(ctx, actor)
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
	s.sweep(ctx)
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
		WithMessage("Created a pairing code for a new sensor").WithSeverity(auditdom.SeverityLow))
	v := s.view(ctx, actor, p)
	v.Code = pairing.FormatCode(code)
	return v, nil
}

// GetExpectation returns a request of the actor's tenant.
func (s *Service) GetExpectation(ctx context.Context, actor Actor, id shared.ID) (*View, error) {
	s.sweep(ctx)
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
	Code string
	// Fingerprint is the fingerprint the approver picked from
	// View.FingerprintChoices: it must be the SAS.
	Fingerprint string
	// OrganizationID is the organization the approver saw on the review;
	// it must be the session's.
	OrganizationID string
	StepUp         authapp.StepUpProof
	Name           string
	Type           sensordom.SensorType
	ZoneIDs        []shared.ID
	Profile        string
}

// Approve binds the request's key to the actor's tenant (a new sensor, or
// the re-paired one). Order of checks: a picked fingerprint is present,
// the organization, step-up, then the request itself and the pick (so an
// attacker with a stolen session learns nothing about codes, and closes no
// request, without the second factor). The organization check comes before
// step-up, so a refused approval spends no second factor. A pick that is
// not the request's SAS closes the request.
func (s *Service) Approve(ctx context.Context, actor Actor, id shared.ID, in ApproveInput) (*View, error) {
	if strings.TrimSpace(in.Fingerprint) == "" {
		return nil, ErrFingerprintRequired
	}
	if in.OrganizationID != actor.TenantID.String() {
		s.logAudit(ctx, s.auditContext(actor), auditapp.NewFailureEvent(auditdom.ActionSensorPairingApproved, auditdom.ResourceTypeSensor, id.String(), ErrOrganizationMismatch).
			WithMessage("Sensor pairing approval refused: it named another organization than the session's").
			WithSeverity(auditdom.SeverityMedium).WithMetadata("named_organization_id", truncate(in.OrganizationID, 64)))
		return nil, ErrOrganizationMismatch
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
	if !sameFingerprint(in.Fingerprint, p.SAS) {
		s.fingerprintMismatch(ctx, actor, p, in.Code)
		return nil, ErrFingerprintMismatch
	}
	// The profile chosen now, else the one the expectation named, else the
	// default for the sensor's type (collector for a collector, else the
	// narrow scanner default).
	profile := firstNonEmpty(in.Profile, p.RequestedProfile)
	if s.hook != nil {
		if profile == "" {
			profile = s.hook.DefaultProfileFor(in.Type)
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
	if p.IsEnrollment() && s.tokens != nil {
		// A request a token started keeps the token's labels.
		if t, err := s.tokens.GetEnrollmentTokenUnscoped(ctx, *p.EnrollmentTokenID); err == nil && t.TenantID == actor.TenantID {
			approval.OnApproved = withLabels(approval.OnApproved, actor.TenantID, t.Labels)
		}
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

// Deny refuses an open request: one of the actor's organization, or a
// tenantless default-mode request whose code the actor entered (like an
// approval, the id alone is never enough).
func (s *Service) Deny(ctx context.Context, actor Actor, id shared.ID, code string) error {
	codeHash := ""
	if norm, err := pairing.NormalizeCode(code); err == nil {
		codeHash = s.codeHash(norm)
	}
	p, err := s.repo.Deny(ctx, actor.TenantID, id, actor.UserID, codeHash, s.now())
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
	return err == nil && sen != nil && !sen.IsShared() && sen.Status != sensordom.SensorStatusRevoked
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
		return
	}
	removed, err := s.repo.RemoveUnconfirmedSensors(ctx)
	if err != nil {
		s.log.Warn("sensor pairing sweep: remove unconfirmed sensors", "error", err)
		return
	}
	for _, r := range removed {
		s.log.Info("removed a sensor whose pairing was approved but never confirmed",
			"sensor_id", r.ID.String(), "tenant_id", r.TenantID.String())
		s.logAudit(ctx, auditapp.AuditContext{TenantID: r.TenantID.String(), ActorEmail: actorSensor},
			auditapp.NewSuccessEvent(auditdom.ActionSensorDeleted, auditdom.ResourceTypeSensor, r.ID.String()).
				WithResourceName(r.Name).
				WithMessage("Removed sensor "+r.Name+": its pairing was approved but the sensor never confirmed it within 10 minutes, so it never had a working key").
				WithSeverity(auditdom.SeverityLow).WithMetadata("reason", "pairing_not_confirmed"))
	}
}

// Refusal is a refused start that carried a code.
type Refusal struct {
	Code       string
	PublicKey  []byte
	SourceIP   net.IP
	Reason     string
	ClockSkew  time.Duration
	RetryAfter time.Duration
}

// RecordRefusal notes a refused start on its code's open expectation, so
// the console's waiting step can say why no sensor arrived. Only the
// expectation's organization reads it; the sensor's answer is unchanged.
// Call it only for a start whose signature verified with the key in its
// body. Best effort: a failure is logged, never returned.
func (s *Service) RecordRefusal(ctx context.Context, r Refusal) {
	if s == nil {
		return
	}
	norm, err := pairing.NormalizeCode(r.Code)
	if err != nil {
		return
	}
	thumb := sensorsig.Thumbprint(r.PublicKey)
	details := map[string]any{"key_fingerprint": pairing.KeyFingerprint(thumb)}
	if r.SourceIP != nil {
		details["source_ip"] = r.SourceIP.String()
	}
	if r.Reason == sensordom.RefusalClockSkew {
		details["clock_offset_seconds"] = int64(r.ClockSkew / time.Second)
	}
	if r.RetryAfter > 0 {
		details["retry_after_seconds"] = int64(r.RetryAfter / time.Second)
	}
	if err := s.repo.RecordRefusalUnscoped(ctx, s.codeHash(norm), thumb, r.Reason, details, s.now()); err != nil {
		s.log.Warn("record sensor pairing refusal", "error", logger.SanitizeError(err))
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

// lookupFailed counts a failed lookup and reports whether this one locked
// the user's lookups.
func (s *Service) lookupFailed(user shared.ID) bool {
	s.lookupMu.Lock()
	defer s.lookupMu.Unlock()
	s.lookupFailures[user] = append(s.lookupFailures[user], s.now())
	return len(s.lookupFailures[user]) == LookupFailureLimit
}

// lookupMissed counts a failed lookup; the one that locks the user's
// lookups is audited (code guessing, or codes sent by someone else).
func (s *Service) lookupMissed(ctx context.Context, actor Actor) {
	if !s.lookupFailed(actor.UserID) {
		return
	}
	s.logAudit(ctx, s.auditContext(actor), auditapp.NewFailureEvent(auditdom.ActionSensorPairingLookupLocked, auditdom.ResourceTypeSensor, actor.UserID.String(), ErrLookupLocked).
		WithMessage(fmt.Sprintf("Pairing code lookups locked for this user after %d failed lookups within %s", LookupFailureLimit, LookupFailureWindow)).
		WithSeverity(auditdom.SeverityHigh))
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

// classifySource says whether a request came from a private or a public
// address, and from which known edge or hosting provider.
func classifySource(ip net.IP) (network, provider string) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", ""
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return "private", ""
	}
	return "public", edgeaddr.Default().Address(a.String(), "", "").Provider
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
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
