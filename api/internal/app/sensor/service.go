// Package sensor implements the application service for the sensor bounded context — orchestrates pkg/domain/sensor entities and cross-cutting concerns (audit, notifications, RBAC).
package sensor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
)

// sensorAuditSystemActor is the actor recorded on sensor lifecycle audit events
// (connect/disconnect) that originate from background reconciliation rather than
// a user request. LogEvent treats an empty ActorID with a non-empty email as a
// system action.
const sensorAuditSystemActor = "system"

// SensorService handles sensor-related business operations.
type SensorService struct {
	// keyUse debounces the key-use writes of recordKeyUseAsync.
	keyUse       keyUseDebouncer
	repo         sensordom.Repository
	auditService *auditapp.AuditService
	logger       *logger.Logger
	// statusChanged is told when a sensor's status or keys change
	// (SetStatusNotifier); nil: nobody.
	statusChanged func(tenantID, sensorID string)
	// pepper is the server-side secret mixed into the API-key hash via
	// HMAC-SHA256. Optional — when empty the hash falls back to plain
	// SHA-256 for backward compatibility with rows written before the
	// pepper was deployed. Set via SetPepper at boot from the platform
	// encryption key (or a dedicated derived secret). The pepper turns
	// a database-only leak into useless ciphertext: an attacker without
	// access to application config cannot brute-force the raw API key
	// from a leaked key_hash column.
	pepper string
	// legacyPeppers are earlier peppers whose hashes still verify (RFC-032
	// Phase 0: the pepper used to be APP_ENCRYPTION_KEY itself). New and
	// renewed keys are always hashed with pepper.
	legacyPeppers []string
	// keyTTL is how long a self-renewed API key stays valid before it must be
	// renewed again (RFC-014 Phase 1b). Zero (the default) disables expiry:
	// renewed keys never expire, preserving today's behavior. Set via
	// SetKeyTTL at boot. Only self-renewal honors it; created and
	// admin-regenerated keys never expire regardless.
	keyTTL time.Duration
	// renewGrace is how long the key a sensor presented to renew keeps
	// authenticating after the renewal (in-flight requests), before it
	// expires: SENSOR_KEY_RENEW_GRACE, default DefaultRenewGrace. Every other
	// credential the sensor still held is capped to the same moment, so a
	// renewal leaves exactly one long-lived key.
	renewGrace time.Duration
	// slimHeartbeatOff is the kill switch of slim heartbeats (RFC-033
	// §6.12, SENSOR_SLIM_HEARTBEAT=false): sensors whose manifest is
	// acknowledged may leave their tool inventory out of heartbeats unless
	// it is set.
	slimHeartbeatOff bool
	// apiKeyRepo is the optional multi-key store (RFC-014 Phase 3). When wired,
	// AuthenticateByAPIKey also accepts keys from sensor_api_keys, and self-renewal
	// under a key TTL issues a NEW key row (rotation overlap) instead of replacing
	// the inline hash — so a renewed key coexists with the one it supersedes. Nil
	// (the default) keeps the single-inline-key behavior.
	apiKeyRepo sensordom.APIKeyRepository
	// signingKeys holds key-bound sensors' public keys (RFC-052); nonces
	// is the shared store of spent request nonces, memNonces the
	// per-replica fallback (keybound.go).
	signingKeys sensordom.SigningKeyRepository
	// identityPolicy is the organization's sensor identity policy
	// (RFC-052 D-4); nil allows bearer-key sensors.
	identityPolicy sensordom.IdentityPolicyRepository

	// stepUp asks for the acting user's recent re-authentication before the
	// identity policy is widened (allowing bearer keys). nil skips the check
	// (a service built outside the HTTP server).
	stepUp shared.RecentAuthGate

	nonces    sensordom.NonceStore
	nonceOnce sync.Once
	memNonces *memoryNonceStore
	// lbWeights are the load-balancing weights used to recompute a sensor's
	// load_score on every heartbeat. Defaults to the compiled-in set;
	// SetLoadBalancingWeights installs the operator's SENSOR_LB_* values.
	lbWeights sensordom.LoadBalancingWeights
	// events stores the sensor's activity timeline (sensor_events); nil
	// records nothing. activity reads the merged timeline.
	events      sensordom.EventRepository
	eventLimits sensordom.EventLimits
	activity    sensordom.ActivityReader
	now         func() time.Time
	// leases renews the leases of the commands a heartbeating sensor holds
	// (RFC-035 D6); nil renews nothing.
	leases commanddom.LeaseRenewer
	// holders takes back the commands a sensor holds when it is revoked or
	// disabled (RFC-040 §5.2); nil leaves them to lease expiry.
	holders commanddom.HolderReleaser
	// cancels finds the commands a heartbeating sensor must stop
	// (cancel_command_ids). Optional; nil sends none.
	cancels commanddom.CancelFinder
	// history keeps the per-sensor heartbeat history (the Control channel
	// sparkline) and gaps observes each heartbeat's gap (metrics); nil
	// records nothing.
	history sensordom.HeartbeatHistoryRepository
	gaps    HeartbeatGapObserver
}

// HeartbeatGapObserver receives the gap of every heartbeat that had a
// previous one, with the interval the sensor followed: a metrics sink.
type HeartbeatGapObserver interface {
	ObserveHeartbeatGap(gap, interval time.Duration)
}

// SetHeartbeatHistory wires the heartbeat history (one bucketed write per
// heartbeat of a tenant sensor). Optional.
func (s *SensorService) SetHeartbeatHistory(r sensordom.HeartbeatHistoryRepository) {
	s.history = r
}

// SetHeartbeatGapObserver wires the heartbeat gap metric. Optional.
func (s *SensorService) SetHeartbeatGapObserver(o HeartbeatGapObserver) {
	s.gaps = o
}

// HeartbeatHistory returns the last window (at most a day) of a tenant
// sensor's heartbeat history, oldest first; empty when none is kept. The
// sensor is looked up in the tenant first: another tenant's sensor is not
// found.
func (s *SensorService) HeartbeatHistory(ctx context.Context, tenantID, sensorID string, window time.Duration) ([]sensordom.HeartbeatBucket, error) {
	a, err := s.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}
	if s.history == nil || a.TenantID == nil {
		return []sensordom.HeartbeatBucket{}, nil
	}
	if window <= 0 || window > sensordom.MaxHeartbeatHistoryWindow {
		window = sensordom.MaxHeartbeatHistoryWindow
	}
	return s.history.HeartbeatHistory(ctx, *a.TenantID, a.ID, s.now().Add(-window))
}

// SetLeaseRenewer wires command lease renewal into the heartbeat: every
// accepted heartbeat renews the leases of the commands the sensor says it
// holds (its running list), or of every command it holds when it does not
// report one (an SDK without the load report). Optional.
func (s *SensorService) SetLeaseRenewer(r commanddom.LeaseRenewer) {
	s.leases = r
}

// SetHolderReleaser wires the release of a sensor's leased commands when it
// is revoked or disabled (RFC-040 §5.2). Without it they wait for their
// lease to run out.
func (s *SensorService) SetHolderReleaser(r commanddom.HolderReleaser) {
	s.holders = r
}

// SetCancelFinder wires the cancel signal into the heartbeat: the answer
// lists the commands the sensor reports holding but must stop (canceled,
// timed out, re-queued, held elsewhere), as cancel_command_ids. Optional.
func (s *SensorService) SetCancelFinder(f commanddom.CancelFinder) {
	s.cancels = f
}

// MaxCancelCommandIDs bounds cancel_command_ids in a heartbeat answer
// (sdk-go reads at most 256).
const MaxCancelCommandIDs = 256

// CommandsToCancel returns the commands among running (the heartbeat's
// running list, untrusted) that sensor a must stop. Best effort: nil when
// nothing is wired, nothing is reported, or the lookup fails (logged), so
// the heartbeat never fails because of it.
func (s *SensorService) CommandsToCancel(ctx context.Context, a *sensordom.Sensor, running []string) []string {
	if s.cancels == nil || a == nil || a.TenantID == nil || len(running) == 0 {
		return nil
	}
	if len(running) > maxRenewedCommands {
		running = running[:maxRenewedCommands]
	}
	ids, err := s.cancels.CommandsToCancel(ctx, *a.TenantID, a.ID, running)
	if err != nil {
		s.logger.Warn("commands to cancel not looked up", "sensor_id", a.ID.String(), "error", err)
		return nil
	}
	if len(ids) > MaxCancelCommandIDs {
		ids = ids[:MaxCancelCommandIDs]
	}
	return ids
}

// SetEventRepository wires the sensor activity store: heartbeat diffs and
// online transitions are recorded there under the limits.
func (s *SensorService) SetEventRepository(repo sensordom.EventRepository, limits sensordom.EventLimits) {
	s.events = repo
	s.eventLimits = limits
}

// SetActivityReader wires the timeline reader (GET /sensors/{id}/activity).
func (s *SensorService) SetActivityReader(r sensordom.ActivityReader) {
	s.activity = r
}

// recordEvents writes events best-effort: a failure is logged, never
// returned, so a heartbeat is not refused because its timeline entry
// could not be written.
func (s *SensorService) recordEvents(ctx context.Context, events []sensordom.Event) {
	if s.events == nil {
		return
	}
	for _, e := range events {
		res, err := s.events.Record(ctx, e, s.eventLimits)
		if err != nil {
			s.logger.Warn("failed to record sensor event",
				"sensor_id", e.SensorID.String(), "type", string(e.Type), "error", err)
			continue
		}
		if res == sensordom.EventDropped {
			s.logger.Debug("sensor event dropped by the hourly limit",
				"sensor_id", e.SensorID.String(), "type", string(e.Type))
		}
	}
}

// warnAudit logs an audit write that failed. Audit writes never fail the
// operation they record, but a lost audit row must not be silent.
func (s *SensorService) warnAudit(err error, action, sensorID string) {
	if err != nil {
		s.logger.Warn("failed to write sensor audit event", "action", logger.SanitizeValue(action),
			"sensor_id", logger.SanitizeValue(sensorID), "error", logger.SanitizeError(err))
	}
}

// NewSensorService creates a new SensorService.
func NewSensorService(repo sensordom.Repository, auditService *auditapp.AuditService, log *logger.Logger) *SensorService {
	return &SensorService{
		repo:         repo,
		auditService: auditService,
		logger:       log.With("service", "sensor"),
		lbWeights:    sensordom.DefaultLoadBalancingWeights(),
		eventLimits:  sensordom.DefaultEventLimits(),
		renewGrace:   DefaultRenewGrace,
		now:          time.Now,
	}
}

// SetLoadBalancingWeights configures the weights used to compute the persisted
// load_score on each heartbeat. Call once at boot. An all-zero weight set is
// ignored so a misconfiguration cannot flatten every sensor's score to 0.
func (s *SensorService) SetLoadBalancingWeights(w sensordom.LoadBalancingWeights) {
	if w.IsZero() {
		s.logger.Warn("ignoring all-zero sensor load-balancing weights; keeping defaults")
		return
	}
	s.lbWeights = w
}

// SetPepper configures the HMAC pepper used by the API-key hash.
// Empty string disables peppering (backward-compat with pre-existing
// SHA-256 hashes). Should be called once at boot before the service
// handles any traffic.
func (s *SensorService) SetPepper(pepper string) {
	s.pepper = pepper
}

// SetLegacyPeppers configures earlier peppers whose hashes keep verifying:
// a key stored under one of them still authenticates, while every new or
// renewed key is stored under the current pepper. Empty values and the
// current pepper are ignored. Call once at boot after SetPepper.
func (s *SensorService) SetLegacyPeppers(peppers ...string) {
	s.legacyPeppers = s.legacyPeppers[:0]
	for _, p := range peppers {
		if p != "" && p != s.pepper && !slices.Contains(s.legacyPeppers, p) {
			s.legacyPeppers = append(s.legacyPeppers, p)
		}
	}
}

// candidateHashes are the stored hashes a presented key may match, current
// pepper first: the current pepper, each legacy pepper, then the plain
// SHA-256 of rows written before any pepper (only when a pepper is set;
// without one the first entry already is the plain hash).
func (s *SensorService) candidateHashes(apiKey string) []string {
	out := make([]string, 0, 2+len(s.legacyPeppers))
	out = append(out, s.hashSensorAPIKey(apiKey))
	for _, p := range s.legacyPeppers {
		out = append(out, crypto.HashTokenPeppered(apiKey, p))
	}
	if s.pepper != "" || len(s.legacyPeppers) > 0 {
		out = append(out, crypto.HashToken(apiKey))
	}
	return slices.Compact(out)
}

// KeyRehasher is implemented by a key store that can replace a key hash made
// with an earlier pepper (compare-and-swap on the old hash) and count the
// active keys still hashed with one.
type KeyRehasher interface {
	RehashKey(ctx context.Context, id shared.ID, oldHash, newHash string) (bool, error)
	CountKeysNotUnderPepper(ctx context.Context) (int, error)
}

// rehashKey stores a key's hash under the current pepper in place of the
// earlier hash it matched, so the key stops depending on an old pepper
// (APP_ENCRYPTION_KEY_PREVIOUS, SENSOR_KEY_PEPPER_PREVIOUS) or on the plain
// SHA-256 of keys from before any pepper. Best effort and never fatal: the
// key keeps verifying under the old hash if the write fails.
func (s *SensorService) rehashKey(ctx context.Context, store any, kind string, id shared.ID, oldHash, newHash string) {
	r, ok := store.(KeyRehasher)
	if !ok {
		return
	}
	if changed, err := r.RehashKey(ctx, id, oldHash, newHash); err != nil {
		s.logger.Warn("sensor key re-hash under the current pepper failed", "kind", kind, "id", id.String(), "error", err)
	} else if changed {
		s.logger.Info("sensor key re-hashed under the current pepper", "kind", kind, "id", id.String())
	}
}

// SetKeyTTL configures how long a self-renewed API key stays valid. Zero (the
// default) disables expiry — renewed keys never expire. Should be called once
// at boot before the service handles traffic.
func (s *SensorService) SetKeyTTL(ttl time.Duration) {
	s.keyTTL = ttl
}

// DefaultRenewGrace is how long a renewed-away key keeps working when
// SENSOR_KEY_RENEW_GRACE is not set.
const DefaultRenewGrace = 15 * time.Minute

// SetRenewGrace configures how long the key a sensor renewed with keeps
// authenticating after the renewal. Zero retires it at once; a negative value
// is ignored (the default stays). Call once at boot.
func (s *SensorService) SetRenewGrace(d time.Duration) {
	if d < 0 {
		s.logger.Warn("ignoring negative sensor key renewal grace; keeping the default", "grace", d.String())
		return
	}
	s.renewGrace = d
}

// SetAPIKeyRepository wires the multi-key store (RFC-014 Phase 3). Optional;
// when nil the service uses only the single inline key per sensor.
func (s *SensorService) SetAPIKeyRepository(repo sensordom.APIKeyRepository) {
	s.apiKeyRepo = repo
}

// CreateSensorInput represents the input for creating a sensor.
type CreateSensorInput struct {
	TenantID          string   `json:"tenant_id" validate:"required,uuid"`
	Name              string   `json:"name" validate:"required,min=1,max=255"`
	Type              string   `json:"type" validate:"required,oneof=worker collector sensor"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	ExecutionMode     string   `json:"execution_mode" validate:"omitempty,oneof=standalone daemon"`
	MaxConcurrentJobs int      `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
	// Audit context (optional, for audit logging)
	AuditContext *auditapp.AuditContext `json:"-"`
}

// CreateSensorOutput represents the output after creating a sensor.
type CreateSensorOutput struct {
	Sensor *sensordom.Sensor `json:"sensor"`
	APIKey string            `json:"api_key"` // Only returned on creation
}

// CreateSensor creates a new sensor and generates an API key.
func (s *SensorService) CreateSensor(ctx context.Context, input CreateSensorInput) (*CreateSensorOutput, error) {
	s.logger.Info("creating sensor", "name", logger.SanitizeValue(input.Name), "type", logger.SanitizeValue(input.Type))

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// An organization that requires key-bound identity creates no bearer
	// keys: its sensors pair (RFC-052 D-4). Existing bearer-key sensors are
	// untouched.
	allowed, err := s.BearerKeysAllowed(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, sensordom.ErrBearerKeysDisabled
	}

	sensorType := sensordom.SensorType(input.Type)
	executionMode := sensordom.ExecutionMode(input.ExecutionMode)
	if executionMode == "" {
		executionMode = sensorType.DefaultExecutionMode()
	}

	a, err := sensordom.NewSensor(tenantID, input.Name, sensorType, input.Description, input.Capabilities, executionMode)
	if err != nil {
		return nil, err
	}

	// Set max concurrent jobs if provided
	if input.MaxConcurrentJobs > 0 {
		a.SetMaxConcurrentJobs(input.MaxConcurrentJobs)
	}

	// Generate API key
	apiKey, hash, prefix, err := s.generateSensorAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}
	a.SetAPIKey(hash, prefix)

	if err := s.repo.Create(ctx, a); err != nil {
		return nil, err
	}

	// Audit logging
	if s.auditService != nil && input.AuditContext != nil {
		s.warnAudit(s.auditService.LogSensorCreated(ctx, *input.AuditContext, a.ID.String(), a.Name, string(a.Type)), "LogSensorCreated", a.ID.String())
	}

	return &CreateSensorOutput{
		Sensor: a,
		APIKey: apiKey,
	}, nil
}

// GetSensor retrieves a sensor by ID.
func (s *SensorService) GetSensor(ctx context.Context, tenantID, sensorID string) (*sensordom.Sensor, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	aid, err := shared.IDFromString(sensorID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid sensor id", shared.ErrValidation)
	}

	return s.repo.GetByTenantAndID(ctx, tid, aid)
}

// ListSensorsInput represents the input for listing sensors.
type ListSensorsInput struct {
	TenantID      string   `json:"tenant_id" validate:"required,uuid"`
	Type          string   `json:"type" validate:"omitempty,oneof=worker collector sensor"`
	Status        string   `json:"status" validate:"omitempty,oneof=active disabled revoked"`      // Admin-controlled
	Health        string   `json:"health" validate:"omitempty,oneof=unknown online offline error"` // Automatic
	ExecutionMode string   `json:"execution_mode" validate:"omitempty,oneof=standalone daemon"`
	Capabilities  []string `json:"capabilities"`
	Tools         []string `json:"tools"`
	Search        string   `json:"search" validate:"max=255"`
	HasCapacity   *bool    `json:"has_capacity"` // Filter by sensors with available capacity
	// SDKVersion filters on the reported SDK version; "" = unknown, nil = all.
	SDKVersion *string `json:"sdk_version"`
	Page       int     `json:"page"`
	PerPage    int     `json:"per_page"`
}

// ListSensors lists sensors with filters.
func (s *SensorService) ListSensors(ctx context.Context, input ListSensorsInput) (pagination.Result[*sensordom.Sensor], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*sensordom.Sensor]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := sensordom.Filter{
		// The tenant's own sensors (never shared platform sensors); the
		// sensor stats count the same rows.
		TenantID:     &tenantID,
		Capabilities: input.Capabilities,
		Tools:        input.Tools,
		Search:       input.Search,
		HasCapacity:  input.HasCapacity,
		SDKVersion:   input.SDKVersion,
	}

	if input.Type != "" {
		t := sensordom.SensorType(input.Type)
		filter.Type = &t
	}

	if input.Status != "" {
		st := sensordom.SensorStatus(input.Status)
		filter.Status = &st
	}

	if input.ExecutionMode != "" {
		em := sensordom.ExecutionMode(input.ExecutionMode)
		filter.ExecutionMode = &em
	}

	if input.Health != "" {
		h := sensordom.SensorHealth(input.Health)
		filter.Health = &h
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, page)
}

// UpdateSensorInput represents the input for updating a sensor.
type UpdateSensorInput struct {
	TenantID          string   `json:"tenant_id" validate:"required,uuid"`
	SensorID          string   `json:"sensor_id" validate:"required,uuid"`
	Name              string   `json:"name" validate:"omitempty,min=1,max=255"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Status            string   `json:"status" validate:"omitempty,oneof=active disabled revoked"` // Admin-controlled
	MaxConcurrentJobs *int     `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
	// Audit context (optional, for audit logging)
	AuditContext *auditapp.AuditContext `json:"-"`
}

// UpdateSensor updates a sensor.
func (s *SensorService) UpdateSensor(ctx context.Context, input UpdateSensorInput) (*sensordom.Sensor, error) {
	a, err := s.GetSensor(ctx, input.TenantID, input.SensorID)
	if err != nil {
		return nil, err
	}

	// Track changes for audit
	changes := audit.NewChanges()
	oldName := a.Name

	if input.Name != "" && input.Name != a.Name {
		changes.Set("name", a.Name, input.Name)
		a.Name = input.Name
	}

	if input.Description != "" && input.Description != a.Description {
		changes.Set("description", a.Description, input.Description)
		a.Description = input.Description
	}

	// Capabilities are a limit on what the sensor reports (RFC-029 §4.3.1).
	// A list that is present replaces the limit; [] removes it (every
	// capability the sensor reports may be used). Absent (nil) leaves it as
	// it is. Tools have no such limit here: the sensor grant narrows them.
	if input.Capabilities != nil && !slices.Equal(input.Capabilities, a.Capabilities) {
		changes.Set("capabilities", a.Capabilities, input.Capabilities)
		a.Capabilities = append([]string{}, input.Capabilities...)
	}

	// Revocation is permanent (ActivateSensor refuses it too). Without this a
	// PUT with {"status":"active"} brought a revoked sensor and its old key
	// back.
	if input.Status != "" && a.Status == sensordom.SensorStatusRevoked &&
		sensordom.SensorStatus(input.Status) != sensordom.SensorStatusRevoked {
		return nil, shared.NewDomainError("FORBIDDEN", "cannot change the status of a revoked sensor", shared.ErrForbidden)
	}

	// Revocation has its own route (POST /sensors/{id}/revoke), which records
	// a reason and a Critical sensor.revoked audit event. The generic update
	// would log it as a Low sensor.updated, so it may not revoke.
	if sensordom.SensorStatus(input.Status) == sensordom.SensorStatusRevoked && a.Status != sensordom.SensorStatusRevoked {
		return nil, shared.NewDomainError("VALIDATION", "revoke a sensor with POST /api/v1/sensors/{id}/revoke", shared.ErrValidation)
	}

	withdrawn := false
	if input.Status != "" {
		oldStatus := a.Status
		a.SetStatus(sensordom.SensorStatus(input.Status), "")
		changes.Set("status", string(oldStatus), input.Status)
		withdrawn = a.Status != oldStatus &&
			(a.Status == sensordom.SensorStatusRevoked || a.Status == sensordom.SensorStatusDisabled)
	}

	if input.MaxConcurrentJobs != nil {
		changes.Set("max_concurrent_jobs", a.MaxConcurrentJobs, *input.MaxConcurrentJobs)
		a.SetMaxConcurrentJobs(*input.MaxConcurrentJobs)
	}

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, err
	}

	// Audit logging
	if s.auditService != nil && input.AuditContext != nil && !changes.IsEmpty() {
		sensorName := a.Name
		if sensorName == "" {
			sensorName = oldName
		}
		s.warnAudit(s.auditService.LogSensorUpdated(ctx, *input.AuditContext, a.ID.String(), sensorName, changes), "LogSensorUpdated", a.ID.String())
	}
	if withdrawn {
		s.releaseHeldCommands(ctx, a, input.AuditContext)
	}

	return a, nil
}

// SensorHeartbeatData represents the data received from sensor heartbeat.
type SensorHeartbeatData struct {
	Version  string
	Hostname string
	// InstanceID is the random id the sensor process picked at start (sdk-go
	// v0.12+; "" from older SDKs, which are observed by hostname instead).
	// Untrusted; sanitized before use. Drives clone detection (identity.go).
	InstanceID string
	// IPAddress is the address the heartbeat came from, resolved by the HTTP
	// layer with the trusted-proxy rule. Never taken from the request body:
	// the sensor is untrusted. An empty or unparseable value keeps the
	// previously stored address.
	IPAddress string

	CPUPercent    float64
	MemoryPercent float64
	CurrentJobs   int
	Region        string

	// Disk/network throughput in MB/s. Optional — sensors that do not report
	// them leave the corresponding load-score terms at zero.
	DiskReadMBPS  float64
	DiskWriteMBPS float64
	NetworkRxMBPS float64
	NetworkTxMBPS float64

	// Outbox is the sensor's outbox state, nil when the heartbeat did not
	// carry one. It is clamped here, at the ingest boundary. nil leaves the
	// stored snapshot untouched (see sensordom.HeartbeatUpdate.Outbox).
	Outbox *sensordom.OutboxStats

	// Protocol is the sensor protocol the heartbeat arrived on (1 or 2) and
	// UserAgent the client's User-Agent, for the fleet's protocol telemetry
	// (RFC-029 §5.3). Protocol 0 leaves the stored values untouched.
	Protocol  int
	UserAgent string
	// Binding is the binding the heartbeat arrived on (decided by the
	// platform, RFC-059); FallbackReason is the sensor's account of why it
	// is not on gRPC (untrusted, sanitized before it is stored).
	Binding        string
	FallbackReason string

	// UptimeSeconds is the process uptime the heartbeat reported; 0 when it
	// did not report one. Clamped before it is stored.
	UptimeSeconds int64

	// Running is the ids of the commands the sensor says it holds (the
	// heartbeat's "running"), untrusted. RunningReported is false for a
	// sensor that does not report it (an SDK without the load report): its
	// heartbeat then renews every command it holds.
	Running         []string
	RunningReported bool

	// Load is the load report the heartbeat carried (resources, capacity,
	// local queue), untrusted; nil when it carried none. Clamped here before
	// it is stored (sensordom.LoadReport.Clamp).
	Load *sensordom.LoadReport

	// Report is the capability report the heartbeat carried, untrusted; nil
	// when it carried none. It is sanitized here against the tool catalog
	// before it is stored (sensordom.CapabilityReportInput.Sanitize).
	Report *sensordom.CapabilityReportInput

	// Build is the build information the heartbeat carried (sdk, sensor
	// members), untrusted. Parts it leaves empty are read from UserAgent.
	Build sensordom.BuildReport

	// Content is the content freshness of a slim heartbeat (RFC-033 §6.12):
	// a sensor whose manifest is acknowledged leaves its tools out and sends
	// each tool's content (with Tool set) here, untrusted. It is merged into
	// the stored tools' content. nil: none.
	Content []sensordom.ReportedContent

	// Control is the control-channel report the heartbeat carried
	// (sensordom.ParseControlReport, already clamped); nil when it carried
	// none. Stored as the latest report; its interval_s feeds the deadline.
	Control *sensordom.ControlReport

	// AdvisedSeconds is the next_heartbeat_seconds the doorbell computed for
	// this heartbeat (0: none), and DoorbellAware whether the sensor follows
	// that advice (protocol v2, or v1 with the doorbell feature). Together
	// with Control they give the interval the next deadline is computed
	// from (sensordom.FollowedHeartbeatInterval).
	AdvisedSeconds int
	DoorbellAware  bool

	// LocalPolicy is the local policy report the heartbeat carried
	// (RFC-040 §5.7), untrusted; nil when it carried none.
	LocalPolicy *sensordom.LocalPolicyReport

	// ManifestDigest is the manifest digest the sensor echoes (RFC-033); ""
	// from a sensor that registers no manifest, whose manifest is then
	// derived from this heartbeat's report.
	ManifestDigest string

	// ConfigReport is the config report summary the heartbeat carried
	// (research/26), untrusted; nil when it carried none. Only its digest
	// is stored, validated (sensordom.HeartbeatConfigDigest).
	ConfigReport *sensordom.ConfigReportSummary
}

// sanitizeReport turns a heartbeat's capability report into what may be
// stored: known tools and capabilities only, bounded sizes, clamped
// concurrency. nil when there is nothing to store, or when the catalog
// cannot be read (the stored report is then kept; the heartbeat itself
// still succeeds).
func (s *SensorService) sanitizeReport(ctx context.Context, a *sensordom.Sensor, in *sensordom.CapabilityReportInput) *sensordom.CapabilityReport {
	if in == nil || in.IsEmpty() {
		return nil
	}
	knownTools, knownCaps := map[string]bool{}, map[string]bool{}
	if tools, caps := in.CatalogCandidates(); len(tools) > 0 || len(caps) > 0 {
		var err error
		knownTools, knownCaps, err = s.repo.KnownCapabilityNames(ctx, a.TenantID, tools, caps)
		if err != nil {
			s.logger.Warn("sensor capability report not stored: tool catalog unavailable",
				"sensor_id", a.ID.String(), "error", err)
			return nil
		}
	}
	report := in.Sanitize(knownTools, knownCaps)
	return &report
}

// UpdateHeartbeat updates sensor metrics from heartbeat.
//
// The sensor row is read only to (a) detect an offline -> online transition for
// the connect audit event and (b) compute the load score from the stored
// capacity. The write itself is a targeted UPDATE of the heartbeat-owned
// columns guarded by status = 'active' (repo.UpdateHeartbeat) — never a
// full-row rewrite. A full-row Update here used to write back the status and
// API-key hash read at the start of the request, so a heartbeat landing just
// after an admin revoke or key regeneration silently undid it.
func (s *SensorService) UpdateHeartbeat(ctx context.Context, sensorID shared.ID, data SensorHeartbeatData) error {
	a, err := s.repo.GetByID(ctx, sensorID)
	if err != nil {
		return err
	}

	// SECURITY: the region is reported by the untrusted sensor process and is
	// later rendered verbatim into the operator's setup snippets (env/docker/
	// yaml) via text/template. Sanitize it at this ingest boundary so a
	// malicious sensor cannot inject shell metacharacters that would execute
	// when an operator copy-pastes the generated config. This covers both the
	// persisted value (repo.UpdateHeartbeat below) and the load-score snapshot.
	data.Region = sensordom.SanitizeRegion(data.Region)

	// The load report is untrusted: clamp it. A sensor on an SDK that
	// reports resources but not the legacy cpu/memory percentages still
	// feeds the load score.
	var load *sensordom.LoadReport
	if !data.Load.IsEmpty() {
		clamped := data.Load.Clamp()
		load = &clamped
		if cpu, mem, ok := clamped.Resources.ResourcePercents(); ok && data.CPUPercent == 0 && data.MemoryPercent == 0 {
			data.CPUPercent, data.MemoryPercent = cpu, mem
		}
	}

	// Capture health BEFORE the heartbeat flips it to online, so we can detect
	// an offline/unknown/error -> online TRANSITION (a connect event) and audit
	// it once, instead of logging on every steady-state heartbeat.
	prevHealth := a.Health

	// Recompute the load score on a private copy (the repo may hand back a
	// shared/cached pointer) with this deployment's configured weights.
	snapshot := *a
	snapshot.UpdateExtendedMetricsWithWeights(sensordom.ExtendedMetrics{
		CPUPercent:    data.CPUPercent,
		MemoryPercent: data.MemoryPercent,
		DiskReadMBPS:  data.DiskReadMBPS,
		DiskWriteMBPS: data.DiskWriteMBPS,
		NetworkRxMBPS: data.NetworkRxMBPS,
		NetworkTxMBPS: data.NetworkTxMBPS,
		ActiveJobs:    data.CurrentJobs,
		Region:        data.Region,
	}, s.lbWeights)

	clientIP := net.ParseIP(data.IPAddress)

	var outbox *sensordom.OutboxStats
	if data.Outbox != nil {
		clamped := data.Outbox.Clamp()
		outbox = &clamped
	}

	now := s.now()
	userAgent := sensordom.SanitizeUserAgent(data.UserAgent)
	build, version := sensordom.ResolveBuild(data.Build, data.Version, userAgent, now)
	uptime := sensordom.ClampUptime(data.UptimeSeconds)
	carriedTools := data.Report != nil && data.Report.Tools != nil
	report := s.sanitizeReport(ctx, a, withSlimContent(a, data.Report, data.Content))
	// An SDK that reports its slots but no ceiling has none (sdk-go v0.13+:
	// max_concurrent_jobs is only the operator's cap). Older SDKs with a
	// load report always sent max_concurrent_jobs, so this clears exactly
	// the upper bound (64) they stored (RFC-033 §6.1). A slim heartbeat
	// carries no tools and says nothing about the ceiling.
	if carriedTools && report != nil && report.MaxConcurrentJobs == 0 &&
		load != nil && load.Capacity != nil && load.Capacity.SlotsTotal > 0 {
		report.NoCeiling = true
	}

	// The local policy report: sanitized, and a slim heartbeat's (state,
	// digest, kill switch) merged with the stored summary of the same policy.
	localPolicy := sensordom.MergeLocalPolicyReport(a.LocalPolicy, sensordom.SanitizeLocalPolicyReport(data.LocalPolicy))
	if data.LocalPolicy == nil {
		localPolicy = nil
	}

	updated, err := s.repo.UpdateHeartbeat(ctx, a.ID, sensordom.HeartbeatUpdate{
		TenantID:      a.TenantID,
		Version:       version,
		Hostname:      data.Hostname,
		IPAddress:     clientIP,
		Region:        data.Region,
		CPUPercent:    data.CPUPercent,
		MemoryPercent: data.MemoryPercent,
		DiskReadMBPS:  data.DiskReadMBPS,
		DiskWriteMBPS: data.DiskWriteMBPS,
		NetworkRxMBPS: data.NetworkRxMBPS,
		NetworkTxMBPS: data.NetworkTxMBPS,
		LoadScore:     snapshot.LoadScore,
		Outbox:        outbox,
		Protocol:      data.Protocol,
		Load:          load,
		UserAgent:     userAgent,

		Binding:        heartbeatBinding(data.Binding),
		FallbackReason: sensordom.SanitizeFallbackReason(data.FallbackReason),
		UptimeSeconds:  uptime,
		Report:         report,
		Build:          build,
		Interval:       sensordom.FollowedHeartbeatInterval(data.Control, data.AdvisedSeconds, data.DoorbellAware),
		Control:        data.Control,
		LocalPolicy:    localPolicy,
		// The digest the sensor holds: "" (none) marks a stored report stale.
		ConfigReportDigest: sensordom.HeartbeatConfigDigest(data.ConfigReport),
	})
	if err != nil {
		return err
	}
	if !updated {
		// The sensor was disabled/revoked (or deleted) between authentication
		// and this write. The guarded UPDATE left it untouched — which is the
		// point — and there is no connect event to record.
		s.logger.Debug("heartbeat ignored for non-active sensor", "sensor_id", a.ID.String())
		return nil
	}

	s.observeInstance(ctx, a, data.InstanceID, data.Hostname, now)
	s.renewLeases(ctx, a, data)
	s.observeHeartbeat(ctx, a, data, now)

	// Record a connect event only on an offline/unknown/error -> online
	// transition. A late or stale sensor never stopped being connected: its
	// heartbeat only came after its deadline (RFC-035 §5.6). Tenant sensors
	// only: platform sensors (TenantID == nil) are shared infrastructure with
	// no owning tenant to scope the audit log to.
	reconnected := !prevHealth.IsLive()
	if s.auditService != nil && reconnected && a.TenantID != nil {
		ip := "an unknown address"
		switch {
		case clientIP != nil:
			ip = clientIP.String()
		case a.IPAddress != nil:
			ip = a.IPAddress.String()
		}
		s.warnAudit(s.auditService.LogSensorConnected(ctx, auditapp.AuditContext{
			TenantID:   a.TenantID.String(),
			ActorEmail: sensorAuditSystemActor,
		}, a.ID.String(), a.Name, ip), "LogSensorConnected", a.ID.String())
	}

	// The activity timeline: what this heartbeat changed compared with the
	// stored row read above, plus the online transition.
	if a.TenantID != nil && s.events != nil {
		var startedAt *time.Time
		if uptime > 0 {
			t := now.Add(-time.Duration(uptime) * time.Second)
			startedAt = &t
		}
		var events []sensordom.Event
		if reconnected {
			if e, ok := sensordom.OnlineEvent(a, now); ok {
				events = append(events, e)
			}
		} else if e, ok := sensordom.RecoveredEvent(a, now); ok {
			// The heartbeat came after its deadline had made the sensor
			// late, stale or offline: one entry per recovery.
			events = append(events, e)
		}
		for _, e := range sensordom.DiffHeartbeat(a, sensordom.HeartbeatObservation{
			At: now, Version: version, Protocol: data.Protocol, StartedAt: startedAt, Report: report, Build: build,
		}) {
			// A sensor that registers its manifest records tool and
			// capacity changes as manifest_changed when it registers them
			// (RFC-033 §6.12); its heartbeat would only say it twice.
			if data.ManifestDigest != "" && (e.Type == sensordom.EventToolsChanged || e.Type == sensordom.EventCapacityChanged) {
				continue
			}
			events = append(events, e)
		}
		if data.LocalPolicy != nil {
			if e, ok := sensordom.LocalPolicyEvent(a, localPolicy, now); ok {
				events = append(events, e)
			}
		}
		s.recordEvents(ctx, events)
	}

	// A sensor that registers no manifest: keep the history of the one its
	// heartbeat implies (RFC-033 §6.6).
	if data.ManifestDigest == "" {
		s.recordDerivedManifest(ctx, a, report, build, version, now)
	}

	return nil
}

// observeHeartbeat feeds the heartbeat's gap (since the previous heartbeat,
// from the stored deadline: polls do not shorten it) to the metric and the
// tenant sensor's heartbeat history. Best effort: failures are logged.
func (s *SensorService) observeHeartbeat(ctx context.Context, a *sensordom.Sensor, data SensorHeartbeatData, now time.Time) {
	var gap time.Duration
	if prev := a.PreviousHeartbeatAt(); prev != nil && now.After(*prev) {
		gap = now.Sub(*prev)
	}
	interval := a.HeartbeatInterval
	if gap > 0 && s.gaps != nil {
		s.gaps.ObserveHeartbeatGap(gap, interval)
	}
	if s.history == nil || a.TenantID == nil {
		return
	}
	sample := sensordom.HeartbeatSample{TenantID: *a.TenantID, SensorID: a.ID, At: now, Gap: gap, Interval: interval}
	if c := data.Control; c != nil {
		sample.LagMillis, sample.Failures = c.LagMillis, c.Failures
	}
	if err := s.history.RecordHeartbeat(ctx, sample); err != nil {
		s.logger.Warn("heartbeat history not recorded", "sensor_id", a.ID.String(), "error", err)
	}
}

// maxRenewedCommands bounds the running list a heartbeat renews.
const maxRenewedCommands = 1000

// renewLeases renews the leases of the commands a heartbeating tenant
// sensor holds. Best effort: a failure is logged; the lease then runs out
// only if the next heartbeats fail too.
func (s *SensorService) renewLeases(ctx context.Context, a *sensordom.Sensor, data SensorHeartbeatData) {
	if s.leases == nil || a.TenantID == nil {
		return
	}
	ids := data.Running
	if len(ids) > maxRenewedCommands {
		ids = ids[:maxRenewedCommands]
	}
	if _, err := s.leases.RenewLeases(ctx, *a.TenantID, a.ID, ids, !data.RunningReported); err != nil {
		s.logger.Warn("command leases not renewed", "sensor_id", a.ID.String(), "error", err)
	}
}

// observeInstance feeds the heartbeat's process instance to clone
// detection (pkg/domain/sensor/identity.go). An unchanged instance (every
// steady-state heartbeat) costs nothing; a change is applied under a row
// lock. When two live instances alternate the identity is flagged once:
// an event on the sensor's timeline and a high-severity audit entry.
// Best-effort: a failure is logged and never fails the heartbeat.
func (s *SensorService) observeInstance(ctx context.Context, a *sensordom.Sensor, instanceID, hostname string, now time.Time) {
	obs, ok := s.repo.(sensordom.InstanceObserver)
	if !ok || a.TenantID == nil {
		return
	}
	inst := sensordom.HeartbeatInstance(instanceID, hostname)
	if inst == "" || inst == a.InstanceID {
		return
	}
	var lastSeen time.Time
	if a.LastSeenAt != nil {
		lastSeen = *a.LastSeenAt
	}
	verdict, flagged, err := obs.ObserveInstance(ctx, a.ID, inst, now, lastSeen)
	if err != nil {
		s.logger.Warn("failed to observe sensor instance", "sensor_id", a.ID.String(), "error", err)
		return
	}
	if !flagged {
		return
	}
	s.logger.Warn("sensor identity cloned: two live instances use the same key",
		"sensor_id", a.ID.String(), "instances", len(verdict.Live))
	s.recordEvents(ctx, []sensordom.Event{sensordom.NewEvent(*a.TenantID, a.ID, sensordom.EventIdentityCloned, now,
		"Two sensor processes are using the same API key",
		map[string]any{"instances": verdict.Live})})
	if s.auditService != nil {
		s.warnAudit(s.auditService.LogSensorIdentityCloned(ctx, auditapp.AuditContext{
			TenantID:   a.TenantID.String(),
			ActorEmail: sensorAuditSystemActor,
		}, a.ID.String(), a.Name, len(verdict.Live)), "LogSensorIdentityCloned", a.ID.String())
	}
}

// RecordOffline records the offline transition of a sensor the health
// checker marked offline.
func (s *SensorService) RecordOffline(ctx context.Context, a *sensordom.Sensor) {
	if e, ok := sensordom.OfflineEvent(a, s.now()); ok {
		s.recordEvents(ctx, []sensordom.Event{e})
	}
}

// ActivityInput selects a page of a sensor's activity timeline.
type ActivityInput struct {
	TenantID string
	SensorID string
	// Categories filters the timeline; empty means all.
	Categories []string
	// IncludeAudit admits audit-log items (the caller holds audit:read).
	IncludeAudit bool
	Cursor       string
	Limit        int
}

// ActivityPage is one page of a sensor's timeline.
type ActivityPage struct {
	Items      []sensordom.ActivityItem
	NextCursor string
}

// Activity limits.
const (
	DefaultActivityLimit = 30
	MaxActivityLimit     = 100
)

// ListActivity returns a page of the sensor's timeline: its events, its jobs
// and, when admitted, its audit rows (including those written before the
// rename as resource type "agent"), newest first. The sensor must belong to
// the tenant.
func (s *SensorService) ListActivity(ctx context.Context, in ActivityInput) (*ActivityPage, error) {
	if s.activity == nil {
		return nil, shared.NewDomainError("UNAVAILABLE", "sensor activity is not available", shared.ErrInternal)
	}
	a, err := s.GetSensor(ctx, in.TenantID, in.SensorID)
	if err != nil {
		return nil, err
	}
	if a.TenantID == nil {
		return nil, shared.ErrNotFound
	}

	cats := make([]sensordom.ActivityCategory, 0, len(in.Categories))
	for _, c := range in.Categories {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		cat := sensordom.ActivityCategory(c)
		if !cat.IsValid() {
			return nil, fmt.Errorf("%w: unknown activity type %q (want people, status, updates or jobs)", shared.ErrValidation, c)
		}
		if !slices.Contains(cats, cat) {
			cats = append(cats, cat)
		}
	}
	if len(cats) == 0 {
		cats = sensordom.AllCategories()
	}

	cursor, err := sensordom.ParseActivityCursor(in.Cursor)
	if err != nil {
		return nil, err
	}
	limit := in.Limit
	if limit <= 0 {
		limit = DefaultActivityLimit
	}
	limit = min(limit, MaxActivityLimit)

	items, err := s.activity.ListActivity(ctx, sensordom.ActivityQuery{
		TenantID: *a.TenantID, SensorID: a.ID, Categories: cats,
		IncludeAudit: in.IncludeAudit, After: cursor, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	page := &ActivityPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = sensordom.ActivityCursor{At: last.At, Key: last.Key}.Encode()
	}
	return page, nil
}

// DeleteSensor deletes a sensor.
func (s *SensorService) DeleteSensor(ctx context.Context, tenantID, sensorID string, auditCtx *auditapp.AuditContext) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	aid, err := shared.IDFromString(sensorID)
	if err != nil {
		return fmt.Errorf("%w: invalid sensor id", shared.ErrValidation)
	}

	// Verify sensor belongs to tenant and get sensor info for audit
	a, err := s.repo.GetByTenantAndID(ctx, tid, aid)
	if err != nil {
		return err
	}

	sensorName := a.Name

	if err := s.repo.Delete(ctx, aid); err != nil {
		return err
	}
	s.notifyStatus(a)

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		s.warnAudit(s.auditService.LogSensorDeleted(ctx, *auditCtx, sensorID, sensorName), "LogSensorDeleted", sensorID)
	}

	return nil
}

// RegenerateAPIKey generates a new API key for a sensor.
//
// This is the admin "hard rotation": the new inline key replaces the old one
// AND every key row in the multi-key store (sensor_api_keys — keys the sensor
// minted for itself through overlapping self-renewal) is revoked. Without the
// second step a renewed key survived the regeneration, so an operator rotating
// a leaked credential left the attacker's renewed copy working.
func (s *SensorService) RegenerateAPIKey(ctx context.Context, tenantID, sensorID string, auditCtx *auditapp.AuditContext) (string, error) {
	a, err := s.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return "", err
	}

	apiKey, hash, prefix, err := s.generateSensorAPIKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Targeted write of the key columns only (admin-regenerated keys never
	// expire). No status guard: an admin may rotate a disabled sensor's key.
	// With the multi-key store, the inline key and the revocation of every
	// key row are written in one transaction under the per-sensor key lock
	// that renewals take, so a renewal that authenticated with the old key
	// cannot mint a row after the revocation (it is refused instead).
	var updated bool
	if s.apiKeyRepo != nil {
		updated, err = s.apiKeyRepo.RegenerateKey(ctx, a.ID, hash, prefix, "regenerated")
	} else {
		updated, err = s.repo.UpdateAPIKey(ctx, a.ID, hash, prefix, nil, false)
	}
	if err != nil {
		return "", err
	}
	if !updated {
		return "", shared.ErrNotFound
	}
	a.SetAPIKey(hash, prefix)

	// Copies of the old key can no longer connect: a cloned-identity flag
	// raised against it is resolved.
	if obs, ok := s.repo.(sensordom.InstanceObserver); ok && a.IdentityClonedAt != nil {
		if err := obs.ClearIdentityCloned(ctx, a.ID); err != nil {
			s.logger.Warn("failed to clear the cloned-identity flag", "sensor_id", a.ID.String(), "error", err)
		}
	}

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		s.warnAudit(s.auditService.LogSensorKeyRegenerated(ctx, *auditCtx, sensorID, a.Name), "LogSensorKeyRegenerated", sensorID)
	}

	return apiKey, nil
}

// RenewAPIKey lets an already-authenticated sensor rotate its own credential.
//
// Unlike RegenerateAPIKey (an admin action, tenant+id scoped), this is the
// self-service renewal a sensor drives itself: it presents its
// current key, gets authenticated by AuthenticateIdentity upstream, and calls
// this with that identity to mint a fresh one. The identity says which
// credential was presented (the inline key or a sensor_api_keys row).
//
// The passed sensor is the one resolved from the presented key. We re-read it by
// ID so a concurrent admin status change (disable/revoke) is not clobbered by a
// stale in-memory copy, and re-check CanAuthenticate to refuse renewal for an
// sensor that was disabled/revoked in the auth→renew window. Works for both
// tenant and platform (nil-tenant) sensors since the lookup/update key on ID.
//
// A renewal has exactly one successor: the presented key, and every other
// credential the sensor still held, stops authenticating once the renewal
// grace (SetRenewGrace) has passed. A copied key therefore cannot renew itself
// a parallel line of long-lived keys: the next renewal by either holder retires
// the other's keys, and the sensor that lost its key has to be re-enrolled,
// which an administrator sees.
//
// When a key TTL is configured (SetKeyTTL), the new key carries a fresh expiry
// and the sensor is expected to renew again before it lapses; otherwise the key
// never expires (today's behavior). Returns the new key and its expiry (nil =
// never expires) so the sensor can schedule its next renewal.
func (s *SensorService) RenewAPIKey(ctx context.Context, id SensorIdentity) (string, *time.Time, error) {
	a := id.Sensor
	if a == nil {
		return "", nil, shared.NewDomainError("UNAUTHORIZED", "no authenticated sensor", shared.ErrUnauthorized)
	}

	// A key-bound sensor has no bearer key and never gets one (RFC-052,
	// RFC-032 D3): minting one would hand a bearer secret to a sensor that
	// proved it can sign.
	if a.KeyBound() || id.KeyBound() {
		return "", nil, shared.NewDomainError("FORBIDDEN", "key-bound sensors do not use API keys", shared.ErrForbidden)
	}
	fresh, err := s.repo.GetByID(ctx, a.ID)
	if err != nil {
		return "", nil, err
	}
	if fresh.KeyBound() {
		return "", nil, shared.NewDomainError("FORBIDDEN", "key-bound sensors do not use API keys", shared.ErrForbidden)
	}
	if !fresh.Status.CanAuthenticate() {
		if fresh.Status == sensordom.SensorStatusRevoked {
			return "", nil, shared.NewDomainError("FORBIDDEN", "sensor access has been revoked", shared.ErrForbidden)
		}
		return "", nil, shared.NewDomainError("FORBIDDEN", "sensor is disabled", shared.ErrForbidden)
	}

	apiKey, hash, prefix, err := s.generateSensorAPIKey()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	now := s.now()
	var expiresAt *time.Time
	if s.keyTTL > 0 {
		t := now.Add(s.keyTTL)
		expiresAt = &t
	}
	retireAt := now.Add(s.renewGrace)
	if expiresAt != nil && retireAt.After(*expiresAt) {
		retireAt = *expiresAt
	}
	presented := id.presentedKey(now)

	// Rotation overlap (RFC-014 Phase 3): with the multi-key store wired AND a
	// TTL configured, issue the new key as its own sensor_api_keys row so the key
	// it supersedes keeps working through the renewal grace — zero-downtime
	// rotation. Without both, fall back to replacing the single inline hash.
	if s.apiKeyRepo != nil && expiresAt != nil {
		if err := s.issueOverlappingKey(ctx, fresh, id, presented, hash, prefix, *expiresAt, retireAt); err != nil {
			if refused := s.renewalRefused(ctx, fresh, id, err); refused != nil {
				return "", nil, refused
			}
			return "", nil, err
		}
		s.logger.Info("sensor renewed its API key (overlap)",
			"sensor_id", fresh.ID.String(), "is_platform", fresh.IsPlatformSensor,
			"presented", id.presentedKeyLabel(), "expires_at", expiresAt, "previous_keys_expire_at", retireAt)
		s.auditKeyRenewed(ctx, fresh, expiresAt, true, id.presentedLegacy)
		return apiKey, expiresAt, nil
	}

	// Targeted, status-guarded write of the key columns only: a full-row
	// Update would also write back the status read above and could revive an
	// sensor an admin revoked in the meantime. The replaced inline key stops
	// authenticating at once. With the multi-key store wired, rotating keys
	// issued while a TTL was configured (the presented key may be one) are
	// retired in the same transaction, serialized with every other renewal of
	// the sensor, so none of them outlives the renewal.
	var updated bool
	if s.apiKeyRepo != nil {
		updated, err = s.apiKeyRepo.ReplaceInlineKey(ctx, fresh.ID, presented, hash, prefix, expiresAt, retireAt)
		if err == nil && !updated {
			err = sensordom.ErrSensorDisabled
		}
	} else {
		updated, err = s.repo.UpdateAPIKey(ctx, fresh.ID, hash, prefix, expiresAt, true)
	}
	if err != nil {
		if refused := s.renewalRefused(ctx, fresh, id, err); refused != nil {
			return "", nil, refused
		}
		return "", nil, err
	}
	if !updated {
		return "", nil, shared.NewDomainError("FORBIDDEN", "sensor is not active", shared.ErrForbidden)
	}

	s.logger.Info("sensor renewed its API key",
		"sensor_id", fresh.ID.String(), "is_platform", fresh.IsPlatformSensor,
		"presented", id.presentedKeyLabel(), "expires_at", expiresAt)
	s.auditKeyRenewed(ctx, fresh, expiresAt, false, id.presentedLegacy)
	return apiKey, expiresAt, nil
}

// auditKeyRenewed records a sensor self-renewal in the tenant audit log.
// fromLegacy marks the renewal that moved the sensor off a legacy rda_ key
// (the new key is always octs_). Platform sensors (no tenant) have no tenant
// log to write to, so their move is only logged.
func (s *SensorService) auditKeyRenewed(ctx context.Context, a *sensordom.Sensor, expiresAt *time.Time, overlap, fromLegacy bool) {
	if fromLegacy {
		s.logger.Info("sensor moved from a legacy rda_ key to an octs_ key on renewal",
			"sensor_id", a.ID.String(), "is_platform", a.IsPlatformSensor)
	}
	if s.auditService == nil || a.TenantID == nil {
		return
	}
	s.warnAudit(s.auditService.LogSensorKeyRenewed(ctx, auditapp.AuditContext{
		TenantID:   a.TenantID.String(),
		ActorEmail: sensorAuditSystemActor,
	}, a.ID.String(), a.Name, expiresAt, overlap, fromLegacy), "LogSensorKeyRenewed", a.ID.String())
}

// renewalRefused turns a renewal the repository refused under the per-sensor
// key lock into the error the sensor gets, and records it: the key it
// authenticated with was revoked, expired or regenerated, or the sensor
// disabled or revoked, after the authentication. Nothing was written. A
// refusal on the key itself is a security signal, because something still
// holds a key an administrator killed. Returns nil for any other error.
func (s *SensorService) renewalRefused(ctx context.Context, a *sensordom.Sensor, id SensorIdentity, err error) error {
	var refused *shared.DomainError
	switch {
	case errors.Is(err, sensordom.ErrPresentedKeyInvalid):
		refused = shared.NewDomainError("UNAUTHORIZED", "the presented API key is no longer valid", shared.ErrUnauthorized)
	case errors.Is(err, sensordom.ErrSensorRevoked):
		refused = shared.NewDomainError("FORBIDDEN", "sensor access has been revoked", shared.ErrForbidden)
	case errors.Is(err, sensordom.ErrSensorDisabled):
		refused = shared.NewDomainError("FORBIDDEN", "sensor is not active", shared.ErrForbidden)
	default:
		return nil
	}
	reason := err.Error()
	s.logger.Warn("sensor key renewal refused",
		"sensor_id", a.ID.String(), "is_platform", a.IsPlatformSensor,
		"presented", id.presentedKeyLabel(), "reason", reason)
	if s.auditService != nil && a.TenantID != nil {
		s.warnAudit(s.auditService.LogSensorKeyRenewalRefused(ctx, auditapp.AuditContext{
			TenantID:   a.TenantID.String(),
			ActorEmail: sensorAuditSystemActor,
		}, a.ID.String(), a.Name, reason), "LogSensorKeyRenewalRefused", a.ID.String())
	}
	return refused
}

// issueOverlappingKey issues the renewed key as a new sensor_api_keys row and
// retires every credential it supersedes at retireAt (the renewal grace):
//
//   - every other active key row of the sensor, the presented key among them;
//   - the inline key on the sensor row, guarded by its hash — the presented
//     key's (any pepper variant), or the one read above when a key row was
//     presented — so an admin regeneration landing in between is not cut
//     short.
//
// The repository does all of it in one transaction under a per-sensor lock
// (APIKeyRepository.RotateKey), so concurrent renewals of one sensor run one
// after another and end with exactly one long-lived key: the last one issued.
// Done as separate writes, two renewals interleaved and each kept its own key
// long-lived, so a superseded (possibly leaked) credential outlived the
// renewal until its own expiry.
//
// Retirement only ever brings an expiry earlier (never extends one) and
// touches only the expiry columns, so it cannot undo a concurrent admin
// revoke or regeneration. A failure fails the renewal and writes nothing: the
// sensor keeps its old key and retries, rather than receive a new key while
// the old one stays long-lived.
//
// Under the same lock the repository re-checks presented and the sensor's
// status, so a key an administrator regenerated after the renewal
// authenticated is refused instead of renewed (see renewalRefused).
func (s *SensorService) issueOverlappingKey(ctx context.Context, fresh *sensordom.Sensor, id SensorIdentity, presented sensordom.PresentedKey, hash, prefix string, expiresAt, retireAt time.Time) error {
	key, err := sensordom.NewAPIKey(fresh.ID, "renewed", scopesForSensor(fresh.Type))
	if err != nil {
		return err
	}
	key.SetKeyHash(hash, prefix)
	key.SetExpiration(expiresAt)

	inlineHashes := id.keyHashes
	if id.KeyID != nil || len(inlineHashes) == 0 {
		inlineHashes = nil
		if fresh.APIKeyHash != "" {
			inlineHashes = []string{fresh.APIKeyHash}
		}
	}
	if err := s.apiKeyRepo.RotateKey(ctx, key, presented, inlineHashes, retireAt); err != nil {
		return fmt.Errorf("issue overlapping key: %w", err)
	}

	s.pruneExpiredKeys(ctx, fresh.ID)
	return nil
}

// pruneExpiredKeys revokes a sensor's active-but-expired key rows so the active
// set stays bounded to the current overlap pair. Best-effort; failures are logged.
func (s *SensorService) pruneExpiredKeys(ctx context.Context, sensorID shared.ID) {
	keys, err := s.apiKeyRepo.GetBySensorID(ctx, sensorID)
	if err != nil {
		return
	}
	for _, k := range keys {
		if k.IsActive && k.IsExpired() {
			if err := s.apiKeyRepo.Revoke(ctx, k.ID, "expired"); err != nil {
				s.logger.Debug("prune expired key failed", "key_id", k.ID.String(), "error", err)
			}
		}
	}
}

// scopesForSensor returns the default least-privilege scope set for a sensor type
// (used when minting a rotated key). Prep for scope enforcement (Phase 4).
func scopesForSensor(t sensordom.SensorType) []string {
	switch t {
	case sensordom.SensorTypeCollector:
		return sensordom.CollectorScopes()
	case sensordom.SensorTypeEASM:
		return sensordom.SensorScopes()
	case sensordom.SensorTypeWorker:
		return sensordom.WorkerScopes()
	default:
		return sensordom.DefaultSensorScopes()
	}
}

// AuthenticateByAPIKey authenticates a sensor by API key.
// Authentication is based on admin-controlled Status field only:
// - Active: allowed to authenticate
// - Disabled: admin has disabled the sensor
// - Revoked: access permanently revoked
// The Health field (unknown/online/offline/error) is for monitoring only.
func (s *SensorService) AuthenticateByAPIKey(ctx context.Context, apiKey string) (*sensordom.Sensor, error) {
	id, err := s.authenticate(ctx, apiKey, "", false)
	if err != nil {
		return nil, err
	}
	return id.Sensor, nil
}

// SensorIdentity is the sensor a presented key belongs to, with what the
// heartbeat doorbell needs beyond the sensor row itself.
type SensorIdentity struct {
	Sensor *sensordom.Sensor
	// KeyExpiresAt is the expiry of the key the sensor actually presented
	// (nil = never expires). With rotation overlap that is the
	// sensor_api_keys row, not the inline key on the sensor row.
	KeyExpiresAt *time.Time
	// Paused is true when an administrator disabled the sensor. Disabling is
	// reversible, so a disabled sensor may still learn over the heartbeat
	// that it is paused; every other route keeps rejecting its key.
	Paused bool
	// KeyID is the sensor_api_keys row the presented key matched; nil when
	// it matched the inline key on the sensor row. Renewal retires the
	// presented key, so it has to know which one that was.
	KeyID *shared.ID
	// keyHashes are the hashes the presented inline key can be stored under
	// (current pepper, earlier peppers, plain SHA-256): authentication may
	// re-hash the stored value onto the current pepper, so renewal matches
	// the inline row on any of them. All derive from the presented key, so
	// a key an administrator regenerated meanwhile never matches. Set only
	// by authentication, only for the inline key.
	keyHashes []string
	// signingKeyID and keyThumbprint are the sensor_keys row a signed
	// request verified with (RFC-052); nil/"" for a bearer key.
	signingKeyID  *shared.ID
	keyThumbprint string
	// presentedLegacy is true when the presented key is a legacy rda_ key.
	// A renewal from one is the sensor's move to the octs_ format, which the
	// renewal audit event records. Set only by authentication.
	presentedLegacy bool
}

// PresentedLegacyKey reports whether the sensor authenticated with a legacy
// rda_ key.
func (id SensorIdentity) PresentedLegacyKey() bool { return id.presentedLegacy }

// presentedKey is the credential the renewal re-checks under the key lock,
// expiry judged at at. An identity built without authentication (no key row,
// no hashes) presents the inline key the sensor held when it was read.
func (id SensorIdentity) presentedKey(at time.Time) sensordom.PresentedKey {
	p := sensordom.PresentedKey{KeyID: id.KeyID, InlineKeyHashes: id.keyHashes, At: at}
	if p.KeyID == nil && len(p.InlineKeyHashes) == 0 && id.Sensor != nil && id.Sensor.APIKeyHash != "" {
		p.InlineKeyHashes = []string{id.Sensor.APIKeyHash}
	}
	return p
}

// presentedKeyLabel names the presented credential for logs.
func (id SensorIdentity) presentedKeyLabel() string {
	switch {
	case id.KeyID != nil:
		return "key:" + id.KeyID.String()
	case len(id.keyHashes) > 0:
		return "inline"
	default:
		return "unknown"
	}
}

// AuthenticateIdentity authenticates a sensor key like AuthenticateByAPIKey,
// with one difference: a disabled (not revoked) sensor with a valid,
// unexpired key is returned with Paused set instead of being refused. The
// caller decides what a paused sensor may reach — only the heartbeat, to be
// told to pause (RFC-023 §9.2a). A paused sensor's last-seen time is not
// touched.
func (s *SensorService) AuthenticateIdentity(ctx context.Context, apiKey string) (SensorIdentity, error) {
	return s.authenticate(ctx, apiKey, "", true)
}

// AuthenticateIdentityFrom is AuthenticateIdentity for a request from
// clientIP (the HTTP layer's trusted-proxy-aware client address, never a
// value the sensor chose): the address is recorded on the key use, and a
// change of address is written to the sensor's activity timeline.
func (s *SensorService) AuthenticateIdentityFrom(ctx context.Context, apiKey, clientIP string) (SensorIdentity, error) {
	return s.authenticate(ctx, apiKey, clientIP, true)
}

func (s *SensorService) authenticate(ctx context.Context, apiKey, clientIP string, allowPaused bool) (SensorIdentity, error) {
	// Offline format check before any hashing or lookup: an octs_ key whose
	// checksum fails (mistyped, truncated) and an octe_ enrollment token are
	// refused here with the same generic error as an unknown key. This is not
	// a security control (the checksum is public); it only saves the database
	// round trips. Legacy rda_ keys carry no checksum and go on to the lookup.
	if !sensorkey.AcceptableSensorKey(apiKey) {
		return SensorIdentity{}, shared.NewDomainError("UNAUTHORIZED", "invalid API key", shared.ErrUnauthorized)
	}
	legacy := sensorkey.IsLegacy(apiKey)

	// Lookup by each stored-hash variant the key may have: current pepper,
	// earlier peppers (RFC-032 Phase 0), plain SHA-256 (rows from before any
	// pepper). Each is an equality match on the unique index; the common
	// case (a key stored under the current pepper) is one query.
	hashes := s.candidateHashes(apiKey)
	var (
		a       *sensordom.Sensor
		err     = shared.ErrNotFound
		matched string
	)
	for _, h := range hashes {
		if a, err = s.repo.GetByAPIKeyHash(ctx, h); err == nil {
			matched = h
			break
		}
	}
	if err != nil {
		// Inline-hash miss: try the multi-key store (RFC-014 Phase 3). Only
		// reached for keys issued by self-renewal under rotation overlap; the
		// common inline-key path above is unchanged.
		if id, rowErr := s.authByAPIKeyRow(ctx, hashes, clientIP, allowPaused); rowErr == nil {
			id.presentedLegacy = legacy
			return id, nil
		}
		return SensorIdentity{}, shared.NewDomainError("UNAUTHORIZED", "invalid API key", shared.ErrUnauthorized)
	}

	// A key-bound sensor signs its requests; no bearer key may stand in for
	// it (RFC-052). Its stored hash is an unmatchable placeholder, so this
	// only fires if a row was left inconsistent.
	if a.KeyBound() {
		return SensorIdentity{}, shared.NewDomainError("UNAUTHORIZED", "invalid API key", shared.ErrUnauthorized)
	}

	// Check admin-controlled status (not health)
	paused, err := checkSensorStatus(a, allowPaused)
	if err != nil {
		return SensorIdentity{}, err
	}

	// Reject an expired key (RFC-014 Phase 1b). NULL expiry (the default and
	// every legacy row) never expires, so this is a no-op until an operator
	// configures a key TTL and sensors renew. An expired sensor must re-enroll or
	// be admin-regenerated; unauthorized (not forbidden) signals "renew/re-auth".
	if a.IsKeyExpired() {
		return SensorIdentity{}, shared.NewDomainError("UNAUTHORIZED", "api key expired", shared.ErrUnauthorized)
	}

	if matched != hashes[0] {
		s.rehashKey(ctx, s.repo, "inline", a.ID, matched, hashes[0])
	}
	if !paused {
		s.recordKeyUseAsync(a, clientIP, nil)
	}

	return SensorIdentity{Sensor: a, KeyExpiresAt: a.InlineKeyExpiresAt, Paused: paused, keyHashes: hashes, presentedLegacy: legacy}, nil
}

// recordKeyUseAsync marks the sensor seen and records where the key was
// used from, off the request path (bounded by a timeout so a slow database
// cannot pile up goroutines under sensor traffic). keyUsage, when set,
// records the use on the sensor_api_keys row too.
func (s *SensorService) recordKeyUseAsync(a *sensordom.Sensor, clientIP string, keyUsage func(context.Context, string)) {
	sensorID, tenantID, name := a.ID, a.TenantID, a.Name
	ip := net.ParseIP(clientIP)
	// When the key was used, taken on the request path: the goroutines below
	// can reach the database out of order.
	usedAt := s.now()
	if !s.keyUse.due(sensorID.String()+"|"+clientIP, usedAt) {
		return
	}
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if keyUsage != nil {
			keyUsage(bg, clientIP)
		}
		rec, ok := s.repo.(sensordom.KeyUseRecorder)
		if !ok {
			_ = s.repo.UpdateLastSeen(bg, sensorID)
			return
		}
		prev, err := rec.RecordKeyUse(bg, sensorID, ip, usedAt)
		if err != nil {
			s.logger.Debug("failed to record sensor key use", "sensor_id", sensorID.String(), "error", err)
			return
		}
		if ip != nil && prev != nil && !prev.Equal(ip) && tenantID != nil {
			s.recordEvents(bg, []sensordom.Event{sensordom.NewEvent(*tenantID, sensorID, sensordom.EventKeyIPChanged, s.now(),
				fmt.Sprintf("The API key was used from %s (before: %s)", ip, prev),
				map[string]any{"ip": ip.String(), "previous_ip": prev.String(), "sensor_name": name})})
		}
	}()
}

// checkSensorStatus applies the admin-controlled status: active passes,
// revoked never does, and disabled passes as paused only when allowPaused.
func checkSensorStatus(a *sensordom.Sensor, allowPaused bool) (paused bool, err error) {
	if a.Status.CanAuthenticate() {
		return false, nil
	}
	if a.Status == sensordom.SensorStatusDisabled && allowPaused {
		return true, nil
	}
	if a.Status == sensordom.SensorStatusRevoked {
		return false, shared.NewDomainError("FORBIDDEN", "sensor access has been revoked", shared.ErrForbidden)
	}
	return false, shared.NewDomainError("FORBIDDEN", "sensor is disabled", shared.ErrForbidden)
}

// authByAPIKeyRow resolves a sensor via the multi-key sensor_api_keys store
// (RFC-014 Phase 3). Returns ErrUnauthorized on any miss/invalid so the caller
// falls through to a single generic error. GetByHash already filters to active
// keys; IsValid additionally rejects expired ones. The owning sensor's
// admin-controlled status still governs — a revoked/disabled sensor cannot
// authenticate with any of its keys (a disabled one only reaches the
// heartbeat, as paused, when allowPaused).
func (s *SensorService) authByAPIKeyRow(ctx context.Context, hashes []string, clientIP string, allowPaused bool) (SensorIdentity, error) {
	if s.apiKeyRepo == nil {
		return SensorIdentity{}, shared.ErrUnauthorized
	}

	var (
		key     *sensordom.APIKey
		err     = shared.ErrNotFound
		matched string
	)
	for _, h := range hashes {
		if key, err = s.apiKeyRepo.GetByHash(ctx, h); err == nil {
			matched = h
			break
		}
	}
	if err != nil || key == nil || !key.IsValid() {
		return SensorIdentity{}, shared.ErrUnauthorized
	}

	a, err := s.repo.GetByID(ctx, key.SensorID)
	if err != nil {
		return SensorIdentity{}, shared.ErrUnauthorized
	}
	if a.KeyBound() {
		return SensorIdentity{}, shared.ErrUnauthorized
	}
	paused, err := checkSensorStatus(a, allowPaused)
	if err != nil {
		return SensorIdentity{}, err
	}
	if matched != hashes[0] {
		s.rehashKey(ctx, s.apiKeyRepo, "row", key.ID, matched, hashes[0])
	}
	keyID := key.ID
	if paused {
		return SensorIdentity{Sensor: a, KeyExpiresAt: key.ExpiresAt, Paused: true, KeyID: &keyID}, nil
	}

	// Async per-key usage (count, time, client address) + sensor liveness.
	s.recordKeyUseAsync(a, clientIP, func(bg context.Context, ip string) {
		_ = s.apiKeyRepo.RecordUsage(bg, keyID, ip)
	})

	return SensorIdentity{Sensor: a, KeyExpiresAt: key.ExpiresAt, KeyID: &keyID}, nil
}

// ActivateSensor activates a sensor (admin action).
func (s *SensorService) ActivateSensor(ctx context.Context, tenantID, sensorID string, auditCtx *auditapp.AuditContext) (*sensordom.Sensor, error) {
	a, err := s.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}

	if a.Status == sensordom.SensorStatusRevoked {
		return nil, shared.NewDomainError("FORBIDDEN", "cannot activate revoked sensor", shared.ErrForbidden)
	}

	a.Activate()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, err
	}
	s.notifyStatus(a)

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		s.warnAudit(s.auditService.LogSensorActivated(ctx, *auditCtx, sensorID, a.Name), "LogSensorActivated", sensorID)
	}

	s.logger.Info("sensor activated", "sensor_id", logger.SanitizeValue(sensorID))
	return a, nil
}

// DisableSensor disables a sensor (admin action).
func (s *SensorService) DisableSensor(ctx context.Context, tenantID, sensorID, reason string, auditCtx *auditapp.AuditContext) (*sensordom.Sensor, error) {
	a, err := s.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}

	if reason == "" {
		reason = "Disabled by administrator"
	}
	a.Disable(reason)

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, err
	}
	s.notifyStatus(a)

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		s.warnAudit(s.auditService.LogSensorDeactivated(ctx, *auditCtx, sensorID, a.Name, reason), "LogSensorDeactivated", sensorID)
	}
	s.releaseHeldCommands(ctx, a, auditCtx)

	s.logger.Info("sensor disabled", "sensor_id", logger.SanitizeValue(sensorID), "reason", logger.SanitizeValue(reason))
	return a, nil
}

// releaseHeldCommands takes back the commands a sensor that was just revoked
// or disabled holds under a lease (RFC-040 §5.2): routed scan work is
// re-queued for another sensor, the rest fails, and the old holder's late
// writes are fenced off. It runs after the status change is stored, so a
// failure here cannot undo the revocation; it is logged, and the lease
// reaper takes the commands back when their lease runs out.
func (s *SensorService) releaseHeldCommands(ctx context.Context, a *sensordom.Sensor, auditCtx *auditapp.AuditContext) {
	if s.holders == nil || a == nil || a.TenantID == nil {
		return
	}
	var why, requeueMsg, failMsg string
	switch a.Status {
	case sensordom.SensorStatusRevoked:
		why, requeueMsg, failMsg = "revoked", commanddom.SensorRevokedRequeuedMessage, commanddom.SensorRevokedFailedMessage
	case sensordom.SensorStatusDisabled:
		why, requeueMsg, failMsg = "disabled", commanddom.SensorDisabledRequeuedMessage, commanddom.SensorDisabledFailedMessage
	default:
		return
	}
	released, err := s.holders.ReleaseHeldBySensor(ctx, *a.TenantID, a.ID, requeueMsg, failMsg)
	if err != nil {
		s.logger.Error("failed to release the commands of a "+why+" sensor; they wait for their lease to expire",
			"sensor_id", a.ID.String(), "error", logger.SanitizeError(err))
		return
	}
	if len(released) == 0 {
		return
	}
	var requeued, failed []string
	for _, rc := range released {
		if rc.Requeued {
			requeued = append(requeued, rc.ID.String())
		} else {
			failed = append(failed, rc.ID.String())
		}
	}
	s.logger.Info("released the commands of a "+why+" sensor",
		"sensor_id", a.ID.String(), "requeued", len(requeued), "failed", len(failed))
	if s.auditService == nil {
		return
	}
	actx := auditapp.AuditContext{TenantID: a.TenantID.String(), ActorEmail: sensorAuditSystemActor}
	if auditCtx != nil {
		actx = *auditCtx
	}
	s.warnAudit(s.auditService.LogSensorCommandsReleased(ctx, actx, a.ID.String(), a.Name, why, requeued, failed),
		"LogSensorCommandsReleased", a.ID.String())
}

// RevokeSensor permanently revokes a sensor's access (admin action).
func (s *SensorService) RevokeSensor(ctx context.Context, tenantID, sensorID, reason string, auditCtx *auditapp.AuditContext) (*sensordom.Sensor, error) {
	a, err := s.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}

	if reason == "" {
		reason = "Revoked by administrator"
	}
	a.Revoke(reason)

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, err
	}

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		s.warnAudit(s.auditService.LogSensorRevoked(ctx, *auditCtx, sensorID, a.Name, reason), "LogSensorRevoked", sensorID)
	}
	s.releaseHeldCommands(ctx, a, auditCtx)
	// A revoked sensor's signing keys are revoked too (they already
	// authenticate nothing once the sensor is revoked; this keeps the key
	// list honest and survives a later reactivation attempt).
	if s.signingKeys != nil && a.TenantID != nil {
		if _, err := s.signingKeys.RevokeAllForSensor(ctx, *a.TenantID, a.ID, sensordom.KeyRevokedSensor, s.now()); err != nil {
			s.logger.Warn("failed to revoke signing keys of a revoked sensor", "sensor_id", a.ID.String(), "error", err)
		}
	}
	s.notifyStatus(a)

	s.logger.Info("sensor revoked", "sensor_id", logger.SanitizeValue(sensorID), "reason", logger.SanitizeValue(reason))
	return a, nil
}

// SensorHeartbeatInput represents the input for sensor heartbeat.
type SensorHeartbeatInput struct {
	SensorID  shared.ID
	Status    string
	Message   string
	Version   string
	Hostname  string
	IPAddress string
}

// Heartbeat updates sensor status from heartbeat.
func (s *SensorService) Heartbeat(ctx context.Context, input SensorHeartbeatInput) error {
	a, err := s.repo.GetByID(ctx, input.SensorID)
	if err != nil {
		return err
	}

	a.UpdateLastSeen()

	if input.Version != "" || input.Hostname != "" || input.IPAddress != "" {
		var ip net.IP
		if input.IPAddress != "" {
			ip = net.ParseIP(input.IPAddress)
		}
		a.UpdateRuntimeInfo(input.Version, input.Hostname, ip)
	}

	if input.Message != "" {
		a.StatusMessage = input.Message
	}

	return s.repo.Update(ctx, a)
}

// FindAvailableSensors finds sensors that can handle a task.
func (s *SensorService) FindAvailableSensors(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*sensordom.Sensor, error) {
	return s.repo.FindAvailable(ctx, tenantID, capabilities, tool)
}

// FindAvailableWithCapacity finds sensors with available job capacity for load balancing.
func (s *SensorService) FindAvailableWithCapacity(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*sensordom.Sensor, error) {
	return s.repo.FindAvailableWithCapacity(ctx, tenantID, capabilities, tool)
}

// IncrementStats increments sensor statistics.
func (s *SensorService) IncrementStats(ctx context.Context, sensorID shared.ID, findings, scans, errors int64) error {
	return s.repo.IncrementStats(ctx, sensorID, findings, scans, errors)
}

// generateSensorAPIKey generates a new API key for a sensor and the
// peppered hash used to look it up. Caller's responsibility to feed
// the raw key to the sensor and persist only the hash.
//
// Every issuing path (create, admin regeneration, self-renewal including the
// overlapping RotateKey path) comes through here, so every new key is an
// octs_ key: "octs_" + 32 random bytes in base62 + a base62 CRC32 checksum
// (pkg/sensorkey). The stored display prefix is the first
// sensorkey.DisplayPrefixLen characters. Legacy rda_ keys are never issued
// again; a sensor still on one moves to octs_ on its next renewal.
func (s *SensorService) generateSensorAPIKey() (key, hash, prefix string, err error) {
	key, err = sensorkey.New(sensorkey.PrefixSensorKey)
	if err != nil {
		return "", "", "", err
	}
	hash = s.hashSensorAPIKey(key)
	prefix = sensorkey.DisplayPrefix(key)

	return key, hash, prefix, nil
}

// hashSensorAPIKey hashes a sensor API key using HMAC-SHA256 keyed
// with the server-side pepper. Falls back to plain SHA-256 when no
// pepper is configured — required for the boot-time path where
// existing rows in the DB were written before peppering was deployed.
//
// SECURITY: the API key itself is 32 bytes from crypto/rand (256 bits
// of entropy), so plain SHA-256 is computationally infeasible to
// reverse. The peppered variant additionally defends against database-
// only leaks by ensuring an attacker with `key_hash` rows but no
// access to application config cannot pre-compute candidate hashes
// (rainbow tables / hashcat) offline.
func (s *SensorService) hashSensorAPIKey(key string) string {
	return crypto.HashTokenPeppered(key, s.pepper)
}

// =============================================================================
// Tenant Available Capabilities
// =============================================================================

// TenantAvailableCapabilitiesOutput represents the output for available capabilities.
type TenantAvailableCapabilitiesOutput struct {
	Capabilities []string `json:"capabilities"`  // Unique capability names available to tenant
	TotalSensors int      `json:"total_sensors"` // Total number of online sensors
}

// GetAvailableCapabilitiesForTenant returns all capabilities available to a tenant.
// This aggregates capabilities from the tenant's own sensors (if status=active and health=online).
func (s *SensorService) GetAvailableCapabilitiesForTenant(ctx context.Context, tenantID shared.ID) (*TenantAvailableCapabilitiesOutput, error) {
	s.logger.Debug("getting available capabilities for tenant", "tenant_id", tenantID)

	capabilities, err := s.repo.GetAvailableCapabilitiesForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get available capabilities: %w", err)
	}

	// Ensure we return empty array instead of nil
	if capabilities == nil {
		capabilities = []string{}
	}

	return &TenantAvailableCapabilitiesOutput{
		Capabilities: capabilities,
		TotalSensors: len(capabilities), // This is a simplification; could query actual sensor count if needed
	}, nil
}

// HasCapability checks if a tenant has access to a specific capability.
func (s *SensorService) HasCapability(ctx context.Context, tenantID shared.ID, capability string) (bool, error) {
	return s.repo.HasSensorForCapability(ctx, tenantID, capability)
}

// GetTenantSensorStats returns aggregate statistics for the tenant's sensors.
// Computed via SQL aggregation in a single round-trip — replaces the
// previous client-side .filter().length pattern that only saw the current
// page of results.
func (s *SensorService) GetTenantSensorStats(ctx context.Context, tenantID string) (*sensordom.TenantSensorStats, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	stats, err := s.repo.GetTenantSensorStats(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant sensor stats: %w", err)
	}
	return stats, nil
}

// maxFleetListing bounds ListAllSensors: far above any real fleet, low enough
// that a runaway tenant cannot make one stats request read without limit.
const maxFleetListing = 5000

// ListAllSensors returns the tenant's sensors (the rows GET /sensors lists),
// page by page, up to maxFleetListing. Used for fleet-wide breakdowns that are
// computed per sensor (the health state depends on the current time).
func (s *SensorService) ListAllSensors(ctx context.Context, tenantID string) ([]*sensordom.Sensor, error) {
	const perPage = 100
	var all []*sensordom.Sensor
	for page := 1; len(all) < maxFleetListing; page++ {
		res, err := s.ListSensors(ctx, ListSensorsInput{TenantID: tenantID, Page: page, PerPage: perPage})
		if err != nil {
			return nil, err
		}
		all = append(all, res.Data...)
		if len(res.Data) < perPage || int64(len(all)) >= res.Total {
			break
		}
	}
	return all, nil
}

// heartbeatBinding keeps a known binding only.
func heartbeatBinding(b string) string {
	switch b {
	case sensordom.BindingGRPC, sensordom.BindingHTTPS, sensordom.BindingV2:
		return b
	}
	return ""
}
