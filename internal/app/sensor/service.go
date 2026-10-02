// Package sensor implements the application service for the sensor bounded context — orchestrates pkg/domain/sensor entities and cross-cutting concerns (audit, notifications, RBAC).
package sensor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	auditapp "github.com/openctemio/api/internal/app/audit"

	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/audit"
	sensordom "github.com/openctemio/api/pkg/domain/sensor"
	tooldom "github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// sensorAuditSystemActor is the actor recorded on sensor lifecycle audit events
// (connect/disconnect) that originate from background reconciliation rather than
// a user request. LogEvent treats an empty ActorID with a non-empty email as a
// system action.
const sensorAuditSystemActor = "system"

// SensorService handles sensor-related business operations.
type SensorService struct {
	repo         sensordom.Repository
	auditService *auditapp.AuditService
	logger       *logger.Logger
	// pepper is the server-side secret mixed into the API-key hash via
	// HMAC-SHA256. Optional — when empty the hash falls back to plain
	// SHA-256 for backward compatibility with rows written before the
	// pepper was deployed. Set via SetPepper at boot from the platform
	// encryption key (or a dedicated derived secret). The pepper turns
	// a database-only leak into useless ciphertext: an attacker without
	// access to application config cannot brute-force the raw API key
	// from a leaked key_hash column.
	pepper string
	// keyTTL is how long a self-renewed API key stays valid before it must be
	// renewed again (RFC-014 Phase 1b). Zero (the default) disables expiry:
	// renewed keys never expire, preserving today's behavior. Set via
	// SetKeyTTL at boot. Only self-renewal honors it; created and
	// admin-regenerated keys never expire regardless.
	keyTTL time.Duration
	// apiKeyRepo is the optional multi-key store (RFC-014 Phase 3). When wired,
	// AuthenticateByAPIKey also accepts keys from sensor_api_keys, and self-renewal
	// under a key TTL issues a NEW key row (rotation overlap) instead of replacing
	// the inline hash — so a renewed key coexists with the one it supersedes. Nil
	// (the default) keeps the single-inline-key behavior.
	apiKeyRepo sensordom.APIKeyRepository
	// lbWeights are the load-balancing weights used to recompute a sensor's
	// load_score on every heartbeat. Defaults to the compiled-in set;
	// SetLoadBalancingWeights installs the operator's AGENT_LB_* values.
	lbWeights sensordom.LoadBalancingWeights
}

// NewSensorService creates a new SensorService.
func NewSensorService(repo sensordom.Repository, auditService *auditapp.AuditService, log *logger.Logger) *SensorService {
	return &SensorService{
		repo:         repo,
		auditService: auditService,
		logger:       log.With("service", "sensor"),
		lbWeights:    sensordom.DefaultLoadBalancingWeights(),
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

// SetKeyTTL configures how long a self-renewed API key stays valid. Zero (the
// default) disables expiry — renewed keys never expire. Should be called once
// at boot before the service handles traffic.
func (s *SensorService) SetKeyTTL(ttl time.Duration) {
	s.keyTTL = ttl
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
	Type              string   `json:"type" validate:"required,oneof=runner worker collector sensor"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Tools             []string `json:"tools" validate:"max=20,dive,max=50"`
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
	s.logger.Info("creating sensor", "name", input.Name, "type", input.Type)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sensorType := sensordom.SensorType(input.Type)
	executionMode := sensordom.ExecutionMode(input.ExecutionMode)
	if executionMode == "" {
		executionMode = sensorType.DefaultExecutionMode()
	}

	a, err := sensordom.NewSensor(tenantID, input.Name, sensorType, input.Description, input.Capabilities, canonicalToolNames(input.Tools), executionMode)
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
		_ = s.auditService.LogSensorCreated(ctx, *input.AuditContext, a.ID.String(), a.Name, string(a.Type))
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
	Type          string   `json:"type" validate:"omitempty,oneof=runner worker collector sensor"`
	Status        string   `json:"status" validate:"omitempty,oneof=active disabled revoked"`      // Admin-controlled
	Health        string   `json:"health" validate:"omitempty,oneof=unknown online offline error"` // Automatic
	ExecutionMode string   `json:"execution_mode" validate:"omitempty,oneof=standalone daemon"`
	Capabilities  []string `json:"capabilities"`
	Tools         []string `json:"tools"`
	Search        string   `json:"search" validate:"max=255"`
	HasCapacity   *bool    `json:"has_capacity"` // Filter by sensors with available capacity
	Page          int      `json:"page"`
	PerPage       int      `json:"per_page"`
}

// ListSensors lists sensors with filters.
func (s *SensorService) ListSensors(ctx context.Context, input ListSensorsInput) (pagination.Result[*sensordom.Sensor], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*sensordom.Sensor]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := sensordom.Filter{
		TenantID: &tenantID,
		// The tenant's own sensors. Shared platform sensors are not the
		// tenant's to manage; their capacity has its own view (GET
		// /platform/stats), and the sensor stats count the same rows.
		ExcludePlatform: true,
		Capabilities:    input.Capabilities,
		Tools:           input.Tools,
		Search:          input.Search,
		HasCapacity:     input.HasCapacity,
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
	Tools             []string `json:"tools" validate:"max=20,dive,max=50"`
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

	// Tools and capabilities are limits on what the sensor reports
	// (RFC-029 §4.3.1). A list that is present replaces the limit; [] removes
	// it (every tool / capability the sensor reports may be used). Absent
	// (nil) leaves it as it is.
	if input.Capabilities != nil && !slices.Equal(input.Capabilities, a.Capabilities) {
		changes.Set("capabilities", a.Capabilities, input.Capabilities)
		a.Capabilities = append([]string{}, input.Capabilities...)
	}

	if tools := canonicalToolNames(input.Tools); tools != nil && !slices.Equal(tools, a.Tools) {
		changes.Set("tools", a.Tools, tools)
		a.Tools = tools
	}

	// Revocation is permanent (ActivateSensor refuses it too). Without this a
	// PUT with {"status":"active"} brought a revoked sensor and its old key
	// back.
	if input.Status != "" && a.Status == sensordom.SensorStatusRevoked &&
		sensordom.SensorStatus(input.Status) != sensordom.SensorStatusRevoked {
		return nil, shared.NewDomainError("FORBIDDEN", "cannot change the status of a revoked sensor", shared.ErrForbidden)
	}

	if input.Status != "" {
		oldStatus := string(a.Status)
		a.SetStatus(sensordom.SensorStatus(input.Status), "")
		changes.Set("status", oldStatus, input.Status)
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
		_ = s.auditService.LogSensorUpdated(ctx, *input.AuditContext, a.ID.String(), sensorName, changes)
	}

	return a, nil
}

// SensorHeartbeatData represents the data received from sensor heartbeat.
type SensorHeartbeatData struct {
	Version  string
	Hostname string
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

	// UptimeSeconds is the process uptime the heartbeat reported; 0 when it
	// did not report one. Clamped before it is stored.
	UptimeSeconds int64

	// Report is the capability report the heartbeat carried, untrusted; nil
	// when it carried none. It is sanitized here against the tool catalog
	// before it is stored (sensordom.CapabilityReportInput.Sanitize).
	Report *sensordom.CapabilityReportInput
}

// canonicalToolNames writes tool limits the way sensors report tools:
// lowercase catalog names, a retired name as its replacement ("gitleaks" is
// "betterleaks"), so the narrowing (reported ∩ limit) compares like with
// like. nil stays nil (no change on update).
func canonicalToolNames(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(tooldom.CanonicalName(strings.TrimSpace(t)))
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
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

	updated, err := s.repo.UpdateHeartbeat(ctx, a.ID, sensordom.HeartbeatUpdate{
		TenantID:      a.TenantID,
		Version:       data.Version,
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
		UserAgent:     sensordom.SanitizeUserAgent(data.UserAgent),
		UptimeSeconds: sensordom.ClampUptime(data.UptimeSeconds),
		Report:        s.sanitizeReport(ctx, a, data.Report),
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

	// Record a connect event only on an offline/unknown/error -> online
	// transition. Tenant sensors only: platform sensors (TenantID == nil) are
	// shared infrastructure with no owning tenant to scope the audit log to.
	if s.auditService != nil && prevHealth != sensordom.SensorHealthOnline && a.TenantID != nil {
		ip := "an unknown address"
		switch {
		case clientIP != nil:
			ip = clientIP.String()
		case a.IPAddress != nil:
			ip = a.IPAddress.String()
		}
		_ = s.auditService.LogSensorConnected(ctx, auditapp.AuditContext{
			TenantID:   a.TenantID.String(),
			ActorEmail: sensorAuditSystemActor,
		}, a.ID.String(), a.Name, ip)
	}

	return nil
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

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogSensorDeleted(ctx, *auditCtx, sensorID, sensorName)
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
	updated, err := s.repo.UpdateAPIKey(ctx, a.ID, hash, prefix, nil, false)
	if err != nil {
		return "", err
	}
	if !updated {
		return "", shared.ErrNotFound
	}
	a.SetAPIKey(hash, prefix)

	if err := s.revokeAllKeyRows(ctx, a.ID, "regenerated"); err != nil {
		return "", fmt.Errorf("revoke renewed keys: %w", err)
	}

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogSensorKeyRegenerated(ctx, *auditCtx, sensorID, a.Name)
	}

	return apiKey, nil
}

// revokeAllKeyRows revokes every still-active sensor_api_keys row for the
// sensor. No-op when the multi-key store is not wired.
func (s *SensorService) revokeAllKeyRows(ctx context.Context, sensorID shared.ID, reason string) error {
	if s.apiKeyRepo == nil {
		return nil
	}
	keys, err := s.apiKeyRepo.GetBySensorID(ctx, sensorID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if !k.IsActive {
			continue
		}
		if err := s.apiKeyRepo.Revoke(ctx, k.ID, reason); err != nil {
			return err
		}
	}
	return nil
}

// RenewAPIKey lets an already-authenticated sensor rotate its own credential.
//
// Unlike RegenerateAPIKey (an admin action, tenant+id scoped), this is the
// self-service, kubelet-style renewal a sensor drives itself: it presents its
// current key, gets authenticated by AuthenticateByAPIKey upstream, and calls
// this to mint a fresh one. The building block for auto-rotating credentials.
//
// The passed sensor is the one resolved from the presented key. We re-read it by
// ID so a concurrent admin status change (disable/revoke) is not clobbered by a
// stale in-memory copy, and re-check CanAuthenticate to refuse renewal for an
// sensor that was disabled/revoked in the auth→renew window. Works for both
// tenant and platform (nil-tenant) sensors since the lookup/update key on ID.
//
// When a key TTL is configured (SetKeyTTL), the new key carries a fresh expiry
// and the sensor is expected to renew again before it lapses; otherwise the key
// never expires (today's behavior). Returns the new key and its expiry (nil =
// never expires) so the sensor can schedule its next renewal.
func (s *SensorService) RenewAPIKey(ctx context.Context, a *sensordom.Sensor) (string, *time.Time, error) {
	if a == nil {
		return "", nil, shared.NewDomainError("UNAUTHORIZED", "no authenticated sensor", shared.ErrUnauthorized)
	}

	fresh, err := s.repo.GetByID(ctx, a.ID)
	if err != nil {
		return "", nil, err
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

	var expiresAt *time.Time
	if s.keyTTL > 0 {
		t := time.Now().Add(s.keyTTL)
		expiresAt = &t
	}

	// Rotation overlap (RFC-014 Phase 3): with the multi-key store wired AND a
	// TTL configured, issue the new key as its own sensor_api_keys row so the key
	// it supersedes stays valid until that key's own expiry — zero-downtime
	// rotation. Without both, fall back to replacing the single inline hash.
	if s.apiKeyRepo != nil && expiresAt != nil {
		if err := s.issueOverlappingKey(ctx, fresh, hash, prefix, *expiresAt); err != nil {
			return "", nil, err
		}
		s.logger.Info("sensor renewed its API key (overlap)",
			"sensor_id", fresh.ID.String(), "is_platform", fresh.IsPlatformSensor, "expires_at", expiresAt)
		s.auditKeyRenewed(ctx, fresh, expiresAt, true)
		return apiKey, expiresAt, nil
	}

	// Targeted, status-guarded write of the key columns only: a full-row
	// Update would also write back the status read above and could revive an
	// sensor an admin revoked in the meantime.
	updated, err := s.repo.UpdateAPIKey(ctx, fresh.ID, hash, prefix, expiresAt, true)
	if err != nil {
		return "", nil, err
	}
	if !updated {
		return "", nil, shared.NewDomainError("FORBIDDEN", "sensor is not active", shared.ErrForbidden)
	}

	s.logger.Info("sensor renewed its API key",
		"sensor_id", fresh.ID.String(), "is_platform", fresh.IsPlatformSensor, "expires_at", expiresAt)
	s.auditKeyRenewed(ctx, fresh, expiresAt, false)
	return apiKey, expiresAt, nil
}

// auditKeyRenewed records a sensor self-renewal in the tenant audit log.
// Platform sensors (no tenant) have no tenant log to write to.
func (s *SensorService) auditKeyRenewed(ctx context.Context, a *sensordom.Sensor, expiresAt *time.Time, overlap bool) {
	if s.auditService == nil || a.TenantID == nil {
		return
	}
	_ = s.auditService.LogSensorKeyRenewed(ctx, auditapp.AuditContext{
		TenantID:   a.TenantID.String(),
		ActorEmail: sensorAuditSystemActor,
	}, a.ID.String(), a.Name, expiresAt, overlap)
}

// overlapGrace is how long the superseded static (inline) key stays valid after
// an overlapping renewal, covering in-flight requests before it is retired.
const overlapGrace = 15 * time.Minute

// issueOverlappingKey issues the renewed key as a new sensor_api_keys row so the
// key it supersedes keeps working during the overlap window (rotation overlap).
// It also retires the long-lived inline bootstrap key (a short grace, so the
// static credential doesn't linger valid forever after the first renewal) and
// prunes already-expired key rows to bound accumulation.
func (s *SensorService) issueOverlappingKey(ctx context.Context, fresh *sensordom.Sensor, hash, prefix string, expiresAt time.Time) error {
	key, err := sensordom.NewAPIKey(fresh.ID, "renewed", scopesForSensor(fresh.Type))
	if err != nil {
		return err
	}
	key.SetKeyHash(hash, prefix)
	key.SetExpiration(expiresAt)
	if err := s.apiKeyRepo.Create(ctx, key); err != nil {
		return fmt.Errorf("issue overlapping key: %w", err)
	}

	// Retire the static inline key (best-effort): schedule it to lapse a short
	// grace from now, so the original never-expiring bootstrap credential does
	// not remain valid after the sensor has switched to rotating keys.
	//
	// Guard on KeyExpiresAt == nil (NOT !IsKeyExpired): retirement must happen
	// exactly once, on the first overlap renewal while the key is still
	// never-expiring. Using !IsKeyExpired would re-run on every renewal that
	// lands before the grace lapses and keep pushing the grace forward — under a
	// short TTL that would keep the static bootstrap key alive forever.
	//
	// UpdateKeyExpiry writes only key_expires_at under a status='active' guard,
	// so it cannot clobber a concurrent admin revoke back to active (and a
	// revoked sensor's stale inline key is moot — auth rejects the sensor anyway).
	if fresh.KeyExpiresAt == nil {
		grace := time.Now().Add(overlapGrace)
		if grace.After(expiresAt) {
			grace = expiresAt
		}
		if err := s.repo.UpdateKeyExpiry(ctx, fresh.ID, &grace); err != nil {
			s.logger.Warn("failed to retire inline key after overlap renewal",
				"sensor_id", fresh.ID.String(), "error", err)
		}
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
	case sensordom.SensorTypeRunner:
		return sensordom.RunnerScopes()
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
	id, err := s.authenticate(ctx, apiKey, false)
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
}

// AuthenticateIdentity authenticates a sensor key like AuthenticateByAPIKey,
// with one difference: a disabled (not revoked) sensor with a valid,
// unexpired key is returned with Paused set instead of being refused. The
// caller decides what a paused sensor may reach — only the heartbeat, to be
// told to pause (RFC-023 §9.2a). A paused sensor's last-seen time is not
// touched.
func (s *SensorService) AuthenticateIdentity(ctx context.Context, apiKey string) (SensorIdentity, error) {
	return s.authenticate(ctx, apiKey, true)
}

func (s *SensorService) authenticate(ctx context.Context, apiKey string, allowPaused bool) (SensorIdentity, error) {
	// Backward-compat lookup: try the peppered hash first; on miss
	// fall back to the legacy plain SHA-256. Rows written before the
	// pepper was deployed match the legacy variant; the next key
	// rotation will move them to peppered. When no pepper is
	// configured both branches collapse to plain SHA-256 (same hash)
	// so the lookup remains a single DB hit.
	hash := s.hashSensorAPIKey(apiKey)
	a, err := s.repo.GetByAPIKeyHash(ctx, hash)
	if err != nil && s.pepper != "" {
		// Legacy fallback: a row written without pepper would have a
		// plain SHA-256 hash, not the peppered one we just computed.
		legacyHash := crypto.HashToken(apiKey)
		a, err = s.repo.GetByAPIKeyHash(ctx, legacyHash)
	}
	if err != nil {
		// Inline-hash miss: try the multi-key store (RFC-014 Phase 3). Only
		// reached for keys issued by self-renewal under rotation overlap; the
		// common inline-key path above is unchanged.
		if id, rowErr := s.authByAPIKeyRow(ctx, apiKey, hash, allowPaused); rowErr == nil {
			return id, nil
		}
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

	if !paused {
		// Update last seen and health (async). Bounded with a timeout so a slow DB
		// can't accumulate unbounded goroutines under heavy sensor traffic.
		sensorID := a.ID
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.repo.UpdateLastSeen(ctx, sensorID)
		}()
	}

	return SensorIdentity{Sensor: a, KeyExpiresAt: a.KeyExpiresAt, Paused: paused}, nil
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
func (s *SensorService) authByAPIKeyRow(ctx context.Context, apiKey, pepperedHash string, allowPaused bool) (SensorIdentity, error) {
	if s.apiKeyRepo == nil {
		return SensorIdentity{}, shared.ErrUnauthorized
	}

	key, err := s.apiKeyRepo.GetByHash(ctx, pepperedHash)
	if err != nil && s.pepper != "" {
		key, err = s.apiKeyRepo.GetByHash(ctx, crypto.HashToken(apiKey))
	}
	if err != nil || key == nil || !key.IsValid() {
		return SensorIdentity{}, shared.ErrUnauthorized
	}

	a, err := s.repo.GetByID(ctx, key.SensorID)
	if err != nil {
		return SensorIdentity{}, shared.ErrUnauthorized
	}
	paused, err := checkSensorStatus(a, allowPaused)
	if err != nil {
		return SensorIdentity{}, err
	}
	if paused {
		return SensorIdentity{Sensor: a, KeyExpiresAt: key.ExpiresAt, Paused: true}, nil
	}

	// Async per-key audit + sensor liveness.
	keyID, sensorID := key.ID, a.ID
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.apiKeyRepo.RecordUsage(bg, keyID, "")
		_ = s.repo.UpdateLastSeen(bg, sensorID)
	}()

	return SensorIdentity{Sensor: a, KeyExpiresAt: key.ExpiresAt}, nil
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

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogSensorActivated(ctx, *auditCtx, sensorID, a.Name)
	}

	s.logger.Info("sensor activated", "sensor_id", sensorID)
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

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogSensorDeactivated(ctx, *auditCtx, sensorID, a.Name, reason)
	}

	s.logger.Info("sensor disabled", "sensor_id", sensorID, "reason", reason)
	return a, nil
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
		_ = s.auditService.LogSensorRevoked(ctx, *auditCtx, sensorID, a.Name, reason)
	}

	s.logger.Info("sensor revoked", "sensor_id", sensorID, "reason", reason)
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

// ClaimJob claims a job slot on a sensor for load balancing.
func (s *SensorService) ClaimJob(ctx context.Context, sensorID shared.ID) error {
	return s.repo.ClaimJob(ctx, sensorID)
}

// ReleaseJob releases a job slot on a sensor.
func (s *SensorService) ReleaseJob(ctx context.Context, sensorID shared.ID) error {
	return s.repo.ReleaseJob(ctx, sensorID)
}

// IncrementStats increments sensor statistics.
func (s *SensorService) IncrementStats(ctx context.Context, sensorID shared.ID, findings, scans, errors int64) error {
	return s.repo.IncrementStats(ctx, sensorID, findings, scans, errors)
}

// generateSensorAPIKey generates a new API key for a sensor and the
// peppered hash used to look it up. Caller's responsibility to feed
// the raw key to the sensor and persist only the hash.
func (s *SensorService) generateSensorAPIKey() (key, hash, prefix string, err error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", "", err
	}

	key = "rda_" + hex.EncodeToString(keyBytes) // rda = openctem sensor
	hash = s.hashSensorAPIKey(key)
	prefix = key[:12] // "rda_" + first 8 hex chars

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

// =============================================================================
// Platform Sensor Statistics
// =============================================================================

// PlatformTierStats represents statistics for a single platform sensor tier.
type PlatformTierStats struct {
	TotalSensors   int
	OnlineSensors  int
	OfflineSensors int
	TotalCapacity  int
	CurrentLoad    int
	AvailableSlots int
}

// PlatformStatsOutput represents the output for platform stats.
type PlatformStatsOutput struct {
	Enabled         bool
	MaxTier         string
	AccessibleTiers []string
	MaxConcurrent   int
	MaxQueued       int
	CurrentActive   int
	CurrentQueued   int
	AvailableSlots  int
	TierStats       map[string]PlatformTierStats
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

// GetPlatformStats returns aggregate statistics for platform sensors accessible to the tenant.
func (s *SensorService) GetPlatformStats(ctx context.Context, tenantID shared.ID) (*PlatformStatsOutput, error) {
	s.logger.Debug("getting platform stats", "tenant_id", tenantID)

	stats, err := s.repo.GetPlatformSensorStats(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform sensor stats: %w", err)
	}

	// If no platform sensors exist, return disabled
	if stats.TotalSensors == 0 {
		return &PlatformStatsOutput{
			Enabled:         false,
			MaxTier:         "shared",
			AccessibleTiers: []string{"shared"},
			TierStats:       make(map[string]PlatformTierStats),
		}, nil
	}

	// Build tier stats
	tierStats := make(map[string]PlatformTierStats)
	for tier, ts := range stats.TierBreakdown {
		tierStats[tier] = PlatformTierStats{
			TotalSensors:   ts.TotalSensors,
			OnlineSensors:  ts.OnlineSensors,
			OfflineSensors: ts.TotalSensors - ts.OnlineSensors,
			TotalCapacity:  ts.TotalCapacity,
			CurrentLoad:    ts.CurrentLoad,
			AvailableSlots: ts.TotalCapacity - ts.CurrentLoad,
		}
	}

	// Determine accessible tiers (all tenants get shared; add dedicated/premium if sensors exist)
	accessibleTiers := []string{"shared"}
	maxTier := "shared"
	if _, ok := stats.TierBreakdown["dedicated"]; ok {
		accessibleTiers = append(accessibleTiers, "dedicated")
		maxTier = "dedicated"
	}
	if _, ok := stats.TierBreakdown["premium"]; ok {
		accessibleTiers = append(accessibleTiers, "premium")
		maxTier = "premium"
	}

	return &PlatformStatsOutput{
		Enabled:         true,
		MaxTier:         maxTier,
		AccessibleTiers: accessibleTiers,
		MaxConcurrent:   stats.TotalCapacity,
		MaxQueued:       stats.TotalCapacity * 3, // 3x capacity for queue
		CurrentActive:   stats.CurrentActiveJobs,
		CurrentQueued:   stats.CurrentQueuedJobs,
		AvailableSlots:  stats.TotalCapacity - stats.CurrentActiveJobs,
		TierStats:       tierStats,
	}, nil
}
