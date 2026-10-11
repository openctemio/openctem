package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/audit"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// sdkVersionUnknown is the by_sdk_version key and sdk_version filter value
// for sensors whose SDK version is unknown.
const sdkVersionUnknown = "unknown"

// SensorHandler handles HTTP requests for sensors.
type SensorHandler struct {
	service         *sensorapp.SensorService
	templateService *sensorapp.SensorConfigTemplateService
	// transportStatus reports the protocol v3 bindings (SetTransportStatus).
	transportStatus func() SensorTransportStatus
	publicAPIURL    string // Public URL sensors will connect to (defaults to API_URL env var)
	// sensorImage is the image the install snippets run, with its pinned
	// tag (SENSOR_IMAGE + SENSOR_LATEST_VERSION).
	sensorImage string
	// caCertFile is the platform CA the snippets install (SENSOR_CA_CERT_FILE);
	// empty when the platform certificate is publicly trusted.
	caCertFile string
	// healthPolicy holds the thresholds and release channel the computed
	// state, health reasons and version status use.
	healthPolicy sensor.HealthPolicy
	// contentPolicies supplies the tenant's scanner content policy for the
	// content view and health (RFC-031); nil uses the platform default.
	contentPolicies ContentPolicySource
	// zones lists the tenant's scan zones, to prefill the sensor-local
	// policy template with the sensor's ranges; nil leaves them out.
	zones ZoneLister
	// grants serves the per-sensor grant routes (RFC-052 §5); nil: 404.
	grants    *sensorgrant.Service
	now       func() time.Time
	validator *validator.Validator
	logger    *logger.Logger
}

// ZoneLister lists a tenant's scan zones with their assigned sensors.
// Satisfied by the scan zone repository.
type ZoneLister interface {
	List(ctx context.Context, tenantID shared.ID) ([]*scanzone.Zone, error)
}

// SetZoneLister makes the install snippets prefill the sensor-local policy
// with the ranges of the sensor's scan zones (RFC-040 §5.7).
func (h *SensorHandler) SetZoneLister(z ZoneLister) {
	h.zones = z
}

// NewSensorHandler creates a new SensorHandler.
func NewSensorHandler(service *sensorapp.SensorService, v *validator.Validator, log *logger.Logger) *SensorHandler {
	return &SensorHandler{
		service:      service,
		healthPolicy: sensor.DefaultHealthPolicy(),
		now:          time.Now,
		validator:    v,
		logger:       log.With("handler", "sensor"),
	}
}

// SetHealthPolicy sets the heartbeat windows and the sensor release channel
// (SENSOR_LATEST_VERSION / SENSOR_MIN_VERSION) used for the computed state,
// health reasons and version status. Unset values take the defaults.
func (h *SensorHandler) SetHealthPolicy(p sensor.HealthPolicy) {
	h.healthPolicy = p.Normalized()
}

// ContentPolicySource returns a tenant's effective scanner content policy.
type ContentPolicySource interface {
	EffectivePolicy(ctx context.Context, tenantID shared.ID) sensor.ContentPolicy
}

// SetContentPolicySource wires the tenant content policy (RFC-031).
func (h *SensorHandler) SetContentPolicySource(src ContentPolicySource) {
	h.contentPolicies = src
}

// policyFor is the health policy for one tenant: the handler's thresholds
// and release channel, plus the tenant's content policy.
func (h *SensorHandler) policyFor(ctx context.Context, tenantID string) sensor.HealthPolicy {
	p := h.healthPolicy
	if h.contentPolicies == nil {
		return p
	}
	if tid, err := shared.IDFromString(tenantID); err == nil {
		cp := h.contentPolicies.EffectivePolicy(ctx, tid)
		p.Content = &cp
	}
	return p
}

// SetTemplateService injects the sensor config template service.
// Optional dependency — if nil, the config template endpoint returns 503.
func (h *SensorHandler) SetTemplateService(svc *sensorapp.SensorConfigTemplateService) {
	h.templateService = svc
}

// SetPublicAPIURL sets the public URL that sensor configs will reference.
func (h *SensorHandler) SetPublicAPIURL(url string) {
	h.publicAPIURL = url
}

// SetSensorImage sets the image reference (with tag) the install snippets run.
func (h *SensorHandler) SetSensorImage(image string) {
	h.sensorImage = image
}

// SetCACertificateFile sets the platform CA file the install snippets embed
// (SENSOR_CA_CERT_FILE). It is read on each request, so a CA the gateway
// exports after the API started is picked up.
func (h *SensorHandler) SetCACertificateFile(path string) {
	h.caCertFile = path
}

// CreateSensorRequest represents the request body for creating a sensor.
type CreateSensorRequest struct {
	Name              string   `json:"name" validate:"required,min=1,max=255"`
	Type              string   `json:"type" validate:"required,oneof=worker collector sensor"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	ExecutionMode     string   `json:"execution_mode" validate:"omitempty,oneof=standalone daemon"`
	MaxConcurrentJobs int      `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
}

// SensorResponse represents the response for a sensor.
type SensorResponse struct {
	ID            string   `json:"id"`
	TenantID      string   `json:"tenant_id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Description   string   `json:"description,omitempty"`
	Capabilities  []string `json:"capabilities"`
	ExecutionMode string   `json:"execution_mode"`
	Status        string   `json:"status"` // Admin-controlled: active, disabled, revoked
	// Health is automatic: stored by heartbeats and the heartbeat ladder.
	Health        string         `json:"health" enums:"unknown,online,late,stale,offline,error"`
	StatusMessage string         `json:"status_message,omitempty"`
	APIKeyPrefix  string         `json:"api_key_prefix,omitempty"`
	Labels        map[string]any `json:"labels,omitempty"`
	Version       string         `json:"version,omitempty"`
	Hostname      string         `json:"hostname,omitempty"`
	IPAddress     string         `json:"ip_address,omitempty"`
	// System metrics
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	Region        string  `json:"region,omitempty"`
	// Load balancing. current_jobs is the number of commands the sensor
	// holds now (acknowledged or running), counted by the platform;
	// available_slots is what dispatch may still hand it: its effective
	// capacity minus current_jobs, and no more than the free slots of a
	// fresh load report (RFC-030 §5.8).
	MaxConcurrentJobs int     `json:"max_concurrent_jobs"`
	CurrentJobs       int     `json:"current_jobs"`
	AvailableSlots    int     `json:"available_slots"`
	LoadFactor        float64 `json:"load_factor"` // 0.0 to 1.0
	// Load is the load the sensor last reported on its heartbeat
	// (resources, capacity, local queue); null when it never reported one.
	// fresh is false once it is older than 3 minutes (dispatch then ignores
	// it).
	Load *SensorLoadResponse `json:"load"`
	// Control is the control-channel report of the sensor's last heartbeat
	// that carried one (sdk-go, RFC-035 §5.5): how well its heartbeat loop
	// keeps time. null when it never reported one.
	Control *SensorControlResponse `json:"control"`
	// HeartbeatIntervalSeconds is the interval the sensor follows, stored at
	// its last heartbeat (its reported interval or the advised one); null
	// before its first heartbeat since the deadline was introduced (60 s
	// applies). HeartbeatDueAt is when its next heartbeat is due.
	HeartbeatIntervalSeconds *int    `json:"heartbeat_interval_seconds"`
	HeartbeatDueAt           *string `json:"heartbeat_due_at"`
	// HeartbeatState is where the sensor stands on the heartbeat ladder now
	// (RFC-035 §5.6): online until its deadline plus grace, then late (still
	// takes work), stale (takes no new work), offline. "" when it never
	// connected.
	HeartbeatState string `json:"heartbeat_state" enums:",online,late,stale,offline"`
	// Statistics
	LastSeenAt    *string `json:"last_seen_at,omitempty"`
	TotalFindings int64   `json:"total_findings"`
	TotalScans    int64   `json:"total_scans"`
	ErrorCount    int64   `json:"error_count"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	// Outbox is the last outbox state the sensor reported on its heartbeat;
	// null when it never reported one (an SDK without a durable outbox).
	Outbox *SensorOutboxResponse `json:"outbox"`
	// OutboxWarning is true when the last snapshot shows lost or stuck
	// results: dead_letter_count > 0, evicted_count > 0, or
	// oldest_age_seconds > 3600. False when there is no snapshot.
	OutboxWarning bool `json:"outbox_warning"`
	// Protocol is what the platform last saw of the sensor's protocol
	// (RFC-029 §5.3); null before the first heartbeat that recorded it.
	// deprecated is true for protocol v1: the sensor needs an upgrade.
	Protocol *SensorProtocolResponse `json:"protocol"`

	// State is the computed operational state: online, degraded, late,
	// stale, offline, idle (a CI sensor between runs), never_connected,
	// disabled or revoked. Each sensor is judged against its own heartbeat
	// deadline (heartbeat_due_at): online until the deadline plus grace,
	// then late (still takes work), stale (takes no new work), offline once
	// the health checker convicts it; degraded is online with at least one
	// health reason.
	State string `json:"state" enums:"online,degraded,late,stale,offline,idle,never_connected,disabled,revoked"`
	// HealthReasons lists the problems found (never null): an outbox backlog
	// or lost results, an expired or expiring key, a version below the
	// minimum, no scan tools, an error the sensor reported.
	HealthReasons []SensorHealthReasonResponse `json:"health_reasons"`
	// VersionStatus compares the version with the release channel.
	VersionStatus string `json:"version_status" enums:"latest,update_available,unsupported,unknown"`
	// KeyExpiresAt is when the current API key stops working; null = never.
	KeyExpiresAt *string `json:"key_expires_at"`
	// LegacyKey is true while the sensor's current key is a legacy rda_ key.
	// It moves to an octs_ key on its next renewal; rda_ keys are retired 90
	// days after enrollment and key-bound identity (RFC-032) ship.
	LegacyKey bool `json:"legacy_key"`
	// KeyLastUsedAt and KeyLastUsedIP are the last authenticated request with
	// any of the sensor's keys and the client address it came from (behind a
	// trusted proxy, the forwarded address); null until recorded.
	KeyLastUsedAt *string `json:"key_last_used_at"`
	KeyLastUsedIP *string `json:"key_last_used_ip"`
	// InstanceID is the sensor process of the last heartbeat that changed
	// it: the SDK's per-process id, or "host:<hash>" for SDKs that send none.
	InstanceID string `json:"instance_id"`
	// IdentityClonedAt is when two live processes were seen using this
	// sensor's key (health reason identity_cloned); null = not flagged.
	IdentityClonedAt *string `json:"identity_cloned_at"`
	// LastOfflineAt is when the sensor was last marked offline.
	LastOfflineAt *string `json:"last_offline_at"`
	// LastErrorAt is when the sensor last reported an error.
	LastErrorAt *string `json:"last_error_at"`
	// StartedAt is when the sensor process started (from the uptime its
	// heartbeat reports); null when it never reported one.
	StartedAt *string `json:"started_at"`
	// UptimeSeconds is the process uptime at the last heartbeat; null unless
	// the sensor is heartbeating and reports its uptime.
	UptimeSeconds *int64 `json:"uptime_seconds"`

	// capabilities and max_concurrent_jobs above are the administrator's
	// settings (limits). Reported is what the sensor last reported it has
	// (RFC-029 §4.3.1), null when it never reported; Effective is what
	// dispatch uses: the report narrowed by those settings (the settings
	// alone without a report). The effective tools are the reported
	// installed tools (none before a report); the sensor grant narrows them.
	Reported  *SensorReportedResponse `json:"reported"`
	Effective SensorEffectiveResponse `json:"effective"`
	// CapabilityMismatch lists settings the sensor's report contradicts
	// (a capability set here that the sensor does not report); omitted when none.
	CapabilityMismatch *sensor.CapabilityMismatch `json:"capability_mismatch,omitempty"`

	// Content is the scanner content the sensor reports (trivy DB, nuclei
	// templates, semgrep rules; RFC-031), one entry per tool and content,
	// judged against the tenant's content policy. Never null.
	Content []SensorContentResponse `json:"content"`
	// ContentRefreshSupported: the sensor manages content, so it accepts
	// POST /sensors/{id}/content/refresh.
	ContentRefreshSupported bool `json:"content_refresh_supported"`

	// Build information the sensor reported on its heartbeat, or that was
	// read from its User-Agent (older sensors). "" / null when unknown.
	SDKName    string `json:"sdk_name"`
	SDKVersion string `json:"sdk_version"`
	// SDKStatus compares sdk_version with SENSOR_SDK_MIN_VERSION and
	// SENSOR_SDK_LATEST_VERSION.
	SDKStatus       string  `json:"sdk_status" enums:"current,outdated,unsupported,unknown"`
	SensorProduct   string  `json:"sensor_product"`
	SensorCommit    string  `json:"sensor_commit"`
	SensorBuildTime *string `json:"sensor_build_time"`

	// The current manifest (RFC-033): its digest, when it became current
	// and where it came from (sensor: registered; heartbeat: derived by the
	// platform). "" / null before the first one. The document itself is
	// GET /sensors/{id}/manifest.
	ManifestDigest string  `json:"manifest_digest"`
	ManifestAt     *string `json:"manifest_at"`
	ManifestSource string  `json:"manifest_source" enums:",sensor,heartbeat"`

	// LocalPolicy is the sensor-local policy the sensor reports (RFC-040
	// §5.7): enforced on the sensor, shown here. Always present; state
	// "unknown" when the sensor never reported one.
	LocalPolicy SensorLocalPolicyResponse `json:"local_policy"`

	// Posture is the sensor's security posture: its local policy, the
	// platform TLS pin and the tool sandbox's network confinement as the
	// sensor reports them, and the reasons it is unhardened. Always present.
	// Self-reported: shown and alerted on, never trusted to relax a check.
	Posture SensorPostureResponse `json:"posture"`

	// ConfigHealth is the platform's rollup of the sensor's latest config
	// report (research/26): ok, attention, impaired or blocked; null when
	// it sent none. While the report is stale it is still the last rollup;
	// health_reasons then carry config_report_stale. The checklist is
	// GET /sensors/{id}/config-report.
	ConfigHealth *string `json:"config_health" enums:"ok,attention,impaired,blocked"`
}

// SensorPostureResponse is a sensor's security posture as the console shows
// it (sensor.SensorPosture).
type SensorPostureResponse struct {
	// LocalPolicy: enforced; absent_required (the sensor refuses jobs with
	// network targets until a policy is installed); absent_legacy (no
	// policy, jobs admitted); unknown (never reported).
	LocalPolicy string `json:"local_policy" enums:"enforced,absent_required,absent_legacy,unknown"`
	// PlatformPin is how the sensor's HTTPS client trusts the platform: the
	// CA pinned by fingerprint, a private CA file, the system trust store
	// only (none); unknown when the sensor reported no posture.
	PlatformPin string `json:"platform_pin" enums:"fingerprint,ca_file,none,unknown"`
	// NetworkEnforced is whether tool runs are network-confined; null when
	// the sensor did not report its sandbox.
	NetworkEnforced *bool `json:"network_enforced"`
	// Unhardened lists why the sensor is flagged (never null): policy_none,
	// pin_none, network_unenforced, bearer_key.
	Unhardened []string `json:"unhardened" enums:"policy_none,pin_none,network_unenforced,bearer_key"`
}

func postureResponse(a *sensor.Sensor) SensorPostureResponse {
	p := a.PostureOf()
	return SensorPostureResponse{LocalPolicy: p.LocalPolicy, PlatformPin: p.PlatformPin, NetworkEnforced: p.NetworkEnforced, Unhardened: p.Unhardened}
}

// SensorLocalPolicyResponse is a sensor's local policy as the console shows
// it. State is the display state: paused while the kill switch is engaged,
// unknown for a sensor that never reported (an SDK before RFC-040).
type SensorLocalPolicyResponse struct {
	State string `json:"state" enums:"enforced,absent,paused,unknown"`
	// Required: the sensor requires a local policy; absent and required, it
	// refuses every job with a network target.
	Required   bool                       `json:"required"`
	Source     string                     `json:"source,omitempty" enums:",file,env"`
	Digest     string                     `json:"digest,omitempty"`
	KillSwitch bool                       `json:"kill_switch"`
	Summary    *sensor.LocalPolicySummary `json:"summary,omitempty"`
	Warnings   []string                   `json:"warnings,omitempty"`
	ReportedAt *string                    `json:"reported_at,omitempty"`
}

// localPolicyResponse is the console view of a sensor's local policy report.
func localPolicyResponse(a *sensor.Sensor) SensorLocalPolicyResponse {
	r := a.LocalPolicy
	out := SensorLocalPolicyResponse{State: r.DisplayState(), ReportedAt: rfc3339Ptr(a.LocalPolicyReportedAt)}
	if r == nil {
		return out
	}
	out.Source, out.Digest, out.KillSwitch, out.Summary, out.Warnings = r.Source, r.Digest, r.KillSwitch, r.Summary, r.Warnings
	out.Required = r.Required
	return out
}

// SensorContentResponse is one piece of scanner content on a sensor. The
// reported fields come from the sensor (sanitized); age_seconds, stale,
// max_age_hours, pinned_version and pin_mismatch are computed against the
// tenant's content policy.
type SensorContentResponse struct {
	Tool      string  `json:"tool"`
	Name      string  `json:"name" enums:"trivy-db,trivy-java-db,nuclei-templates,semgrep-rules"`
	Version   string  `json:"version"`
	UpdatedAt *string `json:"updated_at"`
	FetchedAt *string `json:"fetched_at"`
	// CheckedAt is when the sensor last confirmed this is still the newest
	// (or pinned) version; stale needs both an age and a confirmation
	// older than max_age_hours.
	CheckedAt *string `json:"checked_at"`
	Source    string  `json:"source"`
	Digest    string  `json:"digest"`
	// Managed: the sensor refreshes, verifies and pins it; false when the
	// tool fetches its content itself (never stale-flagged).
	Managed bool `json:"managed"`
	// Error is the last refresh failure ("" when the last refresh worked).
	Error         string `json:"error"`
	AgeSeconds    *int64 `json:"age_seconds"`
	MaxAgeHours   int    `json:"max_age_hours"`
	Stale         bool   `json:"stale"`
	PinnedVersion string `json:"pinned_version"`
	PinMismatch   bool   `json:"pin_mismatch"`
}

// SensorLoadResponse is a sensor's last load report. A part is null when the
// sensor never reported it.
type SensorLoadResponse struct {
	Resources  *sensor.ReportedResources `json:"resources"`
	Capacity   *sensor.ReportedCapacity  `json:"capacity"`
	Queue      *sensor.ReportedQueue     `json:"queue"`
	ReportedAt *string                   `json:"reported_at"`
	Fresh      bool                      `json:"fresh"`
}

// SensorControlResponse is a sensor's last control-channel report. Values
// are reported by the sensor (clamped on ingest); reported_at is the server
// time it was stored.
type SensorControlResponse struct {
	// IntervalSeconds is the heartbeat interval the sensor follows.
	IntervalSeconds float64 `json:"interval_s"`
	// GapSeconds is the time between its last two delivered heartbeats.
	GapSeconds float64 `json:"gap_s"`
	// LagMillis is how late its heartbeat timer fired (CPU starvation).
	LagMillis int64 `json:"lag_ms"`
	// BuildMillis is how long building the heartbeat report took.
	BuildMillis int64 `json:"build_ms"`
	// RTTMillis is the round trip of its previous heartbeat.
	RTTMillis int64 `json:"rtt_ms"`
	// Failures is the number of heartbeats lost before the last one.
	Failures   int64   `json:"failures"`
	ReportedAt *string `json:"reported_at"`
}

// SensorReportedResponse is a sensor's last capability report. A list is
// null when that part was never reported, [] when the sensor reported none.
type SensorReportedResponse struct {
	Tools             []sensor.ReportedTool `json:"tools"`
	Capabilities      []string              `json:"capabilities"`
	MaxConcurrentJobs *int                  `json:"max_concurrent_jobs"`
	OS                string                `json:"os,omitempty"`
	Arch              string                `json:"arch,omitempty"`
	ReportedAt        *string               `json:"reported_at"`
}

// SensorEffectiveResponse is what dispatch uses for a sensor.
type SensorEffectiveResponse struct {
	Tools             []string `json:"tools"`
	Capabilities      []string `json:"capabilities"`
	MaxConcurrentJobs int      `json:"max_concurrent_jobs"`
}

// SensorProtocolResponse is the protocol telemetry of a sensor's last
// heartbeat. user_agent is reported by the sensor (sanitized) and is display
// data only.
type SensorProtocolResponse struct {
	Version    int    `json:"version"`
	UserAgent  string `json:"user_agent"`
	SeenAt     string `json:"seen_at"`
	Deprecated bool   `json:"deprecated"`
	// Binding is how the last heartbeat arrived (RFC-059): grpc (mTLS),
	// https (protocol v3 over HTTPS) or v2; absent before it was recorded.
	Binding string `json:"binding,omitempty" enums:"grpc,https,v2"`
	// FallbackReason is why the sensor is not on gRPC, as it reported it.
	FallbackReason string `json:"fallback_reason,omitempty"`
}

// SensorHealthReasonResponse is one problem found on a sensor. code is
// stable (clients map it to their own wording and fix actions); message is a
// plain-English fallback.
type SensorHealthReasonResponse struct {
	Code     string `json:"code" enums:"outbox_backlog,outbox_dead_letters,outbox_evicted,key_expired,key_expiring,identity_cloned,version_unsupported,sdk_unsupported,no_tools,error_reported,content_stale,content_refresh_failed,heartbeat_late,control_slow"`
	Severity string `json:"severity" enums:"warning,critical"`
	Message  string `json:"message"`
}

// SensorOutboxResponse is a sensor's last reported outbox state. Values are
// reported by the sensor (clamped on ingest); reported_at is the server time
// the snapshot was stored, so an old reported_at means a stale snapshot.
type SensorOutboxResponse struct {
	PendingCount     int64  `json:"pending_count"`
	PendingBytes     int64  `json:"pending_bytes"`
	OldestAgeSeconds int64  `json:"oldest_age_seconds"`
	DeadLetterCount  int64  `json:"dead_letter_count"`
	EvictedCount     int64  `json:"evicted_count"`
	ReportedAt       string `json:"reported_at"`
}

// CreateSensorResponse includes the API key (only shown once).
type CreateSensorResponse struct {
	Sensor *SensorResponse `json:"sensor"`
	APIKey string          `json:"api_key"`
}

// Create handles POST /api/v1/sensors
// @Summary      Create sensor
// @Description  Create a new sensor and receive its API key
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        body  body      CreateSensorRequest  true  "Sensor data"
// @Success      201   {object}  CreateSensorResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors [post]
func (h *SensorHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateSensorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	input := sensorapp.CreateSensorInput{
		TenantID:          tenantID,
		Name:              req.Name,
		Type:              req.Type,
		Description:       req.Description,
		Capabilities:      req.Capabilities,
		ExecutionMode:     req.ExecutionMode,
		MaxConcurrentJobs: req.MaxConcurrentJobs,
		AuditContext:      h.buildAuditContext(r),
	}

	output, err := h.service.CreateSensor(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := &CreateSensorResponse{
		Sensor: h.toSensorResponse(r.Context(), output.Sensor),
		APIKey: output.APIKey,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Get handles GET /api/v1/sensors/{id}
// @Summary      Get sensor
// @Description  Get a single sensor by ID
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id} [get]
func (h *SensorHandler) Get(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	a, err := h.service.GetSensor(r.Context(), tenantID, sensorID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSensorResponse(r.Context(), a))
}

// List handles GET /api/v1/sensors
// @Summary      List sensors
// @Description  Get a paginated list of sensors for the current tenant
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        type            query     string  false  "Filter by type (runner, worker, collector, sensor)"
// @Param        status          query     string  false  "Filter by admin-controlled status (active, disabled, revoked)"
// @Param        health          query     string  false  "Filter by automatic health (unknown, online, offline, error)"
// @Param        execution_mode  query     string  false  "Filter by execution mode (standalone, daemon)"
// @Param        capabilities    query     string  false  "Filter by capabilities (comma-separated)"
// @Param        tools           query     string  false  "Filter by tools (comma-separated)"
// @Param        has_capacity    query     bool    false  "Filter by sensors with available capacity"
// @Param        search          query     string  false  "Search by name or description"
// @Param        page            query     int     false  "Page number" default(1)
// @Param        per_page        query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[SensorResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors [get]
func (h *SensorHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	input := sensorapp.ListSensorsInput{
		TenantID:      tenantID,
		Type:          r.URL.Query().Get("type"),
		Status:        r.URL.Query().Get("status"),
		Health:        r.URL.Query().Get("health"),
		ExecutionMode: r.URL.Query().Get("execution_mode"),
		Search:        r.URL.Query().Get("search"),
		Page:          paging.Page,
		PerPage:       paging.PerPage,
	}

	if caps := r.URL.Query().Get("capabilities"); caps != "" {
		input.Capabilities = parseQueryArray(caps)
	}

	if tools := r.URL.Query().Get("tools"); tools != "" {
		input.Tools = parseQueryArray(tools)
	}

	if v, ok := r.URL.Query()["sdk_version"]; ok && len(v) > 0 {
		sdk := strings.TrimSpace(v[0])
		if strings.EqualFold(sdk, sdkVersionUnknown) {
			sdk = ""
		} else if sdk = sensor.NormalizeVersion(sdk); !sensor.IsReleaseVersion(sdk) {
			apierror.BadRequest("sdk_version must be a version (e.g. v0.9.0) or unknown").WriteJSON(w)
			return
		}
		input.SDKVersion = &sdk
	}

	if hasCapacity := r.URL.Query().Get("has_capacity"); hasCapacity != "" {
		val := hasCapacity == queryParamTrue
		input.HasCapacity = &val
	}

	result, err := h.service.ListSensors(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*SensorResponse, len(result.Data))
	policy, now := h.policyFor(r.Context(), tenantID), h.now()
	for i, a := range result.Data {
		items[i] = sensorResponseAt(a, policy, now)
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// SensorStatsResponse is the fleet summary for the tenant's sensors. It
// counts the same sensors GET /sensors lists.
type SensorStatsResponse struct {
	Total           int            `json:"total"`
	ByStatus        map[string]int `json:"by_status"`
	ByHealth        map[string]int `json:"by_health"`
	ByType          map[string]int `json:"by_type"`
	ByExecutionMode map[string]int `json:"by_execution_mode"`
	ActiveJobs      int            `json:"active_jobs"`
	OnlineActive    int            `json:"online_active"`

	// ByState counts sensors per computed state (every state is present,
	// zeros included); the same state GET /sensors returns per sensor.
	ByState map[string]int `json:"by_state"`
	// ByVersionStatus counts sensors per version status.
	ByVersionStatus map[string]int `json:"by_version_status"`
	// NeedsAttention counts enabled sensors with at least one health reason.
	NeedsAttention int `json:"needs_attention"`
	// CanTakeJobs counts sensors that can be dispatched work now: enabled,
	// long-running (not one-shot CI) and online, degraded or late.
	CanTakeJobs int `json:"can_take_jobs"`
	// JobsRunning is the sum of current jobs on those sensors, JobSlots the
	// sum of their max concurrent jobs.
	JobsRunning int `json:"jobs_running"`
	JobSlots    int `json:"job_slots"`
	// LatestVersion and MinVersion are the release channel
	// (SENSOR_LATEST_VERSION, SENSOR_MIN_VERSION); "" when not configured.
	LatestVersion string `json:"latest_version"`
	MinVersion    string `json:"min_version"`
	// Each sensor is judged against its own heartbeat deadline
	// (heartbeat_due_at; RFC-035 §5.6). OnlineWindowSeconds is how long a
	// sensor on the idle interval stays online after a heartbeat (interval
	// plus grace); OfflineAfterSeconds (WORKER_HEARTBEAT_TIMEOUT) is the
	// backstop after which an unconvicted sensor shows offline anyway.
	OnlineWindowSeconds int `json:"online_window_seconds"`
	OfflineAfterSeconds int `json:"offline_after_seconds"`

	// SDKMinVersion and SDKLatestVersion are the SDK policy
	// (SENSOR_SDK_MIN_VERSION, SENSOR_SDK_LATEST_VERSION); "" when not set.
	SDKMinVersion    string `json:"sdk_min_version"`
	SDKLatestVersion string `json:"sdk_latest_version"`
	// BySDKVersion counts sensors per reported SDK version ("unknown" when
	// none); its keys are the values GET /sensors?sdk_version= accepts.
	BySDKVersion map[string]int `json:"by_sdk_version"`
	// BySDKStatus counts sensors per SDK status (every status present).
	BySDKStatus map[string]int `json:"by_sdk_status"`
}

// GetStats handles GET /api/v1/sensors/stats
// @Summary      Get tenant sensor statistics
// @Description  Returns aggregated stats for the tenant's sensors (status, health, type, mode breakdowns)
// @Tags         Sensors
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  SensorStatsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /sensors/stats [get]
func (h *SensorHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	stats, err := h.service.GetTenantSensorStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	sensors, err := h.service.ListAllSensors(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := SensorStatsResponse{
		Total:           stats.Total,
		ByStatus:        stats.ByStatus,
		ByHealth:        stats.ByHealth,
		ByType:          stats.ByType,
		ByExecutionMode: stats.ByMode,
		ActiveJobs:      stats.ActiveJobs,
		OnlineActive:    stats.OnlineActive,
	}
	h.addFleetSummary(&resp, sensors, h.policyFor(r.Context(), tenantID))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// addFleetSummary fills the per-sensor breakdowns of the stats response.
func (h *SensorHandler) addFleetSummary(resp *SensorStatsResponse, sensors []*sensor.Sensor, p sensor.HealthPolicy) {
	now := h.now()
	resp.ByState = make(map[string]int, len(sensor.AllStates()))
	for _, st := range sensor.AllStates() {
		resp.ByState[string(st)] = 0
	}
	resp.ByVersionStatus = map[string]int{
		string(sensor.VersionLatest): 0, string(sensor.VersionUpdateAvailable): 0,
		string(sensor.VersionUnsupported): 0, string(sensor.VersionUnknown): 0,
	}
	resp.BySDKVersion = map[string]int{}
	resp.BySDKStatus = make(map[string]int, len(sensor.AllSDKStatuses()))
	for _, st := range sensor.AllSDKStatuses() {
		resp.BySDKStatus[string(st)] = 0
	}
	for _, a := range sensors {
		hl := a.AssessHealth(now, p)
		resp.ByState[string(hl.State)]++
		resp.ByVersionStatus[string(hl.VersionStatus)]++
		resp.BySDKStatus[string(hl.SDKStatus)]++
		sdkKey := a.Build.SDKVersion
		if sdkKey == "" {
			sdkKey = sdkVersionUnknown
		}
		resp.BySDKVersion[sdkKey]++
		enabled := hl.State != sensor.StateDisabled && hl.State != sensor.StateRevoked
		if enabled && len(hl.Reasons) > 0 {
			resp.NeedsAttention++
		}
		if hl.State.TakesJobs() && !a.IsOneShot() {
			resp.CanTakeJobs++
			resp.JobsRunning += a.CurrentJobs
			resp.JobSlots += a.MaxConcurrentJobs
		}
	}
	resp.LatestVersion = p.LatestVersion
	resp.MinVersion = p.MinVersion
	resp.SDKMinVersion = p.SDKMinVersion
	resp.SDKLatestVersion = p.SDKLatestVersion
	resp.OnlineWindowSeconds = int(p.OnlineWindow / time.Second)
	resp.OfflineAfterSeconds = int(p.OfflineAfter / time.Second)
}

// UpdateSensorRequest represents the request body for updating a sensor.
type UpdateSensorRequest struct {
	Name              string   `json:"name" validate:"omitempty,min=1,max=255"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Status            string   `json:"status" validate:"omitempty,oneof=active disabled revoked"` // Admin-controlled
	MaxConcurrentJobs *int     `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
}

// Update handles PUT /api/v1/sensors/{id}
// @Summary      Update sensor
// @Description  Update an existing sensor
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Sensor ID"
// @Param        body  body      UpdateSensorRequest  true  "Update data"
// @Success      200   {object}  SensorResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id} [put]
func (h *SensorHandler) Update(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateSensorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := sensorapp.UpdateSensorInput{
		TenantID:          tenantID,
		SensorID:          sensorID,
		Name:              req.Name,
		Description:       req.Description,
		Capabilities:      req.Capabilities,
		Status:            req.Status,
		MaxConcurrentJobs: req.MaxConcurrentJobs,
		AuditContext:      h.buildAuditContext(r),
	}

	a, err := h.service.UpdateSensor(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSensorResponse(r.Context(), a))
}

// Delete handles DELETE /api/v1/sensors/{id}
// @Summary      Delete sensor
// @Description  Delete a sensor and revoke its API key
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id} [delete]
func (h *SensorHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	if err := h.service.DeleteSensor(r.Context(), tenantID, sensorID, auditCtx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SensorRegenerateAPIKeyResponse represents the response for regenerating an API key.
type SensorRegenerateAPIKeyResponse struct {
	APIKey string `json:"api_key"`
}

// RegenerateAPIKey handles POST /api/v1/sensors/{id}/regenerate-key
// @Summary      Regenerate API key
// @Description  Regenerate the API key for a sensor. The old key will be invalidated.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorRegenerateAPIKeyResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/regenerate-key [post]
func (h *SensorHandler) RegenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	apiKey, err := h.service.RegenerateAPIKey(r.Context(), tenantID, sensorID, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&SensorRegenerateAPIKeyResponse{APIKey: apiKey})
}

// Activate handles POST /api/v1/sensors/{id}/activate
// @Summary      Activate sensor
// @Description  Activate a sensor (admin action). Allows the sensor to authenticate.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/activate [post]
func (h *SensorHandler) Activate(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	a, err := h.service.ActivateSensor(r.Context(), tenantID, sensorID, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSensorResponse(r.Context(), a))
}

// SensorDisableRequest represents the request body for disabling a sensor.
type SensorDisableRequest struct {
	Reason string `json:"reason" validate:"max=500"`
}

// Disable handles POST /api/v1/sensors/{id}/disable
// @Summary      Disable sensor
// @Description  Disable a sensor (admin action). Prevents the sensor from authenticating.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Sensor ID"
// @Param        body  body      SensorDisableRequest false "Disable reason"
// @Success      200   {object}  SensorResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/deactivate [post]
func (h *SensorHandler) Disable(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	var req SensorDisableRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	a, err := h.service.DisableSensor(r.Context(), tenantID, sensorID, req.Reason, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSensorResponse(r.Context(), a))
}

// SensorRevokeRequest represents the request body for revoking a sensor.
type SensorRevokeRequest struct {
	Reason string `json:"reason" validate:"max=500"`
}

// Revoke handles POST /api/v1/sensors/{id}/revoke
// @Summary      Revoke sensor
// @Description  Permanently revoke a sensor's access (admin action). Cannot be undone.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string             true  "Sensor ID"
// @Param        body  body      SensorRevokeRequest false "Revoke reason"
// @Success      200   {object}  SensorResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/revoke [post]
func (h *SensorHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	var req SensorRevokeRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	a, err := h.service.RevokeSensor(r.Context(), tenantID, sensorID, req.Reason, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSensorResponse(r.Context(), a))
}

// ipStringPtr renders an address, nil when unknown.
func ipStringPtr(ip net.IP) *string {
	if ip == nil {
		return nil
	}
	s := ip.String()
	return &s
}

// toSensorResponse converts a sensor entity to response, with the state,
// health reasons and version status computed now under the handler's policy.
func (h *SensorHandler) toSensorResponse(ctx context.Context, a *sensor.Sensor) *SensorResponse {
	return sensorResponseAt(a, h.policyFor(ctx, a.TenantID.String()), h.now())
}

// sensorResponseAt converts a sensor entity to response at a given time.
func sensorResponseAt(a *sensor.Sensor, policy sensor.HealthPolicy, now time.Time) *SensorResponse {
	health := a.AssessHealth(now, policy)
	// The effective credential (rotating key when there is one), never the
	// inline columns: those keep the retired bootstrap key after a renewal.
	keyState := a.KeyState()
	resp := &SensorResponse{
		ID:            a.ID.String(),
		TenantID:      a.TenantID.String(),
		Name:          a.Name,
		Type:          string(a.Type),
		Description:   a.Description,
		Capabilities:  a.Capabilities,
		ExecutionMode: string(a.ExecutionMode),
		Status:        string(a.Status), // Admin-controlled
		Health:        string(a.Health), // Automatic heartbeat
		StatusMessage: a.StatusMessage,
		APIKeyPrefix:  keyState.Prefix,
		Labels:        a.Labels,
		Version:       health.Version, // one form: "v0.4.2"
		Hostname:      a.Hostname,
		// System metrics
		CPUPercent:    a.CPUPercent,
		MemoryPercent: a.MemoryPercent,
		Region:        a.Region,
		// Load balancing
		MaxConcurrentJobs: a.MaxConcurrentJobs,
		CurrentJobs:       a.CurrentJobs,
		AvailableSlots:    a.FreeSlots(now),
		LoadFactor:        a.LoadFactor(),
		// Statistics
		TotalFindings: a.TotalFindings,
		TotalScans:    a.TotalScans,
		ErrorCount:    a.ErrorCount,
		CreatedAt:     a.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     a.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		// Computed fleet health
		State:            string(health.State),
		HealthReasons:    make([]SensorHealthReasonResponse, 0, len(health.Reasons)),
		VersionStatus:    string(health.VersionStatus),
		KeyExpiresAt:     rfc3339Ptr(keyState.ExpiresAt),
		LegacyKey:        keyState.IsLegacy(),
		KeyLastUsedAt:    rfc3339Ptr(a.KeyLastUsedAt),
		KeyLastUsedIP:    ipStringPtr(a.KeyLastUsedIP),
		InstanceID:       a.InstanceID,
		IdentityClonedAt: rfc3339Ptr(a.IdentityClonedAt),
		LastOfflineAt:    rfc3339Ptr(a.LastOfflineAt),
		LastErrorAt:      rfc3339Ptr(a.LastErrorAt),
		StartedAt:        rfc3339Ptr(a.StartedAt),
		UptimeSeconds:    health.UptimeSeconds,
		SDKName:          a.Build.SDKName,
		SDKVersion:       a.Build.SDKVersion,
		SDKStatus:        string(health.SDKStatus),
		SensorProduct:    a.Build.Product,
		SensorCommit:     a.Build.Commit,
		SensorBuildTime:  rfc3339Ptr(a.Build.BuildTime),
	}
	for _, r := range health.Reasons {
		resp.HealthReasons = append(resp.HealthReasons, SensorHealthReasonResponse{
			Code: string(r.Code), Severity: r.Severity, Message: r.Message,
		})
	}
	resp.Content, resp.ContentRefreshSupported = contentResponse(a, policy, now)

	if a.IPAddress != nil {
		resp.IPAddress = a.IPAddress.String()
	}

	if a.LastSeenAt != nil {
		ts := a.LastSeenAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastSeenAt = &ts
	}

	if ob := a.Outbox; ob != nil {
		resp.Outbox = &SensorOutboxResponse{
			PendingCount:     ob.PendingCount,
			PendingBytes:     ob.PendingBytes,
			OldestAgeSeconds: ob.OldestAgeSeconds,
			DeadLetterCount:  ob.DeadLetterCount,
			EvictedCount:     ob.EvictedCount,
			ReportedAt:       ob.ReportedAt.UTC().Format(time.RFC3339),
		}
		resp.OutboxWarning = ob.Warning()
	}

	if !a.Load.IsEmpty() {
		resp.Load = &SensorLoadResponse{
			Resources:  a.Load.Resources,
			Capacity:   a.Load.Capacity,
			Queue:      a.Load.Queue,
			ReportedAt: rfc3339Ptr(a.Load.ReportedAt),
			Fresh:      a.Load.IsFresh(now),
		}
	}

	if c := a.Control; c != nil {
		resp.Control = &SensorControlResponse{
			IntervalSeconds: c.IntervalSeconds, GapSeconds: c.GapSeconds,
			LagMillis: c.LagMillis, BuildMillis: c.BuildMillis, RTTMillis: c.RTTMillis,
			Failures: c.Failures, ReportedAt: rfc3339Ptr(c.ReportedAt),
		}
	}
	if a.HeartbeatInterval > 0 {
		secs := int(a.HeartbeatInterval / time.Second)
		resp.HeartbeatIntervalSeconds = &secs
	}
	resp.HeartbeatDueAt = rfc3339Ptr(a.HeartbeatDueAt)
	if a.LastSeenAt != nil {
		resp.HeartbeatState = string(sensor.Ladder(now, a.HeartbeatDeadline()).State)
	}

	if p := a.Protocol; p != nil {
		resp.Protocol = &SensorProtocolResponse{
			Version:    p.Version,
			UserAgent:  p.UserAgent,
			SeenAt:     p.SeenAt.UTC().Format(time.RFC3339),
			Deprecated: p.Deprecated(),

			Binding:        p.Binding,
			FallbackReason: p.FallbackReason,
		}
	}

	resp.Effective = SensorEffectiveResponse{
		Tools:             a.EffectiveTools(),
		Capabilities:      a.EffectiveCapabilities(),
		MaxConcurrentJobs: a.EffectiveMaxConcurrentJobs(),
	}
	if rep := a.Reported; rep.ReportedAt != nil || rep.HasReport() {
		out := &SensorReportedResponse{
			Tools: rep.Tools, Capabilities: rep.Capabilities,
			OS: rep.OS, Arch: rep.Arch,
		}
		if rep.MaxConcurrentJobs > 0 {
			n := rep.MaxConcurrentJobs
			out.MaxConcurrentJobs = &n
		}
		if rep.ReportedAt != nil {
			ts := rep.ReportedAt.UTC().Format(time.RFC3339)
			out.ReportedAt = &ts
		}
		resp.Reported = out
	}
	if m := a.CapabilityMismatch(); !m.IsEmpty() {
		resp.CapabilityMismatch = &m
	}
	resp.ManifestDigest, resp.ManifestSource = a.ManifestDigest, a.ManifestSource
	resp.ManifestAt = rfc3339Ptr(a.ManifestAt)
	resp.LocalPolicy = localPolicyResponse(a)
	resp.Posture = postureResponse(a)
	if a.ConfigHealth != "" {
		h := a.ConfigHealth
		resp.ConfigHealth = &h
	}

	return resp
}

// contentResponse is the content view of a sensor under the policy (the
// tenant's content policy, the platform default when nil).
func contentResponse(a *sensor.Sensor, policy sensor.HealthPolicy, now time.Time) ([]SensorContentResponse, bool) {
	cp := sensor.DefaultContentPolicy()
	if policy.Content != nil {
		cp = *policy.Content
	}
	views := a.ContentViews(now, cp.WithDefaults(sensor.DefaultContentPolicy()))
	out := make([]SensorContentResponse, 0, len(views))
	for _, v := range views {
		out = append(out, SensorContentResponse{
			Tool: v.Tool, Name: v.Name, Version: v.Version,
			UpdatedAt: rfc3339Ptr(v.UpdatedAt), FetchedAt: rfc3339Ptr(v.FetchedAt), CheckedAt: rfc3339Ptr(v.CheckedAt),
			Source: v.Source, Digest: v.Digest, Managed: v.Managed, Error: v.Error,
			AgeSeconds: v.AgeSeconds, MaxAgeHours: v.MaxAgeHours, Stale: v.Stale,
			PinnedVersion: v.PinnedVersion, PinMismatch: v.PinMismatch,
		})
	}
	return out, a.SupportsContentRefresh()
}

// rfc3339Ptr formats an optional time as RFC 3339 UTC, or nil.
func rfc3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// handleValidationError converts validation errors to API errors.
func (h *SensorHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

// handleServiceError converts service errors to API errors.
func (h *SensorHandler) handleServiceError(w http.ResponseWriter, err error) {
	if WritePlanLimitError(w, err) {
		return
	}
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Sensor").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Sensor already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, sensor.ErrBearerKeysDisabled):
		apierror.New(http.StatusForbidden, "BEARER_KEYS_DISABLED", "This organization requires key-bound identity: pair the sensor instead of creating a key").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
	}
}

// buildAuditContext extracts audit context information from the HTTP request.
func (h *SensorHandler) buildAuditContext(r *http.Request) *audit.AuditContext {
	// Forwarding headers count only from a trusted proxy (S-4); a client
	// must not be able to write any IP it likes into the audit log.
	clientIP := getClientIP(r)

	return &audit.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    clientIP,
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

// =============================================================================
// Available Capabilities
// =============================================================================

// AvailableCapabilitiesResponse represents the response for available capabilities.
type AvailableCapabilitiesResponse struct {
	Capabilities []string `json:"capabilities"`
}

// GetAvailableCapabilities returns all capabilities available to the current tenant.
// GET /api/v1/sensors/available-capabilities
// @Summary Get available capabilities
// @Description Returns all unique capability names from all sensors accessible to the tenant
// @Tags sensors
// @Produce json
// @Success 200 {object} AvailableCapabilitiesResponse
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Failure 500 {object} apierror.Error "Internal server error"
// @Router /sensors/available-capabilities [get]
func (h *SensorHandler) GetAvailableCapabilities(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant ID").WriteJSON(w)
		return
	}

	result, err := h.service.GetAvailableCapabilitiesForTenant(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to get available capabilities", "error", err, "tenant_id", tenantID)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := AvailableCapabilitiesResponse{
		Capabilities: result.Capabilities,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// SensorConfigTemplatesResponse holds the rendered install and configuration
// snippets for one sensor, and what they were rendered with.
type SensorConfigTemplatesResponse struct {
	YAML   string `json:"yaml"`
	Env    string `json:"env"`
	Docker string `json:"docker"`
	CLI    string `json:"cli"`
	// Compose is a compose.yaml for the sensor; Kubernetes a Secret, PVC and
	// Deployment (a Job for a one-shot sensor); Helm the commands that turn
	// on the sensor bundled with the openctem chart.
	Compose    string `json:"compose"`
	Kubernetes string `json:"kubernetes"`
	Helm       string `json:"helm"`
	// Policy is the sensor-local policy template (sensor-policy.yaml, RFC-040
	// §5.7), prefilled with the ranges of the sensor's scan zones, for the
	// network owner to review and install read-only on the sensor host.
	Policy string `json:"policy"`
	// Image is the sensor image the snippets run, with its pinned tag.
	Image string `json:"image"`
	// APIURL is the platform URL the snippets point the sensor at.
	APIURL string `json:"api_url"`
	// APIKeyIncluded is true when the snippets carry the key passed in
	// X-Sensor-API-Key; otherwise they read it from OPENCTEM_API_KEY.
	APIKeyIncluded bool `json:"api_key_included"`
	// CACertificate is the PEM of the platform's private CA the snippets
	// install (SENSOR_CA_CERT_FILE); "" when none is configured.
	CACertificate string `json:"ca_certificate"`
	// CAFingerprintSHA256 is the SHA-256 fingerprint of that CA, colon hex.
	CAFingerprintSHA256 string `json:"ca_fingerprint_sha256"`
}

// sensorAPIKeyHeaderRegexp is the shape of a sensor API key. The header value
// is embedded in shell snippets, so anything else is refused.
var sensorAPIKeyHeaderRegexp = regexp.MustCompile(`^[A-Za-z0-9_-]{8,256}$`)

// DefaultSensorImage is the install snippets' image when none is configured.
// Its tag is versions.yaml sensor.latest, copied by
// .github/scripts/release/sync-versions.sh (RFC-037).
const DefaultSensorImage = "ghcr.io/openctemio/sensor:v0.12.0"

// GetConfigTemplates handles GET /api/v1/sensors/{id}/config-templates
// Returns rendered install and configuration snippets (docker run, Compose,
// Kubernetes, Helm, YAML, env, CLI) for a sensor.
// Templates are loaded from configs/sensor-templates/*.tmpl on the API host
// and can be edited without rebuilding the frontend.
//
// @Summary Get sensor configuration templates
// @Description Returns the install and configuration snippets for a sensor: docker run, Compose, Kubernetes, Helm, YAML, env and CLI, pinned to the sensor image of SENSOR_LATEST_VERSION, pointed at the public platform URL, and installing the platform's private CA when SENSOR_CA_CERT_FILE is set.
// @Tags Sensors
// @Produce json
// @Param id path string true "Sensor ID"
// @Param X-Sensor-API-Key header string false "Optional API key to embed in templates (only available right after creation/regeneration). MUST be sent as header, not query parameter."
// @Success 200 {object} SensorConfigTemplatesResponse
// @Failure 400 {object} apierror.Error "X-Sensor-API-Key is malformed"
// @Failure 404 {object} apierror.Error
// @Failure 500 {object} apierror.Error
// @Failure 503 {object} apierror.Error "Template service not configured"
// @Security BearerAuth
// @Router /sensors/{id}/config-templates [get]
func (h *SensorHandler) GetConfigTemplates(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		apierror.New(http.StatusServiceUnavailable, "TEMPLATE_SERVICE_DISABLED",
			"Sensor config template service is not configured").WriteJSON(w)
		return
	}

	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	a, err := h.service.GetSensor(r.Context(), tenantID, sensorID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// API key MUST come from a header, never a query string. Query strings are
	// logged by load balancers, proxies, CDNs, browser history, and referer
	// headers — embedding a credential there is a known leakage vector.
	// Caller passes the freshly issued key from sensor creation/regeneration
	// in the X-Sensor-API-Key header. If absent, the snippets read the key
	// from $OPENCTEM_API_KEY.
	apiKey := strings.TrimSpace(r.Header.Get("X-Sensor-API-Key"))
	if apiKey != "" && !sensorAPIKeyHeaderRegexp.MatchString(apiKey) {
		apierror.BadRequest("X-Sensor-API-Key is not a sensor API key").WriteJSON(w)
		return
	}

	baseURL := h.publicAPIURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	image := h.sensorImage
	if image == "" {
		image = DefaultSensorImage
	}

	caPEM, caFingerprint, caErr := sensorapp.LoadCACertificate(h.caCertFile)
	if caErr != nil {
		// Not fatal: the snippets then assume a publicly trusted certificate.
		h.logger.Warn("sensor CA certificate not usable; install snippets omit it",
			"path", h.caCertFile, "error", caErr)
	}

	data := sensorapp.SensorTemplateData{
		Sensor:  a,
		APIKey:  apiKey,
		BaseURL: baseURL,
		Image:   image,
		CACert:  caPEM,
	}
	if h.zones != nil && a.TenantID != nil {
		// Best effort: without zones the policy template asks for ranges.
		if zones, zerr := h.zones.List(r.Context(), *a.TenantID); zerr == nil {
			data.Policy = sensorapp.PolicyFromZones(zones, a.ID)
		} else {
			h.logger.Warn("scan zones not read for the policy template", "error", logger.SanitizeError(zerr))
		}
	}
	rendered, err := h.templateService.Render(data)
	if err != nil {
		h.logger.Error("failed to render sensor config templates", "error", logger.SanitizeError(err), "sensor_id", logger.SanitizeValue(sensorID))
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := SensorConfigTemplatesResponse{
		YAML:                rendered.YAML,
		Env:                 rendered.Env,
		Docker:              rendered.Docker,
		CLI:                 rendered.CLI,
		Compose:             rendered.Compose,
		Kubernetes:          rendered.Kubernetes,
		Helm:                rendered.Helm,
		Policy:              rendered.Policy,
		Image:               image,
		APIURL:              baseURL,
		APIKeyIncluded:      apiKey != "",
		CACertificate:       caPEM,
		CAFingerprintSHA256: caFingerprint,
	}
	// The response can carry a freshly issued key: never cache it.
	w.Header().Set("Cache-Control", "no-store")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
