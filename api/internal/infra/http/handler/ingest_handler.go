package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// contextKey is a custom type for context keys.
type contextKey string

const sensorContextKey contextKey = "sensor"

// sensorIdentityContextKey carries the app.SensorIdentity AuthenticateSource
// resolved (paused flag, presented key expiry) for the heartbeat doorbell.
const sensorIdentityContextKey contextKey = "sensor_identity"

// IngestHandler holds the sensor authentication middleware and the services
// the protocol v2 control handler (SensorControlV2Handler) shares: ingest,
// sensor, heartbeat doorbell and heartbeat latency observer.
type IngestHandler struct {
	ingestService *ingest.Service
	sensorService *app.SensorService
	logger        *logger.Logger

	// doorbell computes the heartbeat hints (RFC-023 §9.2a). Nil: no hints.
	doorbell *app.Doorbell

	// heartbeats observes heartbeat handling latency for the health
	// controller's platform-health guard (RFC-035 D3). Nil: not observed.
	heartbeats HeartbeatLatencyObserver
}

// HeartbeatLatencyObserver records how long one heartbeat took to handle.
// Implemented by app.PlatformHealth.
type HeartbeatLatencyObserver interface {
	ObserveHeartbeat(d time.Duration)
}

// SetHeartbeatObserver wires the heartbeat latency observer.
func (h *IngestHandler) SetHeartbeatObserver(o HeartbeatLatencyObserver) { h.heartbeats = o }

func (h *IngestHandler) observeHeartbeat(d time.Duration) {
	if h != nil && h.heartbeats != nil {
		h.heartbeats.ObserveHeartbeat(d)
	}
}

// SetDoorbell wires the heartbeat doorbell. Optional; without it the
// heartbeat carries no hints.
func (h *IngestHandler) SetDoorbell(d *app.Doorbell) {
	h.doorbell = d
}

// NewIngestHandler creates a new ingest handler.
func NewIngestHandler(
	ingestSvc *ingest.Service,
	sensorSvc *app.SensorService,
	log *logger.Logger,
) *IngestHandler {
	return &IngestHandler{
		ingestService: ingestSvc,
		sensorService: sensorSvc,
		logger:        log,
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// HeartbeatRequest represents the heartbeat payload from sensors.
type HeartbeatRequest struct {
	Name     string `json:"name,omitempty"`
	Status   string `json:"status"`
	Version  string `json:"version,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// InstanceID is the random id of the sensor process (sdk-go v0.12+), for
	// clone detection. Optional; older SDKs do not send it.
	InstanceID    string   `json:"instance_id,omitempty"`
	Message       string   `json:"message,omitempty"`
	Scanners      []string `json:"scanners,omitempty"`
	Collectors    []string `json:"collectors,omitempty"`
	Uptime        int64    `json:"uptime_seconds,omitempty"`
	TotalScans    int64    `json:"total_scans,omitempty"`
	Errors        int64    `json:"errors,omitempty"`
	CPUPercent    float64  `json:"cpu_percent,omitempty"`
	MemoryPercent float64  `json:"memory_percent,omitempty"`
	ActiveJobs    int      `json:"active_jobs,omitempty"`
	Region        string   `json:"region,omitempty"`

	// Disk/network throughput in MB/s. Optional — sensors that omit them leave
	// the corresponding load-balancing terms at zero. Accepted here so the
	// SENSOR_LB_DISK_IO_WEIGHT / SENSOR_LB_NETWORK_WEIGHT knobs have real inputs.
	DiskReadMBPS  float64 `json:"disk_read_mbps,omitempty"`
	DiskWriteMBPS float64 `json:"disk_write_mbps,omitempty"`
	NetworkRxMBPS float64 `json:"network_rx_mbps,omitempty"`
	NetworkTxMBPS float64 `json:"network_tx_mbps,omitempty"`

	// Outbox is the state of the sensor's durable outbox (results queued on
	// disk, waiting to be delivered). Optional: SDKs without an outbox omit
	// it, and a heartbeat without it leaves the stored snapshot untouched.
	// Display data only; values are clamped before they are stored.
	Outbox *HeartbeatOutbox `json:"outbox,omitempty"`

	// What the sensor reports it can do (RFC-029 §4.3.1), all optional:
	// its tool inventory, the capabilities it serves, how many jobs it runs
	// at once, and its platform. An absent list is "not reported" (the
	// administrator's settings apply); [] is "none". Untrusted: sanitized
	// against the tool catalog before it is stored, and it can only narrow
	// what the administrator allows.
	Tools             []HeartbeatTool `json:"tools,omitempty"`
	Capabilities      []string        `json:"capabilities,omitempty"`
	MaxConcurrentJobs int             `json:"max_concurrent_jobs,omitempty"`
	OS                string          `json:"os,omitempty"`
	Arch              string          `json:"arch,omitempty"`

	// The sensor's load, computed by the SDK (RFC-030 §5.8), all optional:
	// the machine's resources (container limits when it runs in one), its
	// job slots and per-tool cost, and its local work queue. Untrusted:
	// clamped before it is stored, and it can only lower what dispatch
	// hands the sensor.
	Resources *sensor.ReportedResources `json:"resources,omitempty"`
	Capacity  *sensor.ReportedCapacity  `json:"capacity,omitempty"`
	Queue     *sensor.ReportedQueue     `json:"queue,omitempty"`
	// Running is the ids of the commands the sensor holds (claimed or
	// running). The SDK that sends the queue always lists them (an empty
	// list is left out); the heartbeat renews their leases (RFC-035 D6).
	// Sensor wire only: not part of the management API's documented types.
	Running []string `json:"running,omitempty" swaggerignore:"true"`

	// Build information, optional (docs/architecture/sensors.md "Build
	// information"): sdk {name, version} and sensor {name, version, commit,
	// build_time}. Kept raw and read leniently: a member of an unexpected
	// shape is ignored rather than failing the heartbeat. Untrusted; sensors
	// that omit it are read from their User-Agent.
	SDK    json.RawMessage `json:"sdk,omitempty" swaggertype:"object"`
	Sensor json.RawMessage `json:"sensor,omitempty" swaggertype:"object"`

	// ManifestDigest is the digest of the sensor's registered manifest, as
	// the platform returned it (RFC-033, protocol v2 feature "manifest").
	// When it is not the stored one the v2 answer asks for the manifest
	// (action send_manifest). Absent: the platform derives the manifest
	// from this heartbeat.
	ManifestDigest string `json:"manifest_digest,omitempty"`
	// Content is a slim heartbeat's content freshness (RFC-033 §6.12): a
	// sensor whose manifest is acknowledged leaves tools out and sends each
	// tool's content here, with "tool" set. Merged into the stored tools.
	Content []sensor.ReportedContent `json:"content,omitempty"`

	// Control is how well the sensor's heartbeat loop keeps time (sdk-go,
	// RFC-035 §5.5): {"interval_s","gap_s","lag_ms","build_ms","rtt_ms",
	// "failures"}. Read leniently (a member of the wrong type is ignored)
	// and clamped; interval_s feeds the sensor's heartbeat deadline.
	Control json.RawMessage `json:"control,omitempty" swaggertype:"object"`
	// LocalPolicy is the sensor-local policy report (RFC-040 §5.7): state,
	// digest, summary and kill switch, sent by SDKs that see
	// "local_policy" on hello. Display data; sanitized before it is stored.
	LocalPolicy *sensor.LocalPolicyReport `json:"local_policy,omitempty"`
	// ConfigReport is the config report summary (research/26): digest,
	// health, fail and warn counts, observed_at, sent by SDKs that see
	// "config_report" on hello. The digest is the one PUT /config-report
	// returned. Read leniently (a member of the wrong shape is ignored).
	ConfigReport json.RawMessage `json:"config_report,omitempty" swaggertype:"object"`
}

// loadReport returns the heartbeat's load report, nil when it carried none.
func (req *HeartbeatRequest) loadReport() *sensor.LoadReport {
	l := &sensor.LoadReport{Resources: req.Resources, Capacity: req.Capacity, Queue: req.Queue}
	if l.IsEmpty() {
		return nil
	}
	return l
}

// heartbeatBuildMember is the shape of the sdk and sensor members.
type heartbeatBuildMember struct {
	Name      any `json:"name"`
	Version   any `json:"version"`
	Commit    any `json:"commit"`
	BuildTime any `json:"build_time"`
}

// buildReport reads the heartbeat's sdk and sensor members; a member that is
// not an object, or a field that is not a string, is ignored.
func (req *HeartbeatRequest) buildReport() sensor.BuildReport {
	str := func(v any) string {
		s, _ := v.(string)
		return s
	}
	var out sensor.BuildReport
	var sdk, sen heartbeatBuildMember
	if len(req.SDK) > 0 && json.Unmarshal(req.SDK, &sdk) == nil {
		out.SDKName, out.SDKVersion = str(sdk.Name), str(sdk.Version)
	}
	if len(req.Sensor) > 0 && json.Unmarshal(req.Sensor, &sen) == nil {
		out.SensorName, out.SensorVersion = str(sen.Name), str(sen.Version)
		out.Commit, out.BuildTime = str(sen.Commit), str(sen.BuildTime)
	}
	return out
}

// HeartbeatTool is one tool of a heartbeat's tool inventory.
type HeartbeatTool struct {
	Name string `json:"name"`
	// Kind is "scanner" or "collector" (sdk-go v0.10+).
	Kind      string `json:"kind,omitempty"`
	Version   string `json:"version,omitempty"`
	Installed bool   `json:"installed"`
	// Capabilities are what the tool serves besides its name (sdk-go
	// v0.13+); sanitized against the capability registry like the flat list.
	Capabilities []string `json:"capabilities,omitempty"`
	// Content is the scanner content the tool scans with (RFC-031).
	Content []sensor.ReportedContent `json:"content,omitempty"`
}

// capabilityReport returns the heartbeat's capability report, nil when it
// carried none.
func (req *HeartbeatRequest) capabilityReport() *sensor.CapabilityReportInput {
	in := sensor.CapabilityReportInput{
		Capabilities:      req.Capabilities,
		MaxConcurrentJobs: req.MaxConcurrentJobs,
		OS:                req.OS,
		Arch:              req.Arch,
	}
	if req.Tools != nil {
		in.Tools = make([]sensor.ReportedTool, 0, min(len(req.Tools), sensor.MaxReportedTools))
		for i, t := range req.Tools {
			if i >= sensor.MaxReportedTools {
				break
			}
			in.Tools = append(in.Tools, sensor.ReportedTool{Name: t.Name, Kind: t.Kind, Version: t.Version,
				Installed: t.Installed, Capabilities: t.Capabilities, Content: t.Content})
		}
	}
	if in.IsEmpty() {
		return nil
	}
	return &in
}

// HeartbeatOutbox is the outbox block of the heartbeat request.
type HeartbeatOutbox struct {
	// PendingCount is the number of items waiting to be delivered.
	PendingCount int64 `json:"pending_count"`
	// PendingBytes is the size on disk of those items.
	PendingBytes int64 `json:"pending_bytes"`
	// OldestAgeSeconds is the age of the oldest pending item (0 when empty).
	OldestAgeSeconds int64 `json:"oldest_age_seconds"`
	// DeadLetterCount is the number of items the platform refused for good.
	DeadLetterCount int64 `json:"dead_letter_count"`
	// EvictedCount is the number of items dropped by the size/age cap since
	// the sensor process started.
	EvictedCount int64 `json:"evicted_count"`
}

// toOutboxStats returns the clamped domain snapshot, or nil for nil.
func (o *HeartbeatOutbox) toOutboxStats() *sensor.OutboxStats {
	if o == nil {
		return nil
	}
	stats := sensor.OutboxStats{
		PendingCount:     o.PendingCount,
		PendingBytes:     o.PendingBytes,
		OldestAgeSeconds: o.OldestAgeSeconds,
		DeadLetterCount:  o.DeadLetterCount,
		EvictedCount:     o.EvictedCount,
	}.Clamp()
	return &stats
}

// =============================================================================
// Authentication Middleware
// =============================================================================

// AuthenticateSource is middleware that authenticates the sensor by API key
// (sensor routes outside /api/v2/sensor, e.g. POST /api/v1/validation/evidence).
// A disabled (paused) sensor is refused.
func (h *IngestHandler) AuthenticateSource(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A signed request (key-bound sensor, RFC-052) is decided by its
		// signature alone; only an unsigned one may present a bearer key.
		id, signed, err := authenticateSigned(r, h.sensorService, getClientIP(r), time.Now())
		switch {
		case err == nil:
			r = signed
		case errors.Is(err, errNotSigned):
			apiKey := extractAPIKey(r)
			if apiKey == "" {
				apierror.Unauthorized("API key required").WriteJSON(w)
				return
			}
			id, err = h.sensorService.AuthenticateIdentityFrom(r.Context(), apiKey, getClientIP(r))
		}
		if err == nil && id.Paused {
			err = errSensorPaused
		}
		if err != nil {
			h.logger.Debug("authentication failed", "error", err)
			apierror.Unauthorized("Invalid API key").WriteJSON(w)
			return
		}
		agt := id.Sensor
		// A CI runner authenticating with a long-lived sensor key: still
		// accepted, but deprecated in favor of OIDC workload identity
		// (RFC-051). The headers let the runner warn its pipeline.
		if agt.Type == sensor.SensorTypeRunner {
			w.Header().Set("Deprecation", runnerKeyDeprecatedAt)
			w.Header().Set("Link", `</api/v1/ci/oidc/exchange>; rel="successor-version"`)
		}

		// Add sensor to context
		ctx := context.WithValue(r.Context(), sensorContextKey, agt)
		ctx = context.WithValue(ctx, sensorIdentityContextKey, id)
		// Expose the authenticated sensor's tenant to tenant-keyed
		// middleware that runs later in the chain (ingest/telemetry
		// rate limiters). Sensor API-key auth is the tenant-binding
		// authority on these routes; without this the per-tenant rate
		// limiters key on an empty string and pass through every
		// request — the "compromised key replays at line rate" abuse
		// the limiters exist to stop. Platform sensors (nil tenant)
		// are rejected by the per-handler nil-tenant guards before
		// they act, so we only need the common tenant-bound case here.
		if agt.TenantID != nil {
			ctx = context.WithValue(ctx, middleware.TenantIDKey, agt.TenantID.String())
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// runnerKeyDeprecatedAt is the RFC 9745 Deprecation value for CI runners
// that authenticate with a sensor API key (2026-10-05): CI should use OIDC
// workload identity (RFC-051).
const runnerKeyDeprecatedAt = "@1791158400"

// errSensorPaused refuses a disabled sensor.
var errSensorPaused = errors.New("sensor is disabled")

// sensorIdentityFromContext returns the identity AuthenticateSource
// resolved, falling back to the bare sensor (no paused flag, the sensor's
// effective key expiry) when only that is in the context.
func sensorIdentityFromContext(ctx context.Context) app.SensorIdentity {
	if id, ok := ctx.Value(sensorIdentityContextKey).(app.SensorIdentity); ok && id.Sensor != nil {
		return id
	}
	agt := SensorFromContext(ctx)
	if agt == nil {
		return app.SensorIdentity{}
	}
	return app.SensorIdentity{Sensor: agt, KeyExpiresAt: agt.KeyState().ExpiresAt}
}

// SensorFromContext retrieves the authenticated sensor from context.
func SensorFromContext(ctx context.Context) *sensor.Sensor {
	agt, _ := ctx.Value(sensorContextKey).(*sensor.Sensor)
	return agt
}

// commandsToCancel is what the heartbeat tells the sensor to stop: the
// commands in its running list it no longer holds (canceled, timed out,
// re-queued, held elsewhere). Only a sensor that reports its running list
// (it sends the queue) gets any; the lookup never fails the heartbeat.
func (h *IngestHandler) commandsToCancel(ctx context.Context, s *sensor.Sensor, req *HeartbeatRequest) []string {
	if req == nil || req.Queue == nil || len(req.Running) == 0 {
		return nil
	}
	return h.sensorService.CommandsToCancel(ctx, s, req.Running)
}

// BaselineDiffRequest asks which fingerprints are new vs a PR's base branch.
type BaselineDiffRequest struct {
	Repository   string   `json:"repository"`
	BaseBranch   string   `json:"base_branch"`
	Fingerprints []string `json:"fingerprints"`
}

// =============================================================================
// Helper Functions
// =============================================================================

// extractAPIKey extracts the API key from the request.
// Supports: Authorization: Bearer <key> or X-API-Key: <key>
//
// SECURITY: Query parameter authentication is NOT supported.
// API keys in query parameters are logged by proxies, CDNs, and access logs,
// exposing credentials across the infrastructure stack.
func extractAPIKey(r *http.Request) string {
	// Try Authorization header first (preferred method)
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}

	// Try X-API-Key header (alternative for clients that can't set Authorization)
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		return apiKey
	}

	// SECURITY: DO NOT use query parameter for API key
	// Query params are logged by proxies, CDNs, WAFs, and access logs
	return ""
}
