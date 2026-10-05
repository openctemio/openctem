package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/adapters"
	"github.com/openctemio/openctem/api/internal/infra/adapters/core"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/legacyv1"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// ChunkData represents a chunk of a large CTIS report.
// Inlined from sdk-go/pkg/chunk to remove SDK dependency.
type ChunkData struct {
	ReportID    string               `json:"report_id"`
	ChunkIndex  int                  `json:"chunk_index"`
	TotalChunks int                  `json:"total_chunks"`
	Tool        *ctis.Tool           `json:"tool,omitempty"`
	Metadata    *ctis.ReportMetadata `json:"metadata,omitempty"`
	Assets      []ctis.Asset         `json:"assets,omitempty"`
	Findings    []ctis.Finding       `json:"findings,omitempty"`
	IsFinal     bool                 `json:"is_final"`
}

// contextKey is a custom type for context keys.
type contextKey string

const sensorContextKey contextKey = "sensor"

// sensorIdentityContextKey carries the app.SensorIdentity AuthenticateSource
// resolved (paused flag, presented key expiry) for the heartbeat doorbell.
const sensorIdentityContextKey contextKey = "sensor_identity"

// IngestHandler handles ingestion-related HTTP requests.
// It supports CTIS, SARIF, Recon, and raw scanner output formats.
type IngestHandler struct {
	ingestService   *ingest.Service
	sensorService   *app.SensorService
	adapterRegistry *adapters.Registry
	logger          *logger.Logger

	// Async ingest (RFC-005). Wired only when INGEST_MODE=async via
	// SetAsyncIngest; nil/false means the legacy synchronous path is used.
	ingestJobRepo       ingestjob.Repository
	asyncMode           bool
	maxPendingPerTenant int

	// doorbell computes the heartbeat hints (RFC-023 §9.2a). Nil keeps the
	// plain v1 heartbeat response.
	doorbell *app.Doorbell

	// v2Advertised: protocol v2 results are served (RFC-026), so a heartbeat
	// from a sensor that announced the results-v2 feature is answered with
	// X-OpenCTEM-Protocol: 2. Nobody else sees the header.
	v2Advertised bool

	// heartbeats observes heartbeat handling latency for the health
	// controller's platform-health guard (RFC-035 D3). Nil: not observed.
	heartbeats HeartbeatLatencyObserver
}

// HeartbeatLatencyObserver records how long one heartbeat took to handle.
// Implemented by app.PlatformHealth.
type HeartbeatLatencyObserver interface {
	ObserveHeartbeat(d time.Duration)
}

// SetHeartbeatObserver wires the heartbeat latency observer (v1 and v2).
func (h *IngestHandler) SetHeartbeatObserver(o HeartbeatLatencyObserver) { h.heartbeats = o }

func (h *IngestHandler) observeHeartbeat(d time.Duration) {
	if h != nil && h.heartbeats != nil {
		h.heartbeats.ObserveHeartbeat(d)
	}
}

// SetV2Advertised turns on the protocol v2 advertisement on the heartbeat.
func (h *IngestHandler) SetV2Advertised(on bool) { h.v2Advertised = on }

// SetDoorbell wires the heartbeat doorbell. Optional; without it the
// heartbeat answers exactly as protocol v1 did before the doorbell.
func (h *IngestHandler) SetDoorbell(d *app.Doorbell) {
	h.doorbell = d
}

// SetAsyncIngest enables async ingest: the CTIS endpoint enqueues the payload
// and returns 202 instead of processing it in-request. Opt-in — when not
// called, ingest stays fully synchronous.
func (h *IngestHandler) SetAsyncIngest(repo ingestjob.Repository, maxPendingPerTenant int) {
	h.ingestJobRepo = repo
	h.asyncMode = true
	h.maxPendingPerTenant = maxPendingPerTenant
}

// NewIngestHandler creates a new ingest handler.
func NewIngestHandler(
	ingestSvc *ingest.Service,
	sensorSvc *app.SensorService,
	log *logger.Logger,
) *IngestHandler {
	return &IngestHandler{
		ingestService:   ingestSvc,
		sensorService:   sensorSvc,
		adapterRegistry: adapters.NewRegistry(),
		logger:          log,
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// IngestResponse represents the response from ingestion.
type IngestResponse struct {
	ScanID          string   `json:"scan_id"`
	AssetsCreated   int      `json:"assets_created"`
	AssetsUpdated   int      `json:"assets_updated"`
	FindingsCreated int      `json:"findings_created"`
	FindingsUpdated int      `json:"findings_updated"`
	FindingsSkipped int      `json:"findings_skipped"`
	CVEsCreated     int      `json:"cves_created"`
	CVEsUpdated     int      `json:"cves_updated"`
	Errors          []string `json:"errors,omitempty"`
	// AssetsSkippedExcluded counts new assets not added because they match
	// an active scope exclusion; their findings are in findings_skipped.
	AssetsSkippedExcluded int `json:"assets_skipped_excluded,omitempty"`
	// Binding is "command" when the report named a command assigned to this
	// sensor (X-OpenCTEM-Command-ID), "unsolicited" otherwise (RFC-040 §5.3).
	Binding string `json:"binding,omitempty"`
	// AssetsLimited counts existing assets the report matched but was not
	// allowed to change, because no command covering them stood behind it.
	AssetsLimited int `json:"assets_limited,omitempty"`
	// ReopensWithheld counts findings a person had resolved that the report
	// saw again but was not allowed to reopen.
	ReopensWithheld int `json:"reopens_withheld,omitempty"`
	// UnsolicitedWarned: this sensor's role may not send results without a
	// command; the report was applied only because the tenant's policy is
	// "warn". Under "quarantine" it is held for review (422
	// RESULTS_QUARANTINED).
	UnsolicitedWarned bool `json:"unsolicited_warned,omitempty"`
}

// HeaderCommandID binds a v1 ingest request to the command it is the result
// of (RFC-040 §5.3). It must name a command assigned to the sensor and open;
// anything else is 404 COMMAND_NOT_FOUND.
const HeaderCommandID = "X-OpenCTEM-Command-ID"

// newIngestResponse is the v1 response for an ingest output.
func newIngestResponse(output *ingest.Output) IngestResponse {
	return IngestResponse{
		ScanID:                output.ReportID,
		AssetsCreated:         output.AssetsCreated,
		AssetsUpdated:         output.AssetsUpdated,
		FindingsCreated:       output.FindingsCreated,
		FindingsUpdated:       output.FindingsUpdated,
		FindingsSkipped:       output.FindingsSkipped,
		AssetsSkippedExcluded: output.AssetsSkippedExcluded,
		CVEsCreated:           output.CVEsCreated,
		CVEsUpdated:           output.CVEsUpdated,
		Errors:                output.Errors,
		Binding:               output.Binding,
		AssetsLimited:         output.AssetsLimited,
		ReopensWithheld:       output.ReopensWithheld,
		UnsolicitedWarned:     output.UnsolicitedWarned,
	}
}

// bindRequest resolves the X-OpenCTEM-Command-ID header into the request's
// binding. It answers 404 COMMAND_NOT_FOUND and returns false when the
// header names a command this sensor does not hold open.
func (h *IngestHandler) bindRequest(w http.ResponseWriter, r *http.Request, agt *sensor.Sensor) (ingest.Binding, bool) {
	id := strings.TrimSpace(r.Header.Get(HeaderCommandID))
	b, err := h.ingestService.BindCommand(r.Context(), agt, id)
	if err != nil {
		h.logger.Warn("ingest refused: the command it names is not open on this sensor",
			"sensor_id", agt.ID.String(), "command_id", sanitizeLogField(id))
		apierror.New(http.StatusNotFound, ingest.CodeCommandNotFound,
			"No open command with this id is assigned to this sensor.").WriteJSON(w)
		return ingest.Binding{}, false
	}
	return b, true
}

// CTISIngestRequest represents the request body for CTIS ingestion.
type CTISIngestRequest struct {
	Report ctis.Report `json:"report"`
}

// ReconIngestRequest represents reconnaissance scan results to ingest.
type ReconIngestRequest struct {
	// Scanner info
	ScannerName    string `json:"scanner_name"`
	ScannerVersion string `json:"scanner_version,omitempty"`
	ReconType      string `json:"recon_type"` // subdomain, dns, port, http_probe, url_crawl

	// Target
	Target string `json:"target"`

	// Timing
	StartedAt  int64 `json:"started_at,omitempty"`
	FinishedAt int64 `json:"finished_at,omitempty"`
	DurationMs int64 `json:"duration_ms,omitempty"`

	// Results (populated based on recon_type)
	Subdomains []SubdomainResult     `json:"subdomains,omitempty"`
	DNSRecords []DNSRecordResult     `json:"dns_records,omitempty"`
	OpenPorts  []OpenPortResult      `json:"open_ports,omitempty"`
	LiveHosts  []LiveHostResult      `json:"live_hosts,omitempty"`
	URLs       []DiscoveredURLResult `json:"urls,omitempty"`
}

// SubdomainResult represents a discovered subdomain.
type SubdomainResult struct {
	Host   string   `json:"host"`
	Domain string   `json:"domain,omitempty"`
	Source string   `json:"source,omitempty"`
	IPs    []string `json:"ips,omitempty"`
}

// DNSRecordResult represents a DNS record.
type DNSRecordResult struct {
	Host       string   `json:"host"`
	RecordType string   `json:"record_type"`
	Values     []string `json:"values"`
	TTL        int      `json:"ttl,omitempty"`
	Resolver   string   `json:"resolver,omitempty"`
	StatusCode string   `json:"status_code,omitempty"`
}

// OpenPortResult represents an open port.
type OpenPortResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// LiveHostResult represents an HTTP/HTTPS live host.
type LiveHostResult struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	IP            string   `json:"ip,omitempty"`
	Port          int      `json:"port,omitempty"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	ContentLength int64    `json:"content_length,omitempty"`
	Title         string   `json:"title,omitempty"`
	WebServer     string   `json:"web_server,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	CDN           string   `json:"cdn,omitempty"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	Redirect      string   `json:"redirect,omitempty"`
	ResponseTime  int64    `json:"response_time_ms,omitempty"`
}

// DiscoveredURLResult represents a discovered URL/endpoint.
type DiscoveredURLResult struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	Source     string `json:"source,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Depth      int    `json:"depth,omitempty"`
	Parent     string `json:"parent,omitempty"`
	Type       string `json:"type,omitempty"`
	Extension  string `json:"extension,omitempty"`
}

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
	// AGENT_LB_DISK_IO_WEIGHT / AGENT_LB_NETWORK_WEIGHT knobs have real inputs.
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

// CheckFingerprintsRequest represents the request for checking fingerprint existence.
type CheckFingerprintsRequest struct {
	Fingerprints []string `json:"fingerprints"`
}

// CheckFingerprintsResponse represents the response for fingerprint check.
type CheckFingerprintsResponse struct {
	Existing []string `json:"existing"` // Fingerprints that already exist
	Missing  []string `json:"missing"`  // Fingerprints that don't exist
}

// ChunkIngestRequest represents the request body for chunked ingestion.
// This is used by SDK when reports are too large for single upload.
type ChunkIngestRequest struct {
	ReportID    string `json:"report_id"`             // Unique ID for the chunked report
	ChunkIndex  int    `json:"chunk_index"`           // 0-indexed chunk number
	TotalChunks int    `json:"total_chunks"`          // Total number of chunks
	Compression string `json:"compression,omitempty"` // Compression algorithm (zstd, gzip, none)
	Data        string `json:"data"`                  // Base64-encoded chunk data
	IsFinal     bool   `json:"is_final"`              // True for the last chunk
}

// ChunkIngestResponse represents the response from chunk ingestion.
type ChunkIngestResponse struct {
	ChunkID         string `json:"chunk_id"`
	ReportID        string `json:"report_id"`
	ChunkIndex      int    `json:"chunk_index"`
	Status          string `json:"status"`
	AssetsCreated   int    `json:"assets_created"`
	AssetsUpdated   int    `json:"assets_updated"`
	FindingsCreated int    `json:"findings_created"`
	FindingsUpdated int    `json:"findings_updated"`
	FindingsSkipped int    `json:"findings_skipped"`
}

// =============================================================================
// Authentication Middleware
// =============================================================================

// AuthenticateSource is middleware that authenticates the sensor by API key.
//
// A disabled sensor is refused everywhere, as before, with one exception for
// the heartbeat doorbell (RFC-023 §9.2a): on POST /api/v1/agent/heartbeat, a
// disabled sensor that announced the doorbell feature is let through as
// paused, so the heartbeat can answer it with the typed pause action. The
// exception is matched on the exact path and method and is default-deny:
// every other route, and a sensor that did not opt in, still gets the v1 401.
func (h *IngestHandler) AuthenticateSource(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := extractAPIKey(r)
		if apiKey == "" {
			apierror.Unauthorized("API key required").WriteJSON(w)
			return
		}

		id, err := h.sensorService.AuthenticateIdentityFrom(r.Context(), apiKey, getClientIP(r))
		if err == nil && id.Paused && !(isHeartbeatRequest(r) && sensorHasFeature(r, legacyv1.FeatureDoorbell)) {
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

// errSensorPaused refuses a disabled sensor outside the doorbell exception.
var errSensorPaused = errors.New("sensor is disabled")

// isHeartbeatRequest reports whether r is the v1 heartbeat.
func isHeartbeatRequest(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == legacyv1.HeartbeatPath
}

// sensorHasFeature reports whether the sensor listed feature in the
// X-OpenCTEM-Sensor-Features request header.
func sensorHasFeature(r *http.Request, feature string) bool {
	for _, v := range r.Header.Values(legacyv1.HeaderSensorFeatures) {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), feature) {
				return true
			}
		}
	}
	return false
}

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

// requireSensorTenant verifies the authenticated sensor carries tenant context,
// writing a 403 and returning false for platform sensors (tenant_id NULL) that
// have no business performing these tenant-scoped operations. Mirrors the
// scansession handler's guard and prevents a nil-pointer deref of
// agt.TenantID (recovered as a 500) on the command / telemetry / chunk-ingest
// paths. Callers must return immediately when it returns false.
func requireSensorTenant(w http.ResponseWriter, agt *sensor.Sensor) bool {
	if agt.TenantID == nil {
		apierror.Forbidden(legacyv1.MsgTenantContextRequired).WriteJSON(w)
		return false
	}
	return true
}

// sensorTenantString returns the sensor's tenant ID as a string, or "" when the
// sensor has no tenant (platform sensor). For informational log/response fields
// where a missing tenant must not panic.
func sensorTenantString(agt *sensor.Sensor) string {
	if agt == nil || agt.TenantID == nil {
		return ""
	}
	return agt.TenantID.String()
}

// =============================================================================
// CTIS Ingestion Endpoint
// =============================================================================

// IngestCTIS handles POST /api/v1/agent/ingest/ctis
// @Summary      Ingest CTIS report
// @Description  Ingest a full CTIS (CTEM Ingest Schema) report containing assets and findings
// @Tags         Sensor
// @Accept       json
// @Produce      json
// @Param        request  body      CTISIngestRequest  true  "CTIS report"
// @Success      201  {object}  IngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/ctis [post]
func (h *IngestHandler) IngestCTIS(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}

	// Read body once for multiple parse attempts
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Debug("failed to read request body", "error", err)
		apierror.BadRequest("Failed to read request body").WriteJSON(w)
		return
	}

	// Async mode (RFC-005): persist the raw payload + enqueue, return 202.
	// Falls through to the synchronous path when async is off or the sensor has
	// no tenant context (platform sensors are validated by the sync path).
	//
	// Escape hatch (Phase 2): a sensor that can't yet handle 202 + polling can
	// force the legacy synchronous response even on an async-mode deployment via
	// ?sync=true or the `Prefer: respond-sync` header. This lets operators flip
	// INGEST_MODE=async globally while older sensors opt back to sync until the
	// fleet is updated.
	binding, ok := h.bindRequest(w, r, agt)
	if !ok {
		return
	}
	// A report bound to a command is processed synchronously: the queue
	// keeps no binding, and the command's lease is checked now.
	if h.asyncMode && h.ingestJobRepo != nil && agt.TenantID != nil && !clientWantsSync(r) && binding.Kind == ingest.BindingUnsolicited {
		h.enqueueAsync(w, r, agt, bodyBytes)
		return
	}

	var report ctis.Report

	// Try wrapped format first: { "report": { ... } }.
	// DisallowUnknownFields rejects fields outside the contract so an
	// sensor cannot smuggle auxiliary keys into the ingest payload.
	var req CTISIngestRequest
	wrappedDec := json.NewDecoder(bytes.NewReader(bodyBytes))
	wrappedDec.DisallowUnknownFields()
	if err := wrappedDec.Decode(&req); err == nil && req.Report.Version != "" {
		report = req.Report
	} else {
		// Try flat format (SDK format): { "version": ..., "metadata": ..., ... }
		flatDec := json.NewDecoder(bytes.NewReader(bodyBytes))
		flatDec.DisallowUnknownFields()
		if err := flatDec.Decode(&report); err != nil {
			h.logger.Debug("failed to parse CTIS ingest request", "error", err)
			apierror.BadRequest("Invalid JSON request body").WriteJSON(w)
			return
		}
	}

	// Validate report
	if report.Version == "" {
		report.Version = "1.0"
	}

	input := ingest.Input{
		Report:  &report,
		Options: ingest.Options{Binding: binding, Route: "ctis"},
	}

	output, err := h.ingestService.Ingest(r.Context(), agt, input)
	if err != nil {
		h.writeIngestError(w, "CTIS ingestion failed", err)
		return
	}

	resp := newIngestResponse(output)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// SARIF Ingestion Endpoint
// =============================================================================

// IngestSARIF handles POST /api/v1/agent/ingest/sarif
// @Summary      Ingest SARIF results
// @Description  Ingest scan results in SARIF 2.1.0 format
// @Tags         Sensor
// @Accept       json
// @Produce      json
// @Param        request         body      object  true   "SARIF data"
// @Param        repository_url  query     string  false  "Repository the log was produced from, when the log has no runs[].versionControlProvenance. Required in that case unless the artifact URIs name a github.com/gitlab.com/bitbucket.org repository."
// @Param        branch          query     string  false  "Branch that was scanned"
// @Param        commit_sha      query     string  false  "Commit that was scanned"
// @Success      201  {object}  IngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/sarif [post]
func (h *IngestHandler) IngestSARIF(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}

	// Read raw body for SARIF processing
	body, err := io.ReadAll(r.Body)
	if err != nil {
		apierror.BadRequest("Failed to read request body").WriteJSON(w)
		return
	}

	if len(body) == 0 {
		apierror.BadRequest("SARIF data is required").WriteJSON(w)
		return
	}

	binding, ok := h.bindRequest(w, r, agt)
	if !ok {
		return
	}
	q := r.URL.Query()
	output, err := h.ingestService.IngestSARIF(r.Context(), agt, body, ingest.SARIFRepository{
		URL:       q.Get("repository_url"),
		Branch:    q.Get("branch"),
		CommitSHA: q.Get("commit_sha"),
	}, binding)
	if errors.Is(err, shared.ErrValidation) {
		// The log or its repository parameters are unusable (see
		// ingest.ErrSARIFNoRepository): a 4xx the sensor can act on, not a 500.
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	if err != nil {
		h.writeIngestError(w, "SARIF ingestion failed", err)
		return
	}

	resp := newIngestResponse(output)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Recon Ingestion Endpoint
// =============================================================================

// IngestReconReport handles POST /api/v1/agent/ingest/recon
// @Summary      Ingest recon results
// @Description  Ingest reconnaissance scan results (subdomains, DNS, ports, etc.)
// @Tags         Sensor
// @Accept       json
// @Produce      json
// @Param        request  body      ReconIngestRequest  true  "Recon results"
// @Success      201  {object}  IngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/recon [post]
func (h *IngestHandler) IngestReconReport(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}

	var req ReconIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("failed to parse recon ingest request", "error", err)
		apierror.BadRequest("Invalid JSON request body").WriteJSON(w)
		return
	}

	// Validate required fields
	if req.Target == "" {
		apierror.BadRequest("Target is required").WriteJSON(w)
		return
	}
	if req.ScannerName == "" {
		apierror.BadRequest("Scanner name is required").WriteJSON(w)
		return
	}

	binding, ok := h.bindRequest(w, r, agt)
	if !ok {
		return
	}

	// Convert recon request to CTIS input
	reconInput := h.buildReconToCTISInput(&req)

	output, err := h.ingestService.IngestRecon(r.Context(), agt, reconInput, binding)
	if err != nil {
		h.writeIngestError(w, "recon ingestion failed", err)
		return
	}

	resp := newIngestResponse(output)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Heartbeat Endpoint
// =============================================================================

// Heartbeat handles POST /api/v1/agent/heartbeat
// @Summary      Sensor heartbeat
// @Description  Send a heartbeat to indicate sensor is alive. The response is also a doorbell (RFC-023 §9.2a): pending_jobs > 0 means poll GET /agent/commands now; next_heartbeat_seconds is the advised interval; actions are typed directives (pause, resume, drain, rotate_key, update). A sensor that sends X-OpenCTEM-Sensor-Features: doorbell also gets config_version and, while disabled, a 200 with the pause action instead of a 401.
// @Tags         Sensor
// @Accept       json
// @Produce      json
// @Param        X-OpenCTEM-Sensor-Features  header  string  false  "Optional protocol features, comma-separated (doorbell)"
// @Param        request  body      HeartbeatRequest  false  "Heartbeat data"
// @Success      200  {object}  legacyv1.Heartbeat
// @Failure      401  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/heartbeat [post]
func (h *IngestHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}
	id := sensorIdentityFromContext(r.Context())

	// Parse heartbeat request (optional body)
	var req HeartbeatRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.logger.Debug("failed to parse heartbeat body", "error", err)
			// Continue anyway - body is optional
		}
	}

	start := time.Now()
	defer func() { h.observeHeartbeat(time.Since(start)) }()

	resp := legacyv1.Heartbeat{
		SensorID: agt.ID.String(),
		Status:   "ok",
		TenantID: sensorTenantString(agt), // "" for tenant-less platform sensors
	}

	// Doorbell hints (RFC-023 §9.2a). Ring never fails; with nothing to say
	// every field stays zero and the response is the plain v1 one. It rings
	// before the write so the write stores the deadline of the interval
	// just advised (RFC-035 §5.6).
	aware := sensorHasFeature(r, legacyv1.FeatureDoorbell)
	var hints sensor.HeartbeatHints
	if h.doorbell != nil {
		hints = h.doorbell.Ring(r.Context(), app.DoorbellRequest{Identity: id, Aware: aware})
	}

	// Update sensor metrics via service. A paused (disabled) sensor is only
	// told to pause: it does not come online and its row is not written.
	if !id.Paused {
		data := heartbeatData(r, &req, 1)
		data.AdvisedSeconds, data.DoorbellAware = hints.NextHeartbeatSeconds, aware
		if err := h.sensorService.UpdateHeartbeat(r.Context(), agt.ID, data); err != nil {
			h.logger.Error("failed to update sensor heartbeat", "error", err, "sensor_id", agt.ID)
			// Don't fail the request - heartbeat should be resilient
		}
	}

	if h.doorbell != nil {
		resp.PendingJobs = hints.PendingJobs
		resp.ConfigVersion = hints.ConfigVersion
		resp.NextHeartbeatSeconds = hints.NextHeartbeatSeconds
		for _, a := range hints.Actions {
			resp.Actions = append(resp.Actions, string(a))
		}
	}

	if ids := h.commandsToCancel(r.Context(), agt, &req); len(ids) > 0 {
		resp.CancelCommandIDs = ids
		resp.Actions = append(resp.Actions, protov2.ActionCancel)
	}

	// Discovery of v2 results (RFC-026 WP-A7, RFC-023 C3): only for a sensor
	// that asked, so a deployed v1 sensor's response is unchanged.
	if h.v2Advertised && protov2.HasFeature(r.Header.Values(legacyv1.HeaderSensorFeatures), protov2.FeatureResultsV2) {
		w.Header().Set(protov2.HeaderProtocolAdvert, strconv.Itoa(protov2.ProtocolVersion))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

// RenewKeyResponse is returned by the sensor self-renew endpoint. The new key is
// shown once, exactly like creation/regeneration — the server stores only its hash.
// ExpiresAt is when the new key stops authenticating (nil/omitted = never
// expires); the sensor uses it to schedule its next renewal.
type RenewKeyResponse struct {
	APIKey    string     `json:"api_key"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// RenewKey handles POST /api/v1/agent/renew
// @Summary      Renew sensor API key (self-service)
// @Description  Rotate the calling sensor's own API key. Authenticated by the current key; returns a fresh key shown once. The building block for auto-rotating credentials (kubelet-style).
// @Tags         Sensor
// @Accept       json
// @Produce      json
// @Success      200  {object}  RenewKeyResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/renew [post]
func (h *IngestHandler) RenewKey(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}

	// The identity says which key was presented; renewal retires that key.
	newKey, expiresAt, err := h.sensorService.RenewAPIKey(r.Context(), sensorIdentityFromContext(r.Context()))
	if err != nil {
		if errors.Is(err, shared.ErrForbidden) {
			// Disabled/revoked in the auth→renew window. Generic message; log specifics.
			h.logger.Debug("sensor key renewal refused", "sensor_id", agt.ID.String(), "error", err)
			apierror.Forbidden(legacyv1.MsgCannotRenew).WriteJSON(w)
			return
		}
		h.logger.Error("sensor key renewal failed", "sensor_id", agt.ID.String(), "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&RenewKeyResponse{APIKey: newKey, ExpiresAt: expiresAt})
}

// =============================================================================
// Fingerprint Check Endpoint
// =============================================================================

// CheckFingerprints handles POST /api/v1/ingest/check
// @Summary      Check fingerprints
// @Description  Check if fingerprints already exist for deduplication
// @Tags         Sensor
// @Accept       json
// @Produce      json
// @Param        request  body      CheckFingerprintsRequest  true  "Fingerprints to check"
// @Success      200  {object}  CheckFingerprintsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/check [post]
func (h *IngestHandler) CheckFingerprints(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}

	var req CheckFingerprintsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if len(req.Fingerprints) == 0 {
		// Return empty response for empty input
		resp := CheckFingerprintsResponse{
			Existing: []string{},
			Missing:  []string{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	output, err := h.ingestService.CheckFingerprints(r.Context(), agt, ingest.CheckFingerprintsInput{
		Fingerprints: req.Fingerprints,
	})
	if err != nil {
		h.logger.Error("fingerprint check failed", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := CheckFingerprintsResponse{
		Existing: output.Existing,
		Missing:  output.Missing,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// BaselineDiffRequest asks which fingerprints are new vs a PR's base branch.
type BaselineDiffRequest struct {
	Repository   string   `json:"repository"`
	BaseBranch   string   `json:"base_branch"`
	Fingerprints []string `json:"fingerprints"`
}

// NewVsBase handles POST /api/v1/agent/ingest/new-vs-base
// @Summary      New-vs-base-branch findings
// @Description  Given the current scan's fingerprints + a PR base/target branch,
// @Description  returns which are NEW (not already open on the base branch) so a
// @Description  PR gate / inline comments focus only on findings the PR introduces.
// @Tags         Sensor
// @Accept       json
// @Produce      json
// @Param        request  body      BaselineDiffRequest  true  "Repository, base branch, fingerprints"
// @Success      200  {object}  ingest.BaselineDiffOutput
// @Router       /agent/ingest/baseline-diff [post]
func (h *IngestHandler) BaselineDiff(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}

	var req BaselineDiffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	out, err := h.ingestService.BaselineDiff(r.Context(), agt, ingest.BaselineDiffInput{
		Repository:   req.Repository,
		BaseBranch:   req.BaseBranch,
		Fingerprints: req.Fingerprints,
	})
	if err != nil {
		h.logger.Error("new-vs-base check failed", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// =============================================================================
// Chunked Ingestion Endpoint
// =============================================================================

// IngestChunk handles POST /api/v1/agent/ingest/chunk
// @Summary      Ingest CTIS report chunk
// @Description  Ingest a single chunk of a large CTIS report. Used for reports that exceed single upload limits.
// @Tags         Sensor
// @Accept       json
// @Produce      json
// @Param        request  body      ChunkIngestRequest  true  "Chunk data"
// @Success      201  {object}  ChunkIngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/chunk [post]
//
//nolint:cyclop // Chunk ingestion requires handling many result types
func (h *IngestHandler) IngestChunk(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}
	if !requireSensorTenant(w, agt) {
		return
	}

	var req ChunkIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("failed to parse chunk ingest request", "error", err)
		apierror.BadRequest("Invalid JSON request body").WriteJSON(w)
		return
	}

	// SECURITY: Define limits to prevent DoS attacks
	const (
		MaxTotalChunks   = 10000            // Maximum chunks per report
		MaxChunkDataSize = 10 * 1024 * 1024 // 10MB base64 data per chunk
		MaxReportIDLen   = 256              // Maximum report ID length
	)

	// Validate required fields with security bounds
	if req.ReportID == "" {
		apierror.BadRequest("report_id is required").WriteJSON(w)
		return
	}
	if len(req.ReportID) > MaxReportIDLen {
		apierror.BadRequest("report_id too long").WriteJSON(w)
		return
	}

	// SECURITY: Validate ReportID format to prevent injection
	// Must be alphanumeric with dashes/underscores only
	for _, c := range req.ReportID {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			apierror.BadRequest("report_id contains invalid characters").WriteJSON(w)
			return
		}
	}

	if req.TotalChunks <= 0 {
		apierror.BadRequest("total_chunks must be positive").WriteJSON(w)
		return
	}
	// SECURITY: Prevent unbounded chunk allocation
	if req.TotalChunks > MaxTotalChunks {
		apierror.BadRequest("total_chunks exceeds maximum of 10000").WriteJSON(w)
		return
	}
	if req.ChunkIndex < 0 || req.ChunkIndex >= req.TotalChunks {
		apierror.BadRequest("chunk_index out of range").WriteJSON(w)
		return
	}
	if req.Data == "" {
		apierror.BadRequest("data is required").WriteJSON(w)
		return
	}
	// SECURITY: Limit chunk data size to prevent memory exhaustion
	if len(req.Data) > MaxChunkDataSize {
		apierror.BadRequest("chunk data too large").WriteJSON(w)
		return
	}

	// Decode base64 data
	compressedData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		h.logger.Debug("failed to decode base64 data", "error", err)
		apierror.BadRequest("Invalid base64 data").WriteJSON(w)
		return
	}

	decompressedData, err := decompressChunk(req.Compression, compressedData)
	if err != nil {
		if errors.Is(err, errUnsupportedChunkCompression) {
			apierror.BadRequest("Unsupported compression algorithm: " + sanitizeLogField(req.Compression)).WriteJSON(w)
			return
		}
		if errors.Is(err, errChunkTooLarge) {
			h.logger.Warn("chunk exceeds decompression cap", "cap", maxChunkDecompressed)
			apierror.BadRequest("Chunk exceeds decompression size limit").WriteJSON(w)
			return
		}
		h.logger.Debug("failed to decompress chunk", "error", err)
		apierror.BadRequest("Failed to decompress chunk data").WriteJSON(w)
		return
	}

	// Unmarshal chunk data
	var chunkData ChunkData
	if err := json.Unmarshal(decompressedData, &chunkData); err != nil {
		h.logger.Debug("failed to unmarshal chunk data", "error", err)
		apierror.BadRequest("Invalid chunk data format").WriteJSON(w)
		return
	}

	// Build CTIS report from chunk data
	report := &ctis.Report{
		Version:  "1.0",
		Assets:   chunkData.Assets,
		Findings: chunkData.Findings,
	}

	// Only set Tool and Metadata on first chunk
	if chunkData.Tool != nil {
		report.Tool = chunkData.Tool
	}
	if chunkData.Metadata != nil {
		report.Metadata = *chunkData.Metadata
	}

	// If metadata ID is empty, use the report ID from chunk
	if report.Metadata.ID == "" {
		report.Metadata.ID = req.ReportID
	}

	binding, ok := h.bindRequest(w, r, agt)
	if !ok {
		return
	}

	// Process the chunk through normal ingestion
	input := ingest.Input{
		Report:  report,
		Options: ingest.Options{Binding: binding, Route: "chunk"},
	}

	output, err := h.ingestService.Ingest(r.Context(), agt, input)
	if err != nil {
		h.writeIngestError(w, "chunk ingestion failed", err,
			"report_id", sanitizeLogField(req.ReportID),
			"chunk_index", req.ChunkIndex,
		)
		return
	}

	// AUDIT: Log chunk ingestion with full context for security monitoring
	h.logger.Info("chunk ingested successfully",
		"report_id", req.ReportID,
		"chunk_index", req.ChunkIndex,
		"total_chunks", req.TotalChunks,
		"is_final", req.IsFinal,
		"assets_created", output.AssetsCreated,
		"findings_created", output.FindingsCreated,
		"sensor_id", agt.ID.String(),
		"tenant_id", agt.TenantID.String(),
		"compressed_size", len(compressedData),
		"decompressed_size", len(decompressedData),
	)

	resp := ChunkIngestResponse{
		ChunkID:         uuid.New().String(),
		ReportID:        req.ReportID,
		ChunkIndex:      req.ChunkIndex,
		Status:          "accepted",
		AssetsCreated:   output.AssetsCreated,
		AssetsUpdated:   output.AssetsUpdated,
		FindingsCreated: output.FindingsCreated,
		FindingsUpdated: output.FindingsUpdated,
		FindingsSkipped: output.FindingsSkipped,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Helper Functions
// =============================================================================

// writeIngestError answers an ingest failure. A payload the sensor got wrong
// (not parseable, over the report limits) is a 4xx: a 500 would log an error
// for every bad push and make the sensor's retry queue re-send a request that
// can never succeed. Anything else is a server fault.
//
// Parser errors can quote fragments of the sensor's payload, so the error is
// stripped of line breaks and capped before it reaches the log or the
// response: a sensor must not be able to forge log lines. Callers pass attrs
// already sanitized (sanitizeLogField) for any sensor-supplied string.
func (h *IngestHandler) writeIngestError(w http.ResponseWriter, msg string, err error, attrs ...any) {
	errText := sanitizeLogField(err.Error())
	logAttrs := make([]any, 0, len(attrs)+2)
	logAttrs = append(logAttrs, "error", errText)
	// Callers already sanitize sensor-supplied strings; re-sanitizing every
	// string attr here keeps the guarantee local instead of per call site.
	for _, a := range attrs {
		if s, ok := a.(string); ok {
			a = sanitizeLogField(s)
		}
		logAttrs = append(logAttrs, a)
	}

	var (
		de *shared.DomainError
		qe *ingest.QuarantinedError
	)
	switch {
	case errors.As(err, &qe):
		// Not an error of the sensor's payload: it was stored for review.
		// 422, not 403: sensor SDKs read 401/403 as a key they lost.
		h.logger.Info(msg+": quarantined", "quarantine_id", qe.ID.String())
		apierror.New(http.StatusUnprocessableEntity, ingest.CodeResultsQuarantined, qe.Error()).
			WithDetails(map[string]string{"quarantine_id": qe.ID.String()}).WriteJSON(w)
	case errors.Is(err, sensorresult.ErrFull):
		h.logger.Warn(msg + ": quarantine full")
		apierror.New(http.StatusUnprocessableEntity, "RESULTS_QUARANTINE_FULL",
			"This sensor's role may not send results without a command assigned to it, and the results quarantine is full: the report was refused.").WriteJSON(w)
	case errors.As(err, &de) && de.Code == ingest.CodeCommandNotFound:
		// Fixed messages only: the sensor-supplied parts are not logged.
		h.logger.Warn(msg + ": command not found")
		apierror.New(http.StatusNotFound, ingest.CodeCommandNotFound, de.Message).WriteJSON(w)
	case errors.As(err, &de) && de.Code == ingest.CodeToolNotPermitted:
		h.logger.Warn(msg + ": tool not permitted")
		apierror.New(http.StatusUnprocessableEntity, ingest.CodeToolNotPermitted, de.Message).WriteJSON(w)
	case errors.As(err, &de) && de.Code == ingest.CodePayloadTooLarge:
		h.logger.Warn(msg, logAttrs...)
		apierror.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		h.logger.Warn(msg, logAttrs...)
		apierror.BadRequest("Invalid report: " + errText).WriteJSON(w)
	default:
		h.logger.Error(msg, logAttrs...)
		apierror.InternalError(err).WriteJSON(w)
	}
}

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

// buildReconToCTISInput converts handler request to CTIS input.
func (h *IngestHandler) buildReconToCTISInput(req *ReconIngestRequest) *ctis.ReconToCTISInput {
	ctisInput := &ctis.ReconToCTISInput{
		ScannerName:    req.ScannerName,
		ScannerVersion: req.ScannerVersion,
		ReconType:      req.ReconType,
		Target:         req.Target,
		StartedAt:      req.StartedAt,
		FinishedAt:     req.FinishedAt,
		DurationMs:     req.DurationMs,
	}

	// Convert subdomains
	for _, sub := range req.Subdomains {
		ctisInput.Subdomains = append(ctisInput.Subdomains, ctis.SubdomainInput{
			Host:   sub.Host,
			Domain: sub.Domain,
			Source: sub.Source,
			IPs:    sub.IPs,
		})
	}

	// Convert DNS records
	for _, rec := range req.DNSRecords {
		ctisInput.DNSRecords = append(ctisInput.DNSRecords, ctis.DNSRecordInput{
			Host:       rec.Host,
			RecordType: rec.RecordType,
			Values:     rec.Values,
			TTL:        rec.TTL,
			Resolver:   rec.Resolver,
			StatusCode: rec.StatusCode,
		})
	}

	// Convert open ports
	for _, port := range req.OpenPorts {
		ctisInput.OpenPorts = append(ctisInput.OpenPorts, ctis.OpenPortInput{
			Host:     port.Host,
			IP:       port.IP,
			Port:     port.Port,
			Protocol: port.Protocol,
			Service:  port.Service,
			Version:  port.Version,
			Banner:   port.Banner,
		})
	}

	// Convert live hosts
	for _, host := range req.LiveHosts {
		ctisInput.LiveHosts = append(ctisInput.LiveHosts, ctis.LiveHostInput{
			URL:           host.URL,
			Host:          host.Host,
			IP:            host.IP,
			Port:          host.Port,
			Scheme:        host.Scheme,
			StatusCode:    host.StatusCode,
			ContentLength: host.ContentLength,
			Title:         host.Title,
			WebServer:     host.WebServer,
			ContentType:   host.ContentType,
			Technologies:  host.Technologies,
			CDN:           host.CDN,
			TLSVersion:    host.TLSVersion,
			Redirect:      host.Redirect,
			ResponseTime:  host.ResponseTime,
		})
	}

	// Convert discovered URLs
	for _, url := range req.URLs {
		ctisInput.URLs = append(ctisInput.URLs, ctis.DiscoveredURLInput{
			URL:        url.URL,
			Method:     url.Method,
			Source:     url.Source,
			StatusCode: url.StatusCode,
			Depth:      url.Depth,
			Parent:     url.Parent,
			Type:       url.Type,
			Extension:  url.Extension,
		})
	}

	return ctisInput
}

// =============================================================================
// Raw Scanner Output Ingestion Endpoint
// =============================================================================

// ScanIngestRequest represents the request body for raw scanner output ingestion.
type ScanIngestRequest struct {
	// Scanner type: vuls, trivy, nuclei, semgrep, betterleaks (required if auto-detect fails)
	ScannerType string `json:"scanner_type,omitempty"`

	// Raw scanner output data
	Data json.RawMessage `json:"data"`
}

// ScannerListResponse lists supported scanner adapters.
type ScannerListResponse struct {
	Scanners []string `json:"scanners"`
}

// IngestScan handles POST /api/v1/agent/ingest/scan
// It accepts raw scanner output and uses the appropriate adapter to convert to CTIS.
func (h *IngestHandler) IngestScan(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Debug("failed to read request body", "error", err)
		apierror.BadRequest("Failed to read request body").WriteJSON(w)
		return
	}

	if len(bodyBytes) == 0 {
		apierror.BadRequest("Request body is required").WriteJSON(w)
		return
	}

	// Try to parse as wrapped format: { "scanner_type": "...", "data": {...} }
	var req ScanIngestRequest
	var scannerType string
	var scanData []byte

	if err := json.Unmarshal(bodyBytes, &req); err == nil && len(req.Data) > 0 {
		scannerType = req.ScannerType
		scanData = req.Data
	} else {
		// Treat entire body as raw scanner output (auto-detect mode)
		scanData = bodyBytes
		// Check query param for scanner type hint
		scannerType = r.URL.Query().Get("scanner_type")
	}

	// Pick the adapter once, so the SARIF check below and the conversion
	// agree on what the payload is.
	if scannerType == "" {
		if a, ok := h.adapterRegistry.AutoDetect(scanData); ok {
			scannerType = a.Name()
		}
	}

	// Convert using adapter registry
	report, err := h.adapterRegistry.Convert(r.Context(), scannerType, scanData, &core.AdapterOptions{})
	if err != nil {
		// The adapter error can quote parser internals and fragments of the
		// submitted payload; keep it server-side and return a generic message.
		h.logger.Warn("scanner adapter conversion failed",
			"error", sanitizeLogField(err.Error()), "scanner_type", sanitizeLogField(scannerType))
		apierror.BadRequest("Failed to convert scanner output").WriteJSON(w)
		return
	}

	// SARIF carries no asset of its own: file it under the repository it was
	// produced from (same rules as /ingest/sarif) rather than the shared
	// per-tool fallback asset, where unrelated repositories would merge.
	if strings.EqualFold(scannerType, "sarif") {
		q := r.URL.Query()
		if err := ingest.AttachSARIFRepository(report, scanData, ingest.SARIFRepository{
			URL:       q.Get("repository_url"),
			Branch:    q.Get("branch"),
			CommitSHA: q.Get("commit_sha"),
		}); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}

	binding, ok := h.bindRequest(w, r, agt)
	if !ok {
		return
	}

	// Ingest the converted CTIS report
	input := ingest.Input{
		Report:  report,
		Options: ingest.Options{Binding: binding, Route: "scan"},
	}

	output, err := h.ingestService.Ingest(r.Context(), agt, input)
	if err != nil {
		h.writeIngestError(w, "scan ingestion failed", err, "scanner_type", sanitizeLogField(scannerType))
		return
	}

	resp := newIngestResponse(output)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// ListScanners handles GET /api/v1/agent/ingest/scanners
// It returns the list of supported scanner adapters.
func (h *IngestHandler) ListScanners(w http.ResponseWriter, r *http.Request) {
	resp := ScannerListResponse{
		Scanners: h.adapterRegistry.List(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// clientWantsSync reports whether the caller explicitly opted out of async
// processing (RFC-005 Phase 2 escape hatch) via ?sync=true or
// `Prefer: respond-sync`. Used so an async-mode deployment can still serve
// sensors that haven't learned to poll for job status yet.
func clientWantsSync(r *http.Request) bool {
	if v := strings.TrimSpace(r.URL.Query().Get("sync")); v == "true" || v == "1" {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Prefer")), "respond-sync")
}

// AsyncIngestResponse is the 202 body returned when async ingest is enabled.
type AsyncIngestResponse struct {
	JobID     string `json:"job_id"`
	Status    string `json:"status"`
	ReportID  string `json:"report_id"`
	Duplicate bool   `json:"duplicate"` // true if an identical payload was already queued
}

// enqueueAsync validates the envelope, persists the raw payload, enqueues an
// ingest job, and returns 202. The worker (controller.IngestWorkerController)
// processes it. agt.TenantID is guaranteed non-nil by the caller.
func (h *IngestHandler) enqueueAsync(w http.ResponseWriter, r *http.Request, agt *sensor.Sensor, bodyBytes []byte) {
	ctx := r.Context()
	tenantID := *agt.TenantID

	// Queue-depth backpressure: a tenant with too many unprocessed jobs is told
	// to back off rather than letting payload rows pile up unbounded.
	if h.maxPendingPerTenant > 0 {
		if pending, err := h.ingestJobRepo.CountPendingByTenant(ctx, tenantID); err == nil && pending >= h.maxPendingPerTenant {
			w.Header().Set("Retry-After", "30")
			apierror.TooManyRequests("ingest queue is full for this tenant; retry later").WriteJSON(w)
			return
		}
	}

	// Cheap envelope validation: must be a parseable CTIS report. (Full
	// correctness is re-checked by the worker via the same pipeline.)
	report, err := ingest.ParseReport(bodyBytes)
	if err != nil {
		apierror.BadRequest("Invalid CTIS payload").WriteJSON(w)
		return
	}

	// The unsolicited gate (RFC-040 §5.3) runs before queuing: a report the
	// tenant quarantines is stored for review and never queued.
	if h.ingestService == nil {
		apierror.InternalServerError("ingest is not configured").WriteJSON(w)
		return
	}
	if err := h.ingestService.AdmitQueued(ctx, agt, report); err != nil {
		h.writeIngestError(w, "CTIS ingestion refused", err)
		return
	}

	job := ingestjob.NewJob(tenantID, &agt.ID, report.Metadata.ID, report.Metadata.SourceType, bodyBytes)
	stored, created, err := h.ingestJobRepo.Enqueue(ctx, job)
	if err != nil {
		h.logger.Error("failed to enqueue ingest job", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	dupLabel := "false"
	if !created {
		dupLabel = "true"
	}
	metrics.IngestJobsEnqueuedTotal.WithLabelValues(dupLabel).Inc()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", legacyv1.IngestJobLocation(stored.ID().String()))
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(AsyncIngestResponse{
		JobID:     stored.ID().String(),
		Status:    stored.Status().String(),
		ReportID:  stored.ReportID(),
		Duplicate: !created,
	})
}

// IngestJobStatusResponse is the body of the job-status poll endpoint.
type IngestJobStatusResponse struct {
	JobID    string          `json:"job_id"`
	Status   string          `json:"status"`
	ReportID string          `json:"report_id"`
	Attempts int             `json:"attempts"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// GetIngestJob returns the status of an async ingest job (RFC-005 status poll).
// GET /api/v1/agent/ingest/jobs/{id} — API-key auth, tenant-scoped.
func (h *IngestHandler) GetIngestJob(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil || agt.TenantID == nil {
		apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
		return
	}
	if h.ingestJobRepo == nil {
		apierror.NotFound("ingest job").WriteJSON(w)
		return
	}

	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid job id").WriteJSON(w)
		return
	}

	job, err := h.ingestJobRepo.GetByID(r.Context(), *agt.TenantID, id)
	// A sensor reads only the jobs it queued (RFC-040 §5.3); another
	// sensor's job is not found.
	if err != nil || job.SensorID() == nil || *job.SensorID() != agt.ID {
		apierror.NotFound("ingest job").WriteJSON(w)
		return
	}

	resp := IngestJobStatusResponse{
		JobID:    job.ID().String(),
		Status:   job.Status().String(),
		ReportID: job.ReportID(),
		Attempts: job.Attempts(),
		Error:    job.LastError(),
	}
	if len(job.Result()) > 0 {
		resp.Result = json.RawMessage(job.Result())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// maxChunkDecompressed caps a chunk's decompressed size. 64 MiB is more than
// any legitimate ingest chunk.
const maxChunkDecompressed = 64 << 20

var (
	errChunkTooLarge               = errors.New("chunk exceeds decompression size limit")
	errUnsupportedChunkCompression = errors.New("unsupported chunk compression")
)

// decompressChunk expands an ingest chunk with a hard cap on the output, so a
// highly compressible payload (a zstd or gzip "bomb") cannot expand to
// gigabytes in memory. Every codec is read as a stream through a LimitReader
// and the decoder's own memory is bounded too: zstd's DecodeAll would allocate
// the full frame (a 16 KB frame expands to 512 MiB) before any size check.
func decompressChunk(compression string, data []byte) ([]byte, error) {
	var r io.Reader
	switch strings.ToLower(compression) {
	case "zstd", "":
		dec, err := zstd.NewReader(bytes.NewReader(data),
			zstd.WithDecoderMaxMemory(maxChunkDecompressed),
			zstd.WithDecoderMaxWindow(maxChunkDecompressed),
			zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		defer dec.Close()
		r = dec
	case "gzip":
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	case "none":
		if len(data) > maxChunkDecompressed {
			return nil, errChunkTooLarge
		}
		return data, nil
	default:
		return nil, errUnsupportedChunkCompression
	}
	out, err := io.ReadAll(io.LimitReader(r, maxChunkDecompressed+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxChunkDecompressed {
		return nil, errChunkTooLarge
	}
	return out, nil
}
