// Package legacyv1 is the only place the API still speaks the pre-sensor
// "agent" vocabulary (RFC-023 §9.5).
//
// Two surfaces keep it, both because something already deployed depends on
// the exact bytes:
//
//   - Sensor protocol v1: every sensor and SDK in the field calls
//     /api/v1/agent/*, reads "agent_id" from the responses and
//     "agent_preference" from job payloads, and may still label its own
//     discoveries "agent". Protocol v1 is frozen (RFC-023 §9.2 C1); it is
//     retired by raising the minimum sensor protocol, not by renaming.
//   - The deprecated management path /api/v1/agents, which answers with a
//     308 redirect to /api/v1/sensors until its sunset date.
//
// Everything else in the code base uses sensor terms. A CI rule
// (tools/lint/sensorvocab) fails on agent-vocabulary identifiers outside the
// allow-listed places, this package first among them; the golden test
// internal/infra/http/handler/protocol_v1_golden_db_test.go proves the v1 wire
// is byte-for-byte what it was before the rename.
package legacyv1

import (
	"encoding/json"
	"time"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/scansession"
)

// Protocol v1 mounts. Route registration and the AST-based route tooling
// (tools/lint/openapicontract, tests/unit/route_authz_coverage_test.go) read
// these through Paths.
const (
	// PathPrefix is the sensor protocol v1 mount (sensor API-key auth).
	PathPrefix = "/api/v1/agent"
	// CredentialsPathPrefix is the v1 credential-leak ingest mount.
	CredentialsPathPrefix = "/api/v1/agent/credentials"
	// HeartbeatPath is the v1 heartbeat. A disabled sensor that announced the
	// doorbell feature may reach this one path, to be told to pause.
	HeartbeatPath = "/api/v1/agent/heartbeat"
	// SuppressionsPath lists the active suppression rules of the sensor's
	// tenant for the sensor-side security gate. An ADDITIVE v1 route (RFC-023
	// §9.2): the SDK used to call the user route /api/v1/suppressions/active
	// with its sensor key, which always answered 401, so suppressions never
	// reached the gate. A server without it answers 404; a sensor treats that
	// like "no rules".
	SuppressionsPath = "/api/v1/agent/suppressions"
	// ingestJobsPath is where an async ingest job is polled (RFC-005).
	ingestJobsPath = "/api/v1/agent/ingest/jobs/"
)

// Paths maps the exported path constants by name, for tools that resolve
// `legacyv1.X` route arguments from source.
var Paths = map[string]string{
	"PathPrefix":              PathPrefix,
	"CredentialsPathPrefix":   CredentialsPathPrefix,
	"ManagementPathPrefix":    ManagementPathPrefix,
	"ManagementSuccessorPath": ManagementSuccessorPath,
}

// IngestJobLocation is the Location header of a 202 async ingest response.
func IngestJobLocation(jobID string) string { return ingestJobsPath + jobID }

// Error messages v1 handlers return. Unchanged since before the rename so a
// sensor that matches on them keeps working.
const (
	MsgNotAuthenticated      = "Agent not authenticated"
	MsgCannotRenew           = "Agent cannot renew"
	MsgTenantContextRequired = "Platform agents require tenant context for this operation"
	MsgJobContextRequired    = "Platform agents require job context for this operation"
)

// PayloadKeySensorPreference is the job-payload key deployed sensors read for
// the sensor selection mode (auto | tenant | platform).
const PayloadKeySensorPreference = "agent_preference"

// discoverySourceV1 is how v1 sensors (and the ctis recon converter they
// embed) label assets they discovered themselves.
const discoverySourceV1 = "agent"

// DiscoverySourceSensor is the stored value for "discovered by a sensor".
const DiscoverySourceSensor = "sensor"

// NormalizeDiscoverySource maps the v1 label onto the stored value; any other
// value passes through unchanged.
func NormalizeDiscoverySource(s string) string {
	if s == discoverySourceV1 {
		return DiscoverySourceSensor
	}
	return s
}

// Heartbeat is the v1 heartbeat response. Field order matches the sorted map
// keys the handler encoded before the rename, so the bytes are identical.
//
// The doorbell fields after TenantID are an additive v1 extension (RFC-023
// §9.2a). All are omitempty, so a heartbeat with nothing to say is
// byte-identical to the v1 response; a client that ignores the body, like
// sdk-go v0.6.0, is unaffected either way.
type Heartbeat struct {
	SensorID string `json:"agent_id"`
	Status   string `json:"status"`
	TenantID string `json:"tenant_id"`

	// PendingJobs is how many commands this sensor could claim right now
	// (capped at 100): poll GET /api/v1/agent/commands when it is > 0.
	PendingJobs int `json:"pending_jobs,omitempty"`
	// ConfigVersion is an opaque digest of what the platform governs about
	// the sensor; it changes when that changes. Sent to doorbell-aware
	// sensors only.
	ConfigVersion string `json:"config_version,omitempty"`
	// Actions are typed control directives from a closed set: pause,
	// resume, drain, rotate_key, update. Never free-form text.
	Actions []string `json:"actions,omitempty"`
	// NextHeartbeatSeconds is the server-advised interval to the next
	// heartbeat, already bounded by the server.
	NextHeartbeatSeconds int `json:"next_heartbeat_seconds,omitempty"`
}

// HeaderSensorFeatures is the request header a sensor lists its optional
// protocol features in (comma-separated, case-insensitive).
const HeaderSensorFeatures = "X-OpenCTEM-Sensor-Features"

// FeatureDoorbell announces that the sensor acts on the heartbeat doorbell.
// It opts the sensor into the hints that would otherwise change the v1
// response of an idle or disabled sensor: config_version and the idle
// next_heartbeat_seconds on every heartbeat, and a 200 with the pause action
// instead of a 401 while the sensor is disabled.
const FeatureDoorbell = "doorbell"

// Command is the v1 shape of a command (poll, acknowledge, start, complete,
// fail).
type Command struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id,omitempty"`
	SensorID       string          `json:"agent_id,omitempty"`
	Type           string          `json:"type"`
	Priority       string          `json:"priority"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	Status         string          `json:"status"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
}

// NewCommand converts a domain command to its v1 wire shape.
func NewCommand(c *command.Command) Command {
	out := Command{
		ID:             c.ID.String(),
		TenantID:       c.TenantID.String(),
		Type:           string(c.Type),
		Priority:       string(c.Priority),
		Payload:        c.Payload,
		Status:         string(c.Status),
		ErrorMessage:   c.ErrorMessage,
		CreatedAt:      c.CreatedAt,
		ExpiresAt:      c.ExpiresAt,
		AcknowledgedAt: c.AcknowledgedAt,
		StartedAt:      c.StartedAt,
		CompletedAt:    c.CompletedAt,
		Result:         c.Result,
	}
	if c.SensorID != nil {
		out.SensorID = c.SensorID.String()
	}
	return out
}

// NewCommands converts a poll result.
func NewCommands(cmds []*command.Command) []Command {
	out := make([]Command, len(cmds))
	for i, c := range cmds {
		out[i] = NewCommand(c)
	}
	return out
}

// ScanSession is the v1 shape of GET /api/v1/agent/scans/{id}.
type ScanSession struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id,omitempty"`
	SensorID       string         `json:"agent_id,omitempty"`
	ScannerName    string         `json:"scanner_name"`
	ScannerVersion string         `json:"scanner_version,omitempty"`
	ScannerType    string         `json:"scanner_type,omitempty"`
	AssetType      string         `json:"asset_type"`
	AssetValue     string         `json:"asset_value"`
	AssetID        string         `json:"asset_id,omitempty"`
	CommitSha      string         `json:"commit_sha,omitempty"`
	Branch         string         `json:"branch,omitempty"`
	BaseCommitSha  string         `json:"base_commit_sha,omitempty"`
	Status         string         `json:"status"`
	ErrorMessage   string         `json:"error_message,omitempty"`
	FindingsTotal  int            `json:"findings_total"`
	FindingsNew    int            `json:"findings_new"`
	FindingsFixed  int            `json:"findings_fixed"`
	FindingsBySev  map[string]int `json:"findings_by_severity,omitempty"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	DurationMs     int64          `json:"duration_ms,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

// NewScanSession converts a domain scan session to its v1 wire shape.
func NewScanSession(s *scansession.ScanSession) ScanSession {
	out := ScanSession{
		ID:             s.ID.String(),
		TenantID:       s.TenantID.String(),
		ScannerName:    s.ScannerName,
		ScannerVersion: s.ScannerVersion,
		ScannerType:    s.ScannerType,
		AssetType:      s.AssetType,
		AssetValue:     s.AssetValue,
		CommitSha:      s.CommitSha,
		Branch:         s.Branch,
		BaseCommitSha:  s.BaseCommitSha,
		Status:         string(s.Status),
		ErrorMessage:   s.ErrorMessage,
		FindingsTotal:  s.FindingsTotal,
		FindingsNew:    s.FindingsNew,
		FindingsFixed:  s.FindingsFixed,
		FindingsBySev:  s.FindingsBySeverity,
		StartedAt:      s.StartedAt,
		CompletedAt:    s.CompletedAt,
		DurationMs:     s.DurationMs,
		CreatedAt:      s.CreatedAt,
	}
	if s.SensorID != nil {
		out.SensorID = s.SensorID.String()
	}
	if s.AssetID != nil {
		out.AssetID = s.AssetID.String()
	}
	return out
}

// CodeNoTenantContext is the error code a v1 ingest call from a sensor without
// tenant context (a platform sensor) gets back.
const CodeNoTenantContext = "INVALID_AGENT"

// ScanExportKeySensorPreference is the key scan-config export files written
// before the rename use for the sensor selection mode; ImportConfig still
// reads it so an old export does not silently fall back to "auto".
const ScanExportKeySensorPreference = "agent_preference"
