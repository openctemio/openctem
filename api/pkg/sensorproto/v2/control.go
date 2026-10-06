package v2

// The control-plane resources of protocol v2: everything a sensor does
// besides pushing results (RFC-029, docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md).
// Bodies are JSON. Requests are decoded leniently (unknown members ignored)
// and clients must ignore unknown response members, so v2 grows additively.

import (
	"encoding/json"
	"time"
)

// Control-plane paths under PathPrefix.
const (
	HeartbeatPath         = "/heartbeat"
	SuppressionsPath      = "/suppressions"
	FingerprintsCheckPath = "/fingerprints/check"
	BaselineDiffPath      = "/fingerprints/baseline-diff"
	KeysPath              = "/keys"
	// ManifestPath is the sensor manifest (RFC-033): PUT registers it.
	ManifestPath = "/manifest"
	// ConfigReportPath is the sensor config report (research/26): PUT
	// stores the sensor's preflight check results.
	ConfigReportPath = "/config-report"

	// Command transitions, under CommandsPath + "/{command_id}".
	ClaimAction    = "claim"
	StartAction    = "start"
	CompleteAction = "complete"
	FailAction     = "fail"
)

// ManifestResponse answers PUT /manifest (RFC-033 §6.4): the digest the
// platform stored (the sensor echoes it as the heartbeat's manifest_digest),
// whether it was new, and what was accepted and ignored.
type ManifestResponse struct {
	ManifestDigest string            `json:"manifest_digest"`
	Changed        bool              `json:"changed"`
	Accepted       ManifestAccepted  `json:"accepted"`
	Ignored        []ManifestIgnored `json:"ignored"`
	// Policy is what the platform lets the sensor run now (RFC-033 §6.12,
	// owner decision O2); the SDK refuses commands for other tools.
	Policy ManifestPolicy `json:"policy"`
	// Heartbeat says how the sensor's heartbeats may look while they echo
	// ManifestDigest (owner decision O3).
	Heartbeat ManifestHeartbeat `json:"heartbeat"`
}

// ManifestStateResponse answers GET /manifest: the current digest and the
// policy as it stands now (the sensor re-reads it when config_version
// changes).
type ManifestStateResponse struct {
	ManifestDigest string            `json:"manifest_digest"`
	Policy         ManifestPolicy    `json:"policy"`
	Heartbeat      ManifestHeartbeat `json:"heartbeat"`
}

// ManifestPolicy is the sensor's effective tools, capabilities and
// capacity: its report narrowed by the administrator's settings.
type ManifestPolicy struct {
	AllowedTools        []string `json:"allowed_tools"`
	AllowedCapabilities []string `json:"allowed_capabilities"`
	MaxJobs             int      `json:"max_jobs"`
}

// ManifestHeartbeat: OmitInventory lets the sensor leave tools,
// capabilities and max_concurrent_jobs out of heartbeats that echo the
// digest, sending only the content block (false: the kill switch
// SENSOR_SLIM_HEARTBEAT=false, or a platform that wants them).
type ManifestHeartbeat struct {
	OmitInventory bool `json:"omit_inventory"`
}

// ManifestAccepted is what the platform kept of a manifest: tool names and
// the flat capability list dispatch uses.
type ManifestAccepted struct {
	Tools        []string `json:"tools"`
	Capabilities []string `json:"capabilities"`
}

// ManifestIgnored is one manifest item the platform dropped: where it was,
// its value and why ("unknown-tool", "unknown-capability", "invalid-name",
// "unknown-member", "limit").
type ManifestIgnored struct {
	Path   string `json:"path"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason"`
}

// ActionSendManifest is the heartbeat action asking a sensor whose
// manifest_digest the platform does not have to PUT its manifest (RFC-033
// §6.4). Sent only to sensors that sent a manifest_digest.
const ActionSendManifest = "send_manifest"

// ActionSendConfigReport is the heartbeat action asking a sensor whose
// config_report.digest is not the stored one to PUT its config report.
// Sent only to sensors that sent a digest, when the platform lists
// FeatureConfigReport.
const ActionSendConfigReport = "send_config_report"

// MaxConfigReportBytes caps the body of PUT /config-report (413
// content-too-large with this limit above it).
const MaxConfigReportBytes = 65536

// ConfigReportResponse answers PUT /config-report: the digest the platform
// computed over the report it kept (the sensor echoes it as the
// heartbeat's config_report.digest), whether it differs from the stored
// one, and what the sanitizing dropped.
type ConfigReportResponse struct {
	ConfigReportDigest string                `json:"config_report_digest"`
	Changed            bool                  `json:"changed"`
	Ignored            []ConfigReportIgnored `json:"ignored"`
}

// ConfigReportIgnored is one report item the platform dropped: where it
// was, its value (bounded, display only) and why ("unknown-member",
// "invalid-value", "limit").
type ConfigReportIgnored struct {
	Path   string `json:"path"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason"`
}

// ActionCancel is the heartbeat action that comes with a non-empty
// cancel_command_ids: stop those commands and release them (sdk-go acts on
// the ids; the action names it in the closed set).
const ActionCancel = "cancel"

// Heartbeat status values (RFC-029 §4.3).
const (
	HeartbeatStatusOK     = "ok"
	HeartbeatStatusPaused = "paused"
)

// HeartbeatResponse is the answer of POST /heartbeat. The doorbell is always
// on: every member is present, with zero values when there is nothing to say.
type HeartbeatResponse struct {
	SensorID             string   `json:"sensor_id"`
	TenantID             string   `json:"tenant_id"`
	Status               string   `json:"status"`
	PendingJobs          int      `json:"pending_jobs"`
	NextHeartbeatSeconds int      `json:"next_heartbeat_seconds"`
	Actions              []string `json:"actions"`
	ConfigVersion        string   `json:"config_version"`
	// CancelCommandIDs are commands the sensor listed as running that it
	// must stop: canceled, closed by the platform (a run timeout), re-queued
	// after the lease ran out, or held by another sensor. Stop and release
	// them; their results are refused anyway. At most 256.
	CancelCommandIDs []string `json:"cancel_command_ids"`
}

// Command is a command as the v2 command resources return it. sensor_id is
// the claiming or pinned sensor (null while unassigned). payload is the
// command content as stored.
type Command struct {
	ID             string          `json:"id"`
	Type           string          `json:"type"`
	Priority       string          `json:"priority"`
	Status         string          `json:"status"`
	SensorID       *string         `json:"sensor_id"`
	Payload        json.RawMessage `json:"payload"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      *time.Time      `json:"expires_at"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at"`
	StartedAt      *time.Time      `json:"started_at"`
	CompletedAt    *time.Time      `json:"completed_at"`
	ErrorMessage   string          `json:"error_message"`
	Result         json.RawMessage `json:"result"`
	// LeaseEpoch counts the command's claims and LeaseExpiresAt is when the
	// holder's lease runs out unless renewed (RFC-035 D6). Additive: a
	// sensor may echo the epoch in HeaderLeaseEpoch on complete and fail.
	LeaseEpoch     int        `json:"lease_epoch"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at"`
}

// CommandList is the answer of GET /commands.
type CommandList struct {
	Commands []Command `json:"commands"`
}

// CompleteRequest is the body of POST /commands/{id}/complete.
type CompleteRequest struct {
	Result json.RawMessage `json:"result,omitempty"`
}

// ReleaseRequest is the body of POST /commands/{id}/release (RFC-030 §5.12):
// why the sensor hands the command back (draining, shutdown, canceled,
// politeness, ...). Free text, at most MaxReleaseReasonBytes.
type ReleaseRequest struct {
	Reason string `json:"reason"`
}

// MaxReleaseReasonBytes bounds the reason stored with a released command.
const MaxReleaseReasonBytes = 200

// LogsAction is the logs resource under CommandsPath + "/{command_id}"
// (FeatureLogs, RFC-029 §4.4.1).
const LogsAction = "logs"

// Limits of POST /commands/{id}/logs.
const (
	// MaxLogsBodyBytes caps one logs request body.
	MaxLogsBodyBytes = 256 << 10
	// MaxLogLinesPerBatch caps the lines of one batch.
	MaxLogLinesPerBatch = 500
	// MaxLogSeq bounds the batch number (exclusive).
	MaxLogSeq = 10000
)

// LogsRequest is the body of POST /commands/{id}/logs: batch seq (from 0,
// per command; a replayed seq is stored once) of a task's log lines.
type LogsRequest struct {
	Seq   int       `json:"seq"`
	Lines []LogLine `json:"lines"`
}

// LogLine is one log line. The platform caps, cleans and redacts every
// member again; Fields values are scalars (anything else is kept as its
// JSON text).
type LogLine struct {
	TS     string                     `json:"ts"`
	Level  string                     `json:"level"`
	Msg    string                     `json:"msg"`
	Source string                     `json:"source,omitempty"`
	Fields map[string]json.RawMessage `json:"fields,omitempty"`
}

// LogsResponse answers POST /commands/{id}/logs. Truncated: the command
// reached its log caps and this batch was dropped (Dropped lines); the
// sensor must not resend it.
type LogsResponse struct {
	Stored    int  `json:"stored"`
	Dropped   int  `json:"dropped"`
	Truncated bool `json:"truncated"`
}

// FailRequest is the body of POST /commands/{id}/fail.
type FailRequest struct {
	ErrorMessage string `json:"error_message"`
	// Refusal, when set, says the sensor refused the job under a policy
	// (research/25 §3.6, feature "refusal"): the platform re-queues routed
	// work to another eligible sensor and excludes this one. Optional:
	// without it a reason starting "refused by local policy: " counts too.
	Refusal *Refusal `json:"refusal,omitempty"`
}

// Refusal is a structured policy refusal: the layer (builtin, local,
// managed, scope, platform_tool_gate), the rule ("tools.allow",
// "allow_interactsh", ...) and a short detail.
type Refusal struct {
	Layer  string `json:"layer"`
	Rule   string `json:"rule"`
	Detail string `json:"detail,omitempty"`
}

// FingerprintsCheckRequest is the body of POST /fingerprints/check.
type FingerprintsCheckRequest struct {
	Fingerprints []string `json:"fingerprints"`
}

// FingerprintsCheckResponse answers POST /fingerprints/check.
type FingerprintsCheckResponse struct {
	Existing []string `json:"existing"`
	Missing  []string `json:"missing"`
}

// BaselineDiffRequest is the body of POST /fingerprints/baseline-diff.
type BaselineDiffRequest struct {
	Repository   string   `json:"repository"`
	BaseBranch   string   `json:"base_branch"`
	Fingerprints []string `json:"fingerprints"`
}

// BaselineDiffResponse answers POST /fingerprints/baseline-diff.
type BaselineDiffResponse struct {
	NewFingerprints         []string `json:"new_fingerprints"`
	PreExistingFingerprints []string `json:"pre_existing_fingerprints"`
	BaseBranchScanned       bool     `json:"base_branch_scanned"`
}

// KeyResponse answers POST /keys with the new key, shown once.
type KeyResponse struct {
	APIKey    string     `json:"api_key"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// SuppressionRule is one active suppression rule (same document as v1).
type SuppressionRule struct {
	RuleID      string  `json:"rule_id,omitempty"`
	ToolName    string  `json:"tool_name,omitempty"`
	PathPattern string  `json:"path_pattern,omitempty"`
	AssetID     *string `json:"asset_id,omitempty"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// SuppressionList answers GET /suppressions.
type SuppressionList struct {
	Count int               `json:"count"`
	Rules []SuppressionRule `json:"rules"`
}
