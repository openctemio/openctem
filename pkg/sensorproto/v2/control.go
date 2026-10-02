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

	// Command transitions, under CommandsPath + "/{command_id}".
	ClaimAction    = "claim"
	StartAction    = "start"
	CompleteAction = "complete"
	FailAction     = "fail"
)

// CommandActionPath is the full path of a transition on one command.
func CommandActionPath(commandID, action string) string {
	return PathPrefix + CommandsPath + "/" + commandID + "/" + action
}

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

// FailRequest is the body of POST /commands/{id}/fail.
type FailRequest struct {
	ErrorMessage string `json:"error_message"`
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
