// Package scan defines the Scan domain entity and types.
// A Scan binds an Asset Group with a Scanner/Workflow and Schedule.
package scan

// ScanType represents the type of scan to execute.
type ScanType string

const (
	// ScanTypeWorkflow executes a multi-step pipeline workflow.
	ScanTypeWorkflow ScanType = "workflow"
	// ScanTypeSingle executes a single scanner.
	ScanTypeSingle ScanType = "single"
)

// ScheduleType represents when the scan should run.
type ScheduleType string

const (
	ScheduleManual  ScheduleType = "manual"
	ScheduleDaily   ScheduleType = "daily"
	ScheduleWeekly  ScheduleType = "weekly"
	ScheduleMonthly ScheduleType = "monthly"
	ScheduleCrontab ScheduleType = "crontab"
)

// Status represents the scan status.
type Status string

const (
	StatusActive   Status = "active"
	StatusPaused   Status = "paused"
	StatusDisabled Status = "disabled"
)

// AgentPreference determines which agents can execute the scan.
type AgentPreference string

const (
	// AgentPreferenceAuto tries tenant agents first, falls back to platform.
	AgentPreferenceAuto AgentPreference = "auto"
	// AgentPreferenceTenant only uses tenant's own agents.
	AgentPreferenceTenant AgentPreference = "tenant"
	// AgentPreferencePlatform only uses platform agents.
	AgentPreferencePlatform AgentPreference = "platform"
)

// Timeout constants for scan execution.
const (
	// MinScanTimeoutSeconds is the minimum allowed scan timeout (30 seconds).
	// Lower values would create DoS pressure on the timeout sweeper.
	MinScanTimeoutSeconds = 30
	// DefaultScanTimeoutSeconds is the default scan timeout (1 hour).
	DefaultScanTimeoutSeconds = 3600
	// MaxScanTimeoutSeconds is the maximum allowed scan timeout (24 hours).
	MaxScanTimeoutSeconds = 86400
)

// Retry constants for scan execution.
const (
	// MaxRetryCount is the absolute maximum retries allowed per scan.
	MaxRetryCount = 10
	// DefaultRetryBackoffSeconds is the default initial backoff between retries.
	DefaultRetryBackoffSeconds = 60
	// MinRetryBackoffSeconds is the minimum allowed initial backoff.
	MinRetryBackoffSeconds = 10
	// MaxRetryBackoffSeconds is the maximum allowed initial backoff (24 hours).
	MaxRetryBackoffSeconds = 86400
)

// Run-outcome strings a scan run reports. Used by RecordRun in
// entity.go. Kept as plain string constants (not a typed enum) so
// they line up with the untyped status column on scan_runs.
const (
	RunStatusCompleted = "completed"
	RunStatusSuccess   = "success"
	RunStatusFailed    = "failed"
	RunStatusError     = "error"
)
