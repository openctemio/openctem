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
