package integration

// ============================================================================
// SEVERITY TYPES
// ============================================================================

// Severity represents notification severity level.
// Stored as JSONB array in database for flexibility.
type Severity string

// Known severity levels.
// Add new severity here - no database migration required (JSONB array).
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityNone     Severity = "none"
)

// DefaultEnabledSeverities returns the default enabled severities for new integrations.
func DefaultEnabledSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
	}
}

// AllKnownSeverities returns all known severity levels (for UI display).
func AllKnownSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
		SeverityNone,
	}
}

// ============================================================================
// EVENT TYPES
// ============================================================================

// EventType represents the type of event that triggers notifications.
type EventType string

// EventCategory groups event types for UI organization.
type EventCategory string

// Event categories for UI grouping.
const (
	EventCategorySystem   EventCategory = "system"
	EventCategoryAsset    EventCategory = "asset"
	EventCategoryScan     EventCategory = "scan"
	EventCategoryFinding  EventCategory = "finding"
	EventCategoryExposure EventCategory = "exposure"
	EventCategoryApproval EventCategory = "approval"
	EventCategoryWorkflow EventCategory = "workflow"
	EventCategorySensor   EventCategory = "sensor"
)

// EventCategoryInfo pairs an event category with its display label.
type EventCategoryInfo struct {
	Category EventCategory
	Label    string
}

// AllEventCategories returns every event category with its display label, in
// the order categories should be presented.
//
// The labels live here rather than in the UI for the same reason AllEventTypes
// does: a category added to the constant block above but missing from a
// client-side label map renders as "undefined" (or crashes a lookup) with
// nothing failing at build time. Both approval and workflow categories were
// added without the UI's map learning about them.
func AllEventCategories() []EventCategoryInfo {
	return []EventCategoryInfo{
		{Category: EventCategoryAsset, Label: "Asset Events"},
		{Category: EventCategoryFinding, Label: "Finding Events"},
		{Category: EventCategoryApproval, Label: "Approval Events"},
		{Category: EventCategoryWorkflow, Label: "Workflow Events"},
		{Category: EventCategoryExposure, Label: "Exposure Events"},
		{Category: EventCategorySensor, Label: "Sensor Events"},
	}
}

// Known event types for notification routing.
// Add new event types here - no database migration required (JSONB array).
// A type goes into AllEventTypes only together with its producer:
// tests/unit/event_type_producer_test.go fails on a type nothing emits.
const (
	// Asset events
	EventTypeNewAsset EventType = "new_asset"

	// Finding events
	EventTypeNewFinding      EventType = "new_finding"
	EventTypeFindingFixed    EventType = "finding_fixed"
	EventTypeFindingReopened EventType = "finding_reopened"
	// EventTypeFindingPriorityEscalated fires when an already-classified
	// finding is re-classified UP (e.g. P3 -> P0 because its CVE was newly
	// listed in KEV, or a compensating control was removed). Without it a
	// priority escalation is a silent dashboard update.
	EventTypeFindingPriorityEscalated EventType = "finding_priority_escalated"

	// EventTypeFindingAssigned fires when an assignment rule routes a finding to
	// a group AND that rule has its "notify group" option switched on. The
	// operator has already opted in at the rule; an unregistered event type made
	// that checkbox inert.
	EventTypeFindingAssigned EventType = "finding_assigned"

	// EventTypeSLABreach fires when the SLA escalation controller marks a
	// finding as having missed its remediation deadline.
	EventTypeSLABreach EventType = "sla_breach"

	// EventTypeSLAWarning fires when the SLA escalation controller flags a
	// finding as approaching its remediation deadline (the pre-breach warning).
	// Emitted at severity "medium", which is below the default severity filter
	// (critical, high), so it is registered as a selectable/opt-in type but NOT
	// added to DefaultEnabledEventTypes — an operator enables it and widens the
	// severity filter to receive it.
	EventTypeSLAWarning EventType = "sla_warning"

	// Approval events (risk-acceptance / status-change approvals on findings)
	EventTypeApprovalRequested EventType = "approval_requested"
	EventTypeApprovalApproved  EventType = "approval_approved"
	EventTypeApprovalRejected  EventType = "approval_rejected"

	// EventTypeWorkflowNotification fires from a workflow notification action
	// node that has no provider-specific integration bound to it, i.e. the
	// operator authored a workflow step whose only purpose is to notify.
	EventTypeWorkflowNotification EventType = "workflow_notification"

	// Exposure events
	EventTypeNewExposure EventType = "new_exposure"

	// EventTypeSensorOffline fires when the sensor-health controller sees a
	// sensor stop heartbeating (online -> offline). The id keeps the dotted
	// form of the event_types catalog row it has always had, which is also
	// what existing subscriptions store (migration 000230 rewrote
	// agent.offline to it). Emitted once per offline transition, not per tick.
	EventTypeSensorOffline EventType = "sensor.offline"

	// CI pipeline signals (RFC-051 §10.6), emitted by the CI alert job once
	// per scan workflow or repository while the condition holds, never per run.
	EventTypeCIScheduleMissed     EventType = "ci.schedule_missed"
	EventTypeCICoverageRegression EventType = "ci.coverage_regression"
	EventTypeCIGateFailing        EventType = "ci.gate_failing"
	EventTypeCIRunnerOutdated     EventType = "ci.runner_outdated"
	// CI security signals: a break-glass created or used (every time), and
	// a burst of refused CI token exchanges (once while it lasts).
	EventTypeCIBreakGlass    EventType = "ci.break_glass"
	EventTypeCITokenRefusals EventType = "ci.token_refusals"

	// Retired types. Nothing ever emitted them, so they are not in
	// AllEventTypes and a channel cannot subscribe to them (settings plan
	// P0-08). They stay as constants only because the legacy aliases below
	// map onto them, and subscriptions stored before the change may still
	// list them; such entries simply never match.
	EventTypeSecurityAlert EventType = "security_alert"
	EventTypeScanCompleted EventType = "scan_completed"

	// Legacy event types (for backward compatibility)
	EventTypeFindings  EventType = "findings"  // Maps to new_finding
	EventTypeExposures EventType = "exposures" // Maps to new_exposure
	EventTypeScans     EventType = "scans"     // Maps to scan_completed
	EventTypeAlerts    EventType = "alerts"    // Maps to security_alert
)

// EventTypeInfo contains metadata about an event type.
type EventTypeInfo struct {
	Type           EventType
	Category       EventCategory
	Label          string
	Description    string
	RequiredModule string // Module ID required for this event type (empty = always available)
}

// Module IDs that map to event types.
// These must match the module IDs in the modules table.
const (
	ModuleAssets   = "assets"
	ModuleScans    = "scans"
	ModuleFindings = "findings"
	ModuleSensors  = "sensors"
)

// AllEventTypes returns all event types with metadata for UI.
// RequiredModule maps to modules.id in the database.
// Empty RequiredModule means the event type is always available (system events).
func AllEventTypes() []EventTypeInfo {
	return []EventTypeInfo{

		// Asset events - require 'assets' module
		{Type: EventTypeNewAsset, Category: EventCategoryAsset, Label: "New Asset", Description: "New asset discovered or added", RequiredModule: ModuleAssets},

		// Finding events - require 'findings' module
		{Type: EventTypeNewFinding, Category: EventCategoryFinding, Label: "New Finding", Description: "New security finding detected", RequiredModule: ModuleFindings},
		{Type: EventTypeFindingFixed, Category: EventCategoryFinding, Label: "Fixed Finding", Description: "Finding has been remediated", RequiredModule: ModuleFindings},
		{Type: EventTypeFindingReopened, Category: EventCategoryFinding, Label: "Reopened Finding", Description: "Finding reopened after fix", RequiredModule: ModuleFindings},
		{Type: EventTypeFindingPriorityEscalated, Category: EventCategoryFinding, Label: "Priority Escalated", Description: "Finding re-classified to a higher priority (e.g. P3 to P0)", RequiredModule: ModuleFindings},
		{Type: EventTypeFindingAssigned, Category: EventCategoryFinding, Label: "Finding Assigned", Description: "Finding routed to a group by an assignment rule with group notification enabled", RequiredModule: ModuleFindings},
		{Type: EventTypeSLABreach, Category: EventCategoryFinding, Label: "SLA Breached", Description: "Finding missed its SLA remediation deadline", RequiredModule: ModuleFindings},
		{Type: EventTypeSLAWarning, Category: EventCategoryFinding, Label: "SLA Approaching", Description: "Finding is approaching its SLA remediation deadline (pre-breach warning)", RequiredModule: ModuleFindings},

		// Approval events - require 'findings' module (approvals gate finding status changes)
		{Type: EventTypeApprovalRequested, Category: EventCategoryApproval, Label: "Approval Requested", Description: "Someone requested approval for a finding status change", RequiredModule: ModuleFindings},
		{Type: EventTypeApprovalApproved, Category: EventCategoryApproval, Label: "Approval Approved", Description: "A requested finding status change was approved", RequiredModule: ModuleFindings},
		{Type: EventTypeApprovalRejected, Category: EventCategoryApproval, Label: "Approval Rejected", Description: "A requested finding status change was rejected", RequiredModule: ModuleFindings},

		// Workflow events - require 'findings' module ('workflows' is a child of
		// 'findings' per migration 000162). Deliberately NOT gated on the
		// 'workflows' module: internal/app/automation never checks module
		// enablement before enqueuing, so gating the notification on a module
		// the emitter ignores would recreate the same silent drop this list
		// exists to prevent.
		{Type: EventTypeWorkflowNotification, Category: EventCategoryWorkflow, Label: "Workflow Notification", Description: "A workflow notification action fired without a provider-specific integration bound", RequiredModule: ModuleFindings},

		// Exposure events - require 'findings' module (part of findings feature)
		{Type: EventTypeNewExposure, Category: EventCategoryExposure, Label: "New Exposure", Description: "New credential/data exposure detected", RequiredModule: ModuleFindings},

		// Sensor events - require 'sensors' module
		{Type: EventTypeSensorOffline, Category: EventCategorySensor, Label: "Sensor Offline", Description: "A sensor stopped sending heartbeats and was marked offline", RequiredModule: ModuleSensors},

		// CI pipeline signals - require 'scans' module (CI runs live there)
		{Type: EventTypeCIScheduleMissed, Category: EventCategorySensor, Label: "CI Scheduled Scan Missed", Description: "A CI pipeline with a schedule missed two expected runs", RequiredModule: ModuleScans},
		{Type: EventTypeCICoverageRegression, Category: EventCategorySensor, Label: "CI Coverage Lost", Description: "A repository that had a fresh CI pipeline has none any more", RequiredModule: ModuleScans},
		{Type: EventTypeCIGateFailing, Category: EventCategorySensor, Label: "CI Default Branch Failing", Description: "The default branch of a repository fails the CI gate (opt-in)", RequiredModule: ModuleScans},
		{Type: EventTypeCIRunnerOutdated, Category: EventCategorySensor, Label: "CI Runner Outdated", Description: "A CI pipeline runs a sensor older than the minimum supported version", RequiredModule: ModuleScans},
		{Type: EventTypeCIBreakGlass, Category: EventCategorySensor, Label: "CI Break-glass", Description: "A break-glass was created, or let a failing CI run pass", RequiredModule: ModuleScans},
		{Type: EventTypeCITokenRefusals, Category: EventCategorySensor, Label: "CI Token Refusals", Description: "Many CI token exchanges were refused in a short time", RequiredModule: ModuleScans},
	}
}

// DefaultEnabledEventTypes returns the default enabled event types for new integrations.
//
// enabled_event_types is an opt-in whitelist, so anything absent here is not
// delivered to an integration created with the defaults. The bar for inclusion
// is therefore not "is this interesting" but "would a reasonable operator be
// surprised to learn this reached nobody".
func DefaultEnabledEventTypes() []EventType {
	return []EventType{
		EventTypeNewFinding,
		EventTypeNewExposure,

		// A missed remediation deadline that notifies nobody defeats the point
		// of having an SLA. Enqueued at severity "high", so it also clears the
		// default severity filter (critical, high).
		EventTypeSLABreach,

		// Emitted only when an assignment rule has its "notify group" option
		// switched on — the operator opted in at the rule. Leaving it off by
		// default would keep that switch inert.
		EventTypeFindingAssigned,

		// Emitted only by a workflow notification action the operator authored,
		// whose sole purpose is to notify. Same argument as above.
		EventTypeWorkflowNotification,

		// An approval request is addressed to a human; if it reaches nobody the
		// finding stays blocked indefinitely. The approved/rejected outcomes are
		// deliberately NOT default-on: they are FYI traffic for the requester,
		// already visible in-app, and broadcasting every one of them to a shared
		// channel is noise.
		EventTypeApprovalRequested,

		// A finding the operator already triaged as low-urgency silently
		// becoming P0 is the escalation they cannot afford to miss, so it is
		// on by default. Migration 000201 backfills existing rows; the
		// per-integration severity filter still applies (P0 -> critical,
		// P1 -> high, ...), so this is not a firehose.
		EventTypeFindingPriorityEscalated,

		// A scheduled CI scan that silently stopped, a repository that lost
		// its scanning, or a runner below the supported version are the
		// failures nobody notices otherwise. A failing default branch is
		// opt-in: the scan workflow itself already reports it.
		EventTypeCIScheduleMissed,
		EventTypeCICoverageRegression,
		EventTypeCIRunnerOutdated,
		// Security signals about the CI gate itself.
		EventTypeCIBreakGlass,
		EventTypeCITokenRefusals,
	}
}

// SeverityFilterApplies reports whether the per-integration severity filter is
// meaningful for this event type.
//
// EnqueueParams.Severity carries two different things depending on the event:
//
//   - For finding-shaped events (new_finding, sla_breach, ...) it IS the
//     finding's severity. An operator who leaves the filter at its default is
//     saying "only tell me about critical and high findings", and honoring
//     that is the whole point of the filter.
//
//   - For approval lifecycle events it is a hardcoded constant chosen by the
//     enqueue site ("medium" for requested/rejected, "low" for approved). It
//     describes nothing about a finding, and no operator ever asked to
//     suppress it.
//
// Running the second kind through a filter built for the first kind silently
// defeats it. That is not hypothetical: DefaultEnabledEventTypes deliberately
// includes EventTypeApprovalRequested, with the comment "if it reaches nobody
// the finding stays blocked indefinitely" — and then the severity gate dropped
// it anyway, because "medium" is not in the default critical+high set. The
// event-type gate was opened on purpose and the severity gate closed it again.
//
// Events exempted here remain fully controllable through the event-type filter,
// which is the switch that actually means "I do not want these".
func SeverityFilterApplies(eventType EventType) bool {
	switch MapLegacyEventType(eventType) {
	case EventTypeApprovalRequested, EventTypeApprovalApproved, EventTypeApprovalRejected:
		return false
	// new_asset announces attack-surface growth (a newly discovered
	// internet-facing asset). Its severity is a fixed label set by the
	// discovery notifier, not a finding severity, so the default
	// critical+high filter would silently drop every one of them.
	case EventTypeNewAsset:
		return false
	// sensor.offline is about the platform's own scanners, not a finding: its
	// severity is a constant chosen by the sensor-health controller. The
	// operator opts in through the event-type list.
	case EventTypeSensorOffline:
		return false
	// The CI signals carry a constant severity chosen by the CI alert job,
	// not a finding's severity.
	case EventTypeCIScheduleMissed, EventTypeCICoverageRegression, EventTypeCIGateFailing, EventTypeCIRunnerOutdated,
		EventTypeCIBreakGlass, EventTypeCITokenRefusals:
		return false
	// sla_warning is stamped "medium" by the SLA warning adapter as the urgency
	// of an approaching deadline, whatever the finding's severity. It is opt-in
	// (not default-on), and under the default critical+high filter every one
	// was dropped, so opting in delivered nothing.
	case EventTypeSLAWarning:
		return false
	default:
		return true
	}
}

// AllKnownEventTypes returns all known event types (for backward compatibility API).
func AllKnownEventTypes() []EventType {
	types := make([]EventType, 0, len(AllEventTypes()))
	for _, info := range AllEventTypes() {
		types = append(types, info.Type)
	}
	return types
}

// MapLegacyEventType maps old event types to new ones for backward compatibility.
func MapLegacyEventType(eventType EventType) EventType {
	switch eventType {
	case EventTypeFindings:
		return EventTypeNewFinding
	case EventTypeExposures:
		return EventTypeNewExposure
	case EventTypeScans:
		return EventTypeScanCompleted
	case EventTypeAlerts:
		return EventTypeSecurityAlert
	default:
		return eventType
	}
}

// GetEventTypesByModules returns event types filtered by enabled modules.
// System events (no required module) are always included.
func GetEventTypesByModules(enabledModuleIDs []string) []EventTypeInfo {
	moduleSet := make(map[string]bool, len(enabledModuleIDs))
	for _, m := range enabledModuleIDs {
		moduleSet[m] = true
	}

	allTypes := AllEventTypes()
	result := make([]EventTypeInfo, 0, len(allTypes))
	for _, et := range allTypes {
		// System events (no module required) are always available
		if et.RequiredModule == "" {
			result = append(result, et)
			continue
		}
		// Check if required module is enabled
		if moduleSet[et.RequiredModule] {
			result = append(result, et)
		}
	}
	return result
}

// GetDefaultEventTypesByModules returns default event types filtered by enabled modules.
func GetDefaultEventTypesByModules(enabledModuleIDs []string) []EventType {
	availableTypes := GetEventTypesByModules(enabledModuleIDs)
	availableSet := make(map[EventType]bool, len(availableTypes))
	for _, et := range availableTypes {
		availableSet[et.Type] = true
	}

	defaults := DefaultEnabledEventTypes()
	result := make([]EventType, 0, len(defaults))
	for _, et := range defaults {
		if availableSet[et] {
			result = append(result, et)
		}
	}
	return result
}

// ValidateEventTypes checks if all event types are available for the given modules.
// Returns a list of invalid event types that require modules not in enabledModuleIDs.
func ValidateEventTypes(eventTypes []EventType, enabledModuleIDs []string) (valid bool, invalidTypes []EventType) {
	availableTypes := GetEventTypesByModules(enabledModuleIDs)
	availableSet := make(map[EventType]bool, len(availableTypes))
	for _, et := range availableTypes {
		availableSet[et.Type] = true
	}

	invalidTypes = make([]EventType, 0)
	for _, et := range eventTypes {
		// Map legacy types first
		mapped := MapLegacyEventType(et)
		if !availableSet[mapped] {
			invalidTypes = append(invalidTypes, et)
		}
	}
	return len(invalidTypes) == 0, invalidTypes
}

// GetRequiredModuleForEventType returns the module ID required for an event type.
// Returns empty string if the event type is always available (system events).
func GetRequiredModuleForEventType(eventType EventType) string {
	mapped := MapLegacyEventType(eventType)
	for _, et := range AllEventTypes() {
		if et.Type == mapped {
			return et.RequiredModule
		}
	}
	return ""
}

// NotificationExtension represents notification-specific extension data for an integration.
// This follows the same pattern as SCM extension.
// Note: channel_id (for Telegram) and channel_name (for Slack/Teams) are now stored in
// integrations.metadata instead of this extension table.
type NotificationExtension struct {
	integrationID ID

	// Enabled severities (dynamic JSONB array - add new severities without migration)
	enabledSeverities []Severity

	// Enabled event types (dynamic JSONB array - add new types without migration)
	enabledEventTypes []EventType

	// Message templates
	messageTemplate string
	includeDetails  bool

	// Rate limiting
	minIntervalMinutes int
}

// NewNotificationExtension creates a new notification extension with defaults.
func NewNotificationExtension(integrationID ID) *NotificationExtension {
	return &NotificationExtension{
		integrationID:      integrationID,
		enabledSeverities:  DefaultEnabledSeverities(),
		enabledEventTypes:  DefaultEnabledEventTypes(),
		includeDetails:     true,
		minIntervalMinutes: 5,
	}
}

// ReconstructNotificationExtension creates a notification extension from stored data.
// Note: channelID and channelName parameters are deprecated and ignored.
// They are now stored in integrations.metadata.
func ReconstructNotificationExtension(
	integrationID ID,
	_ string, // channelID - deprecated, now in integrations.metadata
	_ string, // channelName - deprecated, now in integrations.metadata
	enabledSeverities []Severity,
	enabledEventTypes []EventType,
	messageTemplate string,
	includeDetails bool,
	minIntervalMinutes int,
) *NotificationExtension {
	if minIntervalMinutes <= 0 {
		minIntervalMinutes = 5
	}
	// Use defaults if no severities specified (backward compatibility)
	if len(enabledSeverities) == 0 {
		enabledSeverities = DefaultEnabledSeverities()
	}
	// Use defaults if no event types specified (backward compatibility)
	if len(enabledEventTypes) == 0 {
		enabledEventTypes = DefaultEnabledEventTypes()
	}
	return &NotificationExtension{
		integrationID:      integrationID,
		enabledSeverities:  enabledSeverities,
		enabledEventTypes:  enabledEventTypes,
		messageTemplate:    messageTemplate,
		includeDetails:     includeDetails,
		minIntervalMinutes: minIntervalMinutes,
	}
}

// ReconstructNotificationExtensionFromBooleans creates extension from old boolean fields.
// Used for backward compatibility during migration.
// Note: channelID and channelName parameters are deprecated and ignored.
func ReconstructNotificationExtensionFromBooleans(
	integrationID ID,
	_ string, // channelID - deprecated, now in integrations.metadata
	_ string, // channelName - deprecated, now in integrations.metadata
	notifyOnCritical bool,
	notifyOnHigh bool,
	notifyOnMedium bool,
	notifyOnLow bool,
	enabledEventTypes []EventType,
	messageTemplate string,
	includeDetails bool,
	minIntervalMinutes int,
) *NotificationExtension {
	// Convert boolean flags to severity array
	severities := make([]Severity, 0, 4)
	if notifyOnCritical {
		severities = append(severities, SeverityCritical)
	}
	if notifyOnHigh {
		severities = append(severities, SeverityHigh)
	}
	if notifyOnMedium {
		severities = append(severities, SeverityMedium)
	}
	if notifyOnLow {
		severities = append(severities, SeverityLow)
	}

	return ReconstructNotificationExtension(
		integrationID,
		"", // channelID - deprecated
		"", // channelName - deprecated
		severities,
		enabledEventTypes,
		messageTemplate,
		includeDetails,
		minIntervalMinutes,
	)
}

// Getters

func (n *NotificationExtension) IntegrationID() ID { return n.integrationID }

// ChannelID returns empty string - deprecated, now stored in integrations.metadata as chat_id
func (n *NotificationExtension) ChannelID() string { return "" }

// ChannelName returns empty string - deprecated, now stored in integrations.metadata as channel_name
func (n *NotificationExtension) ChannelName() string            { return "" }
func (n *NotificationExtension) EnabledSeverities() []Severity  { return n.enabledSeverities }
func (n *NotificationExtension) EnabledEventTypes() []EventType { return n.enabledEventTypes }
func (n *NotificationExtension) MessageTemplate() string        { return n.messageTemplate }
func (n *NotificationExtension) IncludeDetails() bool           { return n.includeDetails }
func (n *NotificationExtension) MinIntervalMinutes() int        { return n.minIntervalMinutes }

// Backward compatibility getters (derived from enabledSeverities)
func (n *NotificationExtension) NotifyOnCritical() bool { return n.IsSeverityEnabled(SeverityCritical) }
func (n *NotificationExtension) NotifyOnHigh() bool     { return n.IsSeverityEnabled(SeverityHigh) }
func (n *NotificationExtension) NotifyOnMedium() bool   { return n.IsSeverityEnabled(SeverityMedium) }
func (n *NotificationExtension) NotifyOnLow() bool      { return n.IsSeverityEnabled(SeverityLow) }

// IsSeverityEnabled checks if a specific severity is enabled.
func (n *NotificationExtension) IsSeverityEnabled(severity Severity) bool {
	// Empty list means default severities (critical, high)
	if len(n.enabledSeverities) == 0 {
		return severity == SeverityCritical || severity == SeverityHigh
	}
	for _, s := range n.enabledSeverities {
		if s == severity {
			return true
		}
	}
	return false
}

// ShouldNotify checks if a notification should be sent for the given severity string.
func (n *NotificationExtension) ShouldNotify(severity string) bool {
	return n.IsSeverityEnabled(Severity(severity))
}

// ShouldNotifyEventType checks if a notification should be sent for the given event type.
func (n *NotificationExtension) ShouldNotifyEventType(eventType EventType) bool {
	// Empty list means all events are enabled (backward compatibility)
	if len(n.enabledEventTypes) == 0 {
		return true
	}
	// Check for legacy event types and map them
	mappedEventType := MapLegacyEventType(eventType)
	for _, et := range n.enabledEventTypes {
		if et == eventType || et == mappedEventType {
			return true
		}
	}
	return false
}

// IsEventTypeEnabled checks if a specific event type is enabled.
func (n *NotificationExtension) IsEventTypeEnabled(eventType EventType) bool {
	return n.ShouldNotifyEventType(eventType)
}

// Setters

// SetChannel is deprecated - channel info is now stored in integrations.metadata
// This function is kept for backward compatibility but does nothing.
func (n *NotificationExtension) SetChannel(_, _ string) {
	// No-op: channel_id and channel_name are now stored in integrations.metadata
}

func (n *NotificationExtension) SetEnabledSeverities(severities []Severity) {
	n.enabledSeverities = severities
}

func (n *NotificationExtension) SetEnabledEventTypes(types []EventType) {
	n.enabledEventTypes = types
}

func (n *NotificationExtension) SetMessageTemplate(template string) {
	n.messageTemplate = template
}

func (n *NotificationExtension) SetIncludeDetails(include bool) {
	n.includeDetails = include
}

func (n *NotificationExtension) SetMinIntervalMinutes(minutes int) {
	if minutes <= 0 {
		minutes = 5
	}
	n.minIntervalMinutes = minutes
}

// Backward compatibility setters
func (n *NotificationExtension) SetNotifyOnCritical(notify bool) {
	n.updateSeverityEnabled(SeverityCritical, notify)
}

func (n *NotificationExtension) SetNotifyOnHigh(notify bool) {
	n.updateSeverityEnabled(SeverityHigh, notify)
}

func (n *NotificationExtension) SetNotifyOnMedium(notify bool) {
	n.updateSeverityEnabled(SeverityMedium, notify)
}

func (n *NotificationExtension) SetNotifyOnLow(notify bool) {
	n.updateSeverityEnabled(SeverityLow, notify)
}

// updateSeverityEnabled adds or removes a severity from the enabled list.
func (n *NotificationExtension) updateSeverityEnabled(severity Severity, enabled bool) {
	if enabled {
		// Add if not already present
		for _, s := range n.enabledSeverities {
			if s == severity {
				return
			}
		}
		n.enabledSeverities = append(n.enabledSeverities, severity)
	} else {
		// Remove if present
		newSeverities := make([]Severity, 0, len(n.enabledSeverities))
		for _, s := range n.enabledSeverities {
			if s != severity {
				newSeverities = append(newSeverities, s)
			}
		}
		n.enabledSeverities = newSeverities
	}
}

// IntegrationWithNotification combines an Integration with its notification extension.
type IntegrationWithNotification struct {
	*Integration
	Notification *NotificationExtension
}

// NewIntegrationWithNotification creates a new integration with notification extension.
func NewIntegrationWithNotification(integration *Integration, notification *NotificationExtension) *IntegrationWithNotification {
	return &IntegrationWithNotification{
		Integration:  integration,
		Notification: notification,
	}
}
