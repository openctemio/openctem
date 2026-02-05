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
)

// Known event types for notification routing.
// Add new event types here - no database migration required (JSONB array).
const (
	// System events
	EventTypeSecurityAlert EventType = "security_alert"
	EventTypeSystemError   EventType = "system_error"

	// Asset events
	EventTypeNewAsset     EventType = "new_asset"
	EventTypeAssetChanged EventType = "asset_changed"
	EventTypeAssetDeleted EventType = "asset_deleted"

	// Scan events
	EventTypeScanStarted   EventType = "scan_started"
	EventTypeScanCompleted EventType = "scan_completed"
	EventTypeScanFailed    EventType = "scan_failed"

	// Finding events
	EventTypeNewFinding       EventType = "new_finding"
	EventTypeFindingConfirmed EventType = "finding_confirmed"
	EventTypeFindingTriaged   EventType = "finding_triaged"
	EventTypeFindingFixed     EventType = "finding_fixed"
	EventTypeFindingReopened  EventType = "finding_reopened"

	// Exposure events
	EventTypeNewExposure      EventType = "new_exposure"
	EventTypeExposureResolved EventType = "exposure_resolved"

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
)

// AllEventTypes returns all event types with metadata for UI.
// RequiredModule maps to modules.id in the database.
// Empty RequiredModule means the event type is always available (system events).
func AllEventTypes() []EventTypeInfo {
	return []EventTypeInfo{
		// System events - always available (no module required)
		{Type: EventTypeSecurityAlert, Category: EventCategorySystem, Label: "Security Alert", Description: "Security-related alerts and warnings", RequiredModule: ""},
		{Type: EventTypeSystemError, Category: EventCategorySystem, Label: "System Error", Description: "System errors and failures", RequiredModule: ""},

		// Asset events - require 'assets' module
		{Type: EventTypeNewAsset, Category: EventCategoryAsset, Label: "New Asset", Description: "New asset discovered or added", RequiredModule: ModuleAssets},
		{Type: EventTypeAssetChanged, Category: EventCategoryAsset, Label: "Asset Changed", Description: "Asset information changed", RequiredModule: ModuleAssets},
		{Type: EventTypeAssetDeleted, Category: EventCategoryAsset, Label: "Asset Deleted", Description: "Asset removed from inventory", RequiredModule: ModuleAssets},

		// Scan events - require 'scans' module
		{Type: EventTypeScanStarted, Category: EventCategoryScan, Label: "Scan Started", Description: "Scan job started", RequiredModule: ModuleScans},
		{Type: EventTypeScanCompleted, Category: EventCategoryScan, Label: "Scan Completed", Description: "Scan job completed successfully", RequiredModule: ModuleScans},
		{Type: EventTypeScanFailed, Category: EventCategoryScan, Label: "Scan Failed", Description: "Scan job failed", RequiredModule: ModuleScans},

		// Finding events - require 'findings' module
		{Type: EventTypeNewFinding, Category: EventCategoryFinding, Label: "New Finding", Description: "New security finding detected", RequiredModule: ModuleFindings},
		{Type: EventTypeFindingConfirmed, Category: EventCategoryFinding, Label: "Confirmed Finding", Description: "Finding confirmed as valid", RequiredModule: ModuleFindings},
		{Type: EventTypeFindingTriaged, Category: EventCategoryFinding, Label: "Need Triage Finding", Description: "Finding needs triage/review", RequiredModule: ModuleFindings},
		{Type: EventTypeFindingFixed, Category: EventCategoryFinding, Label: "Fixed Finding", Description: "Finding has been remediated", RequiredModule: ModuleFindings},
		{Type: EventTypeFindingReopened, Category: EventCategoryFinding, Label: "Reopened Finding", Description: "Finding reopened after fix", RequiredModule: ModuleFindings},

		// Exposure events - require 'findings' module (part of findings feature)
		{Type: EventTypeNewExposure, Category: EventCategoryExposure, Label: "New Exposure", Description: "New credential/data exposure detected", RequiredModule: ModuleFindings},
		{Type: EventTypeExposureResolved, Category: EventCategoryExposure, Label: "Exposure Resolved", Description: "Exposure has been resolved", RequiredModule: ModuleFindings},
	}
}

// DefaultEnabledEventTypes returns the default enabled event types for new integrations.
func DefaultEnabledEventTypes() []EventType {
	return []EventType{
		EventTypeSecurityAlert,
		EventTypeNewFinding,
		EventTypeNewExposure,
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
