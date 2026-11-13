package module

// EventType represents a notification event type stored in the database.
// This is the single source of truth for all event types in the system.
type EventType struct {
	id                 string
	slug               string
	name               string
	description        string
	category           string
	icon               string
	color              string
	severityApplicable bool
	isDefault          bool
	isActive           bool
	displayOrder       int
}

// ReconstructEventType creates an EventType from stored data.
func ReconstructEventType(
	id, slug, name, description, category, icon, color string,
	severityApplicable, isDefault, isActive bool,
	displayOrder int,
) *EventType {
	return &EventType{
		id:                 id,
		slug:               slug,
		name:               name,
		description:        description,
		category:           category,
		icon:               icon,
		color:              color,
		severityApplicable: severityApplicable,
		isDefault:          isDefault,
		isActive:           isActive,
		displayOrder:       displayOrder,
	}
}

// Getters

func (e *EventType) ID() string               { return e.id }
func (e *EventType) Slug() string             { return e.slug }
func (e *EventType) Name() string             { return e.name }
func (e *EventType) Description() string      { return e.description }
func (e *EventType) Category() string         { return e.category }
func (e *EventType) Icon() string             { return e.icon }
func (e *EventType) Color() string            { return e.color }
func (e *EventType) SeverityApplicable() bool { return e.severityApplicable }
func (e *EventType) IsDefault() bool          { return e.isDefault }
func (e *EventType) IsActive() bool           { return e.isActive }
func (e *EventType) DisplayOrder() int        { return e.displayOrder }

// EventTypeWithModule represents an event type with its associated module ID.
type EventTypeWithModule struct {
	*EventType
	ModuleID string
}

// EventTypeCategory represents a category of event types for UI grouping.
type EventTypeCategory struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	EventTypes []*EventType `json:"event_types"`
}

// Known event type categories.
const (
	EventCategorySystem      = "system"
	EventCategoryAsset       = "asset"
	EventCategoryScan        = "scan"
	EventCategoryFinding     = "finding"
	EventCategoryExposure    = "exposure"
	EventCategoryCredential  = "credential"
	EventCategoryPentest     = "pentest"
	EventCategoryRemediation = "remediation"
	EventCategoryComponent   = "component"
	EventCategoryThreatIntel = "threat_intel"
)

// CategoryDisplayNames maps category IDs to display names.
var CategoryDisplayNames = map[string]string{
	EventCategorySystem:      "System",
	EventCategoryAsset:       "Assets",
	EventCategoryScan:        "Scans",
	EventCategoryFinding:     "Findings",
	EventCategoryExposure:    "Exposures",
	EventCategoryCredential:  "Credentials",
	EventCategoryPentest:     "Penetration Testing",
	EventCategoryRemediation: "Remediation",
	EventCategoryComponent:   "Components",
	EventCategoryThreatIntel: "Threat Intelligence",
}

// GetCategoryDisplayName returns the display name for a category.
func GetCategoryDisplayName(category string) string {
	if name, ok := CategoryDisplayNames[category]; ok {
		return name
	}
	return category
}

// GroupEventTypesByCategory groups event types by their category.
func GroupEventTypesByCategory(eventTypes []*EventType) []EventTypeCategory {
	// Use a map to group
	categoryMap := make(map[string][]*EventType)
	categoryOrder := make([]string, 0)

	for _, et := range eventTypes {
		if _, exists := categoryMap[et.category]; !exists {
			categoryOrder = append(categoryOrder, et.category)
		}
		categoryMap[et.category] = append(categoryMap[et.category], et)
	}

	// Build result in order
	result := make([]EventTypeCategory, 0, len(categoryOrder))
	for _, cat := range categoryOrder {
		result = append(result, EventTypeCategory{
			ID:         cat,
			Name:       GetCategoryDisplayName(cat),
			EventTypes: categoryMap[cat],
		})
	}

	return result
}

// GetDefaultEventTypeIDs returns the IDs of event types that are default enabled.
func GetDefaultEventTypeIDs(eventTypes []*EventType) []string {
	result := make([]string, 0)
	for _, et := range eventTypes {
		if et.isDefault {
			result = append(result, et.id)
		}
	}
	return result
}
