package ticketmap

import "strings"

// AllowedValue is one value a tracker field accepts.
type AllowedValue struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// FieldMeta describes one tracker field of a project and issue type, as the
// tracker's create metadata reports it.
type FieldMeta struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Required      bool           `json:"required"`
	HasDefault    bool           `json:"has_default"`
	Schema        FieldSchema    `json:"schema"`
	AllowedValues []AllowedValue `json:"allowed_values,omitempty"`
}

// ProjectMeta is everything the mapper needs about one destination: its
// fields and its workflow.
type ProjectMeta struct {
	ProjectID   string      `json:"project_id"`
	ProjectKey  string      `json:"project_key"`
	IssueTypeID string      `json:"issue_type_id"`
	IssueType   string      `json:"issue_type"`
	Fields      []FieldMeta `json:"fields"`
	Workflow    Workflow    `json:"workflow"`
}

// Field finds a field by id.
func (m ProjectMeta) Field(id string) (FieldMeta, bool) {
	for _, f := range m.Fields {
		if f.ID == id {
			return f, true
		}
	}
	return FieldMeta{}, false
}

// alwaysSent are fields the engine sets itself on create.
var alwaysSent = map[string]bool{"project": true, "issuetype": true}

func allowedHas(vals []AllowedValue, v string) bool {
	for _, a := range vals {
		if strings.EqualFold(a.Name, v) || a.ID == v {
			return true
		}
	}
	return false
}

func allowedID(vals []AllowedValue, v string) (string, bool) {
	for _, a := range vals {
		if strings.EqualFold(a.Name, v) || a.ID == v {
			return a.ID, true
		}
	}
	return "", false
}

// fieldTypeOption is the tracker's single-select field type.
const fieldTypeOption = "option"

// targetShape is the abstract shape of a tracker field for type checks.
type targetShape string

const (
	shapeText    targetShape = "text"
	shapeNumber  targetShape = "number"
	shapeDate    targetShape = "date"
	shapeOption  targetShape = "option" // option, priority, security level, select: one of allowed values
	shapeUser    targetShape = "user"
	shapeLabels  targetShape = "labels" // array of free strings
	shapeOptions targetShape = "options"
	shapeOther   targetShape = "other"
)

func shapeOf(s FieldSchema) targetShape {
	switch s.Type {
	case "string":
		return shapeText
	case "number":
		return shapeNumber
	case "date", "datetime":
		return shapeDate
	case fieldTypeOption, "priority", "securitylevel", "resolution", "component", "version":
		return shapeOption
	case "user":
		return shapeUser
	case "array":
		switch s.Items {
		case "string":
			return shapeLabels
		case fieldTypeOption, "component", "version":
			return shapeOptions
		}
	}
	return shapeOther
}
