// Package ticketmap holds the ticket field mapping model: which OpenCTEM
// attribute goes to which tracker field (outbound), which tracker field comes
// back to which attribute (inbound), and how values are transformed on the way.
//
// Design: docs/rfcs/RFC-097-ticket-field-mapping.md.
//
// The package is pure: it validates a mapping against the tracker's field
// metadata, renders the field payload for one object, and turns an inbound
// tracker change into commands. It never calls a tracker and never reads the
// database; the application layer supplies the values and applies commands
// through the normal service paths.
package ticketmap

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SchemaVersion names the spec document format (export / import).
const SchemaVersion = "openctem.mapping/v1"

// ObjectKind is the OpenCTEM object a profile maps.
type ObjectKind string

const (
	// ObjectFinding maps one finding to one issue.
	ObjectFinding ObjectKind = "finding"
	// ObjectTask maps one remediation task (the "Tasks" of the remediation
	// pages) to one issue.
	ObjectTask ObjectKind = "task"
)

// Valid reports whether k is a known object kind.
func (k ObjectKind) Valid() bool { return k == ObjectFinding || k == ObjectTask }

// Direction says which way a mapping row flows.
type Direction string

const (
	DirOut  Direction = "out"  // OpenCTEM → tracker
	DirIn   Direction = "in"   // tracker → OpenCTEM
	DirBoth Direction = "both" // both ways
)

func (d Direction) outbound() bool { return d == DirOut || d == DirBoth }
func (d Direction) inbound() bool  { return d == DirIn || d == DirBoth }

// SyncMode says when an outbound row is written.
type SyncMode string

const (
	// SyncCreate writes the field only when the issue is created.
	SyncCreate SyncMode = "create"
	// SyncAlways writes the field on create and on every change.
	SyncAlways SyncMode = "always"
	// SyncPreserveEdits writes on change only while the tracker still holds
	// the value OpenCTEM pushed last (a person's edit in the tracker stays).
	SyncPreserveEdits SyncMode = "preserve_edits"
)

// Winner decides a conflict on a two-way field.
type Winner string

const (
	WinnerOpenCTEM   Winner = "openctem"
	WinnerTracker    Winner = "tracker"
	WinnerLastWriter Winner = "last_writer"
)

// SourceKind is where an outbound value comes from.
type SourceKind string

const (
	SourceAttr     SourceKind = "attr"     // one catalog attribute
	SourceTemplate SourceKind = "template" // a text template over attributes
	SourceConst    SourceKind = "const"    // a fixed value
)

// TransformKind converts a value to the target field's shape.
type TransformKind string

const (
	TransformNone     TransformKind = ""          // pass through (types must match)
	TransformValueMap TransformKind = "value_map" // table: source value → target value
	TransformUser     TransformKind = "user"      // OpenCTEM user → tracker account
	TransformDate     TransformKind = "date"      // a time → the field's date format
	TransformNumber   TransformKind = "number"    // a number, rounded
	TransformList     TransformKind = "list"      // a list → labels / multi-select
	TransformJoin     TransformKind = "join"      // a list → one text value
)

// Minimization limits how much of an object leaves the platform.
type Minimization string

const (
	// MinTitleOnly sends the title, severity and a link back.
	MinTitleOnly Minimization = "title_only"
	// MinSummary adds the asset, CVEs, location and fix guidance.
	MinSummary Minimization = "summary"
	// MinFull adds descriptions and the remaining attributes.
	MinFull Minimization = "full"
)

// rank orders minimization levels from least to most data.
func (m Minimization) rank() int {
	switch m {
	case MinTitleOnly:
		return 1
	case MinSummary:
		return 2
	case MinFull:
		return 3
	}
	return 0
}

// Allows reports whether an attribute of tier t may leave under level m.
func (m Minimization) Allows(t Minimization) bool { return t.rank() <= m.rank() }

// Source is the outbound side of a row.
type Source struct {
	Kind     SourceKind `json:"kind" yaml:"kind"`
	Attr     string     `json:"attr,omitempty" yaml:"attr,omitempty"`
	Template string     `json:"template,omitempty" yaml:"template,omitempty"`
	Value    string     `json:"value,omitempty" yaml:"value,omitempty"`
}

// FieldSchema is the tracker field's type, as the tracker describes it.
type FieldSchema struct {
	Type   string `json:"type" yaml:"type"`                       // string, number, date, datetime, option, array, user, priority, ...
	Items  string `json:"items,omitempty" yaml:"items,omitempty"` // element type of an array
	System string `json:"system,omitempty" yaml:"system,omitempty"`
	Custom string `json:"custom,omitempty" yaml:"custom,omitempty"`
}

// Target is the tracker field a row writes or reads.
type Target struct {
	FieldID string      `json:"field_id" yaml:"field_id"` // e.g. "priority", "customfield_10042"
	Name    string      `json:"name,omitempty" yaml:"name,omitempty"`
	Schema  FieldSchema `json:"schema" yaml:"schema"`
}

// Transform converts values between the two sides.
type Transform struct {
	Kind TransformKind `json:"kind,omitempty" yaml:"kind,omitempty"`
	// Map is the value table of a value_map (source value → target value, by
	// the target's allowed value name). Inbound uses it inverted.
	Map map[string]string `json:"map,omitempty" yaml:"map,omitempty"`
	// Default is used when the source value is empty or not in Map.
	Default string `json:"default,omitempty" yaml:"default,omitempty"`
	// FallbackAccount is the tracker account a user transform falls back to.
	FallbackAccount string `json:"fallback_account,omitempty" yaml:"fallback_account,omitempty"`
	// Round is the number of decimals a number transform keeps.
	Round int `json:"round,omitempty" yaml:"round,omitempty"`
	// Separator joins a list (join transform).
	Separator string `json:"separator,omitempty" yaml:"separator,omitempty"`
	// Prefix is prepended to every label (list → labels), e.g. "cve:".
	Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
}

// Row is one mapping between an OpenCTEM attribute and a tracker field.
type Row struct {
	ID        string    `json:"id" yaml:"id"`
	Source    Source    `json:"source" yaml:"source"`
	Target    Target    `json:"target" yaml:"target"`
	Direction Direction `json:"direction" yaml:"direction"`
	Sync      SyncMode  `json:"sync,omitempty" yaml:"sync,omitempty"`
	Winner    Winner    `json:"winner,omitempty" yaml:"winner,omitempty"`
	Transform Transform `json:"transform,omitempty" yaml:"transform,omitempty"`
}

// Spec is one version of a mapping profile.
type Spec struct {
	Minimization Minimization `json:"minimization" yaml:"minimization"`
	Fields       []Row        `json:"fields" yaml:"fields"`
	Status       StatusMap    `json:"status" yaml:"status"`
	// CommentsOut posts verification results and moves as comments.
	CommentsOut bool `json:"comments_out" yaml:"comments_out"`
	// CommentsIn imports tracker comments into the timeline.
	CommentsIn bool `json:"comments_in" yaml:"comments_in"`
}

// Limits keep a stored spec bounded.
const (
	MaxRows          = 60
	MaxValueMapSize  = 100
	MaxTemplateRunes = 4000
	MaxConstRunes    = 1000
	MaxStatusEntries = 60
	MaxDocumentBytes = 256 * 1024
)

// CheckShape rejects a spec that is structurally unusable regardless of the
// tracker (unknown enum values, oversized parts, duplicate row ids). Field
// level rules that need the tracker metadata are in Validate.
func (s Spec) CheckShape(kind ObjectKind) error {
	if !kind.Valid() {
		return fmt.Errorf("%w: unknown object kind %q", shared.ErrValidation, kind)
	}
	if s.Minimization.rank() == 0 {
		return fmt.Errorf("%w: minimization must be title_only, summary or full", shared.ErrValidation)
	}
	if len(s.Fields) > MaxRows {
		return fmt.Errorf("%w: at most %d mapping rows", shared.ErrValidation, MaxRows)
	}
	seen := make(map[string]bool, len(s.Fields))
	for i, r := range s.Fields {
		if r.ID == "" || len(r.ID) > 64 {
			return fmt.Errorf("%w: row %d needs an id of at most 64 characters", shared.ErrValidation, i+1)
		}
		if seen[r.ID] {
			return fmt.Errorf("%w: duplicate row id %q", shared.ErrValidation, r.ID)
		}
		seen[r.ID] = true
		if err := r.checkShape(); err != nil {
			return fmt.Errorf("%w: row %q: %s", shared.ErrValidation, r.ID, err.Error())
		}
	}
	if err := s.Status.checkShape(kind); err != nil {
		return err
	}
	return nil
}

func (r Row) checkShape() error {
	switch r.Direction {
	case DirOut, DirIn, DirBoth:
	default:
		return fmt.Errorf("direction must be out, in or both")
	}
	switch r.Sync {
	case "", SyncCreate, SyncAlways, SyncPreserveEdits:
	default:
		return fmt.Errorf("unknown sync mode %q", r.Sync)
	}
	switch r.Winner {
	case "", WinnerOpenCTEM, WinnerTracker, WinnerLastWriter:
	default:
		return fmt.Errorf("unknown conflict winner %q", r.Winner)
	}
	switch r.Source.Kind {
	case SourceAttr:
		if r.Source.Attr == "" {
			return fmt.Errorf("an attribute source needs attr")
		}
	case SourceTemplate:
		if r.Direction != DirOut {
			return fmt.Errorf("a template can only flow out")
		}
		if n := len([]rune(r.Source.Template)); n == 0 || n > MaxTemplateRunes {
			return fmt.Errorf("a template must be 1 to %d characters", MaxTemplateRunes)
		}
	case SourceConst:
		if r.Direction != DirOut {
			return fmt.Errorf("a constant can only flow out")
		}
		if len([]rune(r.Source.Value)) > MaxConstRunes {
			return fmt.Errorf("a constant is at most %d characters", MaxConstRunes)
		}
	default:
		return fmt.Errorf("source kind must be attr, template or const")
	}
	if !validFieldID(r.Target.FieldID) {
		return fmt.Errorf("invalid target field id")
	}
	switch r.Transform.Kind {
	case TransformNone, TransformValueMap, TransformUser, TransformDate, TransformNumber, TransformList, TransformJoin:
	default:
		return fmt.Errorf("unknown transform %q", r.Transform.Kind)
	}
	if len(r.Transform.Map) > MaxValueMapSize {
		return fmt.Errorf("a value map has at most %d entries", MaxValueMapSize)
	}
	if r.Transform.Round < 0 || r.Transform.Round > 6 {
		return fmt.Errorf("round must be 0 to 6")
	}
	if len(r.Transform.Prefix) > 32 || len(r.Transform.Separator) > 8 {
		return fmt.Errorf("prefix or separator too long")
	}
	return nil
}

// validFieldID accepts tracker field ids: lower-case system ids
// ("priority", "duedate") and "customfield_<n>".
func validFieldID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}
