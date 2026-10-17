package ticketmap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Preset is a starting point for a profile.
type Preset struct {
	ID          string     `json:"id"`
	ObjectKind  ObjectKind `json:"object_kind"`
	Description string     `json:"description"`
	Spec        Spec       `json:"spec"`
}

var (
	schemaString   = FieldSchema{Type: "string", System: "summary"}
	schemaDesc     = FieldSchema{Type: "string", System: "description"}
	schemaPriority = FieldSchema{Type: "priority", System: "priority"}
	schemaLabels   = FieldSchema{Type: "array", Items: "string", System: "labels"}
	schemaDue      = FieldSchema{Type: "date", System: "duedate"}
	schemaAssignee = FieldSchema{Type: "user", System: "assignee"}
)

func severityPriorityMap() Transform {
	return Transform{Kind: TransformValueMap, Map: map[string]string{
		"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest",
	}, Default: "Medium"}
}

// Presets returns the preset library for an object kind. Status maps are
// filled per workflow with AutoMapStatus when a preset is applied.
func Presets(kind ObjectKind) []Preset {
	if kind == ObjectTask {
		return []Preset{
			{ID: "security_task", ObjectKind: ObjectTask, Description: "Remediation task in a delivery project: findings table, priority, due date, owner.",
				Spec: Spec{Minimization: MinSummary, CommentsOut: true, Fields: []Row{
					{ID: "summary", Source: Source{Kind: SourceTemplate, Template: "{{ task.title | truncate:240 }}"}, Target: Target{FieldID: "summary", Name: "Summary", Schema: schemaString}, Direction: DirOut, Sync: SyncAlways},
					{ID: "description", Source: Source{Kind: SourceAttr, Attr: "task.findings_table"}, Target: Target{FieldID: "description", Name: "Description", Schema: schemaDesc}, Direction: DirOut, Sync: SyncAlways},
					{ID: "priority", Source: Source{Kind: SourceAttr, Attr: "task.priority"}, Target: Target{FieldID: "priority", Name: "Priority", Schema: schemaPriority}, Direction: DirOut, Sync: SyncAlways,
						Transform: Transform{Kind: TransformValueMap, Map: map[string]string{"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}, Default: "Medium"}},
					{ID: "duedate", Source: Source{Kind: SourceAttr, Attr: "task.due_date"}, Target: Target{FieldID: "duedate", Name: "Due date", Schema: schemaDue}, Direction: DirBoth, Sync: SyncAlways, Winner: WinnerOpenCTEM, Transform: Transform{Kind: TransformDate}},
					{ID: "assignee", Source: Source{Kind: SourceAttr, Attr: "task.assignee"}, Target: Target{FieldID: "assignee", Name: "Assignee", Schema: schemaAssignee}, Direction: DirBoth, Sync: SyncCreate, Winner: WinnerTracker, Transform: Transform{Kind: TransformUser}},
					{ID: "labels", Source: Source{Kind: SourceConst, Value: "openctem"}, Target: Target{FieldID: "labels", Name: "Labels", Schema: schemaLabels}, Direction: DirOut, Sync: SyncCreate},
				}}},
			{ID: "minimal", ObjectKind: ObjectTask, Description: "Title and a link back only.",
				Spec: Spec{Minimization: MinTitleOnly, Fields: []Row{
					{ID: "summary", Source: Source{Kind: SourceAttr, Attr: "task.title"}, Target: Target{FieldID: "summary", Name: "Summary", Schema: schemaString}, Direction: DirOut, Sync: SyncAlways},
					{ID: "description", Source: Source{Kind: SourceTemplate, Template: "Remediation task with {{ task.finding_count }} findings: {{ task.url }}"}, Target: Target{FieldID: "description", Name: "Description", Schema: schemaDesc}, Direction: DirOut, Sync: SyncAlways},
				}}},
		}
	}
	return []Preset{
		{ID: "security_bug", ObjectKind: ObjectFinding, Description: "Security bug in a software project: severity as priority, CVEs as labels, SLA as due date.",
			Spec: Spec{Minimization: MinSummary, CommentsOut: true, Fields: []Row{
				{ID: "summary", Source: Source{Kind: SourceTemplate, Template: "[{{ finding.severity | upper }}] {{ finding.title | truncate:230 }}"}, Target: Target{FieldID: "summary", Name: "Summary", Schema: schemaString}, Direction: DirOut, Sync: SyncAlways},
				{ID: "description", Source: Source{Kind: SourceTemplate, Template: "Asset: {{ finding.asset_name | default:\"-\" }}\nLocation: {{ finding.location | default:\"-\" }}\nCVE: {{ finding.cve_ids | join:\", \" | default:\"-\" }}\nSLA due: {{ finding.sla_deadline | date | default:\"-\" }}\n\nFix: {{ finding.fix_guidance | default:\"see the finding\" }}\n\nOpen in OpenCTEM: {{ finding.url }}"},
					Target: Target{FieldID: "description", Name: "Description", Schema: schemaDesc}, Direction: DirOut, Sync: SyncAlways},
				{ID: "priority", Source: Source{Kind: SourceAttr, Attr: "finding.severity"}, Target: Target{FieldID: "priority", Name: "Priority", Schema: schemaPriority}, Direction: DirOut, Sync: SyncAlways, Transform: severityPriorityMap()},
				{ID: "labels", Source: Source{Kind: SourceAttr, Attr: "finding.cve_ids"}, Target: Target{FieldID: "labels", Name: "Labels", Schema: schemaLabels}, Direction: DirOut, Sync: SyncAlways, Transform: Transform{Kind: TransformList}},
				{ID: "duedate", Source: Source{Kind: SourceAttr, Attr: "finding.sla_deadline"}, Target: Target{FieldID: "duedate", Name: "Due date", Schema: schemaDue}, Direction: DirBoth, Sync: SyncAlways, Winner: WinnerOpenCTEM, Transform: Transform{Kind: TransformDate}},
				{ID: "assignee", Source: Source{Kind: SourceAttr, Attr: "finding.assignee"}, Target: Target{FieldID: "assignee", Name: "Assignee", Schema: schemaAssignee}, Direction: DirBoth, Sync: SyncCreate, Winner: WinnerTracker, Transform: Transform{Kind: TransformUser}},
			}}},
		{ID: "service_desk_incident", ObjectKind: ObjectFinding, Description: "Incident in a service-desk project for a SOC hand-off: urgent findings, minimal technical text.",
			Spec: Spec{Minimization: MinSummary, CommentsOut: true, Fields: []Row{
				{ID: "summary", Source: Source{Kind: SourceTemplate, Template: "Security exposure: {{ finding.title | truncate:200 }} on {{ finding.asset_name | default:\"an asset\" }}"}, Target: Target{FieldID: "summary", Name: "Summary", Schema: schemaString}, Direction: DirOut, Sync: SyncAlways},
				{ID: "description", Source: Source{Kind: SourceTemplate, Template: "Severity: {{ finding.severity }} ({{ finding.priority_class | default:\"unprioritized\" }})\nKnown exploited: {{ finding.is_kev }}\nAsset: {{ finding.asset_name | default:\"-\" }}\nDetails: {{ finding.url }}"},
					Target: Target{FieldID: "description", Name: "Description", Schema: schemaDesc}, Direction: DirOut, Sync: SyncCreate},
				{ID: "priority", Source: Source{Kind: SourceAttr, Attr: "finding.severity"}, Target: Target{FieldID: "priority", Name: "Priority", Schema: schemaPriority}, Direction: DirOut, Sync: SyncAlways, Transform: severityPriorityMap()},
			}}},
		{ID: "minimal", ObjectKind: ObjectFinding, Description: "Title, severity and a link back only.",
			Spec: Spec{Minimization: MinTitleOnly, Fields: []Row{
				{ID: "summary", Source: Source{Kind: SourceTemplate, Template: "[{{ finding.severity }}] {{ finding.title | truncate:230 }}"}, Target: Target{FieldID: "summary", Name: "Summary", Schema: schemaString}, Direction: DirOut, Sync: SyncAlways},
				{ID: "description", Source: Source{Kind: SourceTemplate, Template: "Open in OpenCTEM: {{ finding.url }}"}, Target: Target{FieldID: "description", Name: "Description", Schema: schemaDesc}, Direction: DirOut, Sync: SyncCreate},
			}}},
	}
}

// PresetByID finds a preset.
func PresetByID(kind ObjectKind, id string) (Preset, bool) {
	for _, p := range Presets(kind) {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// AutoMapStatus proposes a status map for a workflow from status categories
// and common names. The admin reviews it before publishing.
func AutoMapStatus(kind ObjectKind, wf Workflow) StatusMap {
	pick := func(cat string, prefer ...string) (WorkflowStatus, bool) {
		var cands []WorkflowStatus
		for _, s := range wf.Statuses {
			if s.Category == cat {
				cands = append(cands, s)
			}
		}
		for _, p := range prefer {
			for _, c := range cands {
				if strings.EqualFold(c.Name, p) {
					return c, true
				}
			}
		}
		if len(cands) > 0 {
			sort.Slice(cands, func(i, j int) bool { return cands[i].ID < cands[j].ID })
			return cands[0], true
		}
		return WorkflowStatus{}, false
	}
	m := StatusMap{Outbound: map[string]StatusTarget{}, VerifyingLabel: "openctem:verifying", SLABreachLabel: "openctem:sla-breached", Regression: RegressionNewIssue}
	todo, okTodo := pick(CategoryNew, "To Do", "Open", "Backlog")
	prog, okProg := pick(CategoryIndeterminate, "In Progress")
	done, okDone := pick(CategoryDone, "Done", "Closed", "Resolved")
	target := func(s WorkflowStatus, res string) StatusTarget {
		return StatusTarget{StatusID: s.ID, Name: s.Name, Resolution: res, Comment: true}
	}
	wontDo := resolutionNamed(wf, "Won't Do", "Won't Fix")
	fixed := resolutionNamed(wf, "Done", "Fixed")
	if kind == ObjectTask {
		if okTodo {
			m.Outbound[TaskOpen] = target(todo, "")
		}
		if okProg {
			m.Outbound[TaskInProgress] = target(prog, "")
			m.Outbound[TaskVerifying] = target(prog, "")
		}
		if okDone {
			m.Outbound[TaskDone] = target(done, fixed)
		}
	} else {
		if okTodo {
			m.Outbound[StateConfirmed] = target(todo, "")
		}
		if okProg {
			m.Outbound[StateInProgress] = target(prog, "")
			m.Outbound[StateVerificationFailed] = target(prog, "")
		}
		if okDone {
			m.Outbound[StateVerified] = target(done, fixed)
			if wontDo != "" {
				m.Outbound[StateAccepted] = target(done, wontDo)
				m.Outbound[StateFalsePositive] = target(done, wontDo)
			}
		}
	}
	// Inbound: resolution-specific rules first, then categories.
	if wontDo != "" {
		m.Inbound = append(m.Inbound, InboundRule{Category: CategoryDone, Resolution: wontDo, Intent: IntentRequestAccept})
	}
	if r := resolutionNamed(wf, "Duplicate"); r != "" {
		m.Inbound = append(m.Inbound, InboundRule{Category: CategoryDone, Resolution: r, Intent: IntentSuggestDuplicate})
	}
	if r := resolutionNamed(wf, "Cannot Reproduce"); r != "" {
		m.Inbound = append(m.Inbound, InboundRule{Category: CategoryDone, Resolution: r, Intent: IntentRequestFP})
	}
	for _, s := range wf.Statuses {
		if strings.EqualFold(s.Name, "Reopened") {
			m.Inbound = append(m.Inbound, InboundRule{StatusID: s.ID, Intent: IntentReopen})
		}
	}
	m.Inbound = append(m.Inbound,
		InboundRule{Category: CategoryDone, Intent: IntentFixClaim},
		InboundRule{Category: CategoryIndeterminate, Intent: IntentInProgress},
		InboundRule{Category: CategoryNew, Intent: IntentIgnore},
	)
	return m
}

func resolutionNamed(wf Workflow, names ...string) string {
	for _, n := range names {
		for _, r := range wf.Resolutions {
			if strings.EqualFold(r.Name, n) {
				return r.Name
			}
		}
	}
	return ""
}

// SuggestRows proposes rows for unmapped fields by name and type (e.g. a
// number field called "CVSS" ← finding.cvss_score). Suggestions are never
// applied without the admin.
func SuggestRows(kind ObjectKind, s Spec, meta ProjectMeta) []Row {
	used := map[string]bool{}
	for _, r := range s.Fields {
		used[r.Target.FieldID] = true
	}
	hints := []struct {
		words []string
		shape targetShape
		attr  string
	}{
		{[]string{"cvss"}, shapeNumber, "finding.cvss_score"},
		{[]string{"epss"}, shapeNumber, "finding.epss_score"},
		{[]string{"cve"}, shapeLabels, "finding.cve_ids"},
		{[]string{"cve"}, shapeText, "finding.cve_ids"},
		{[]string{"cwe"}, shapeLabels, "finding.cwe_ids"},
		{[]string{"asset", "host", "component"}, shapeText, "finding.asset_name"},
		{[]string{"due"}, shapeDate, "finding.sla_deadline"},
		{[]string{"severity"}, shapeOption, "finding.severity"},
		{[]string{"due"}, shapeDate, "task.due_date"},
		{[]string{"finding", "count"}, shapeNumber, "task.finding_count"},
	}
	var out []Row
	for _, f := range meta.Fields {
		if used[f.ID] {
			continue
		}
		name := strings.ToLower(f.Name)
		for _, h := range hints {
			a, ok := LookupAttr(kind, h.attr)
			if !ok || shapeOf(f.Schema) != h.shape {
				continue
			}
			match := false
			for _, w := range h.words {
				if strings.Contains(name, w) {
					match = true
				}
			}
			if !match {
				continue
			}
			r := Row{ID: "suggest-" + f.ID, Source: Source{Kind: SourceAttr, Attr: a.Path},
				Target: Target{FieldID: f.ID, Name: f.Name, Schema: f.Schema}, Direction: DirOut, Sync: SyncAlways}
			switch h.shape {
			case shapeLabels:
				r.Transform = Transform{Kind: TransformList}
			case shapeText:
				if a.Type == TypeList {
					r.Transform = Transform{Kind: TransformJoin, Separator: ", "}
				}
			case shapeDate:
				r.Transform = Transform{Kind: TransformDate}
			case shapeOption:
				r.Transform = Transform{Kind: TransformValueMap, Map: map[string]string{}}
			}
			out = append(out, r)
			used[f.ID] = true
			break
		}
	}
	return out
}

// Document is the import/export format of one profile.
type Document struct {
	Schema     string     `json:"schema" yaml:"schema"`
	ObjectKind ObjectKind `json:"object_kind" yaml:"object_kind"`
	Project    string     `json:"project,omitempty" yaml:"project,omitempty"`
	IssueType  string     `json:"issue_type,omitempty" yaml:"issue_type,omitempty"`
	Spec       Spec       `json:"spec" yaml:"spec"`
}

// Export renders a document as JSON or YAML.
func Export(d Document, format string) ([]byte, error) {
	d.Schema = SchemaVersion
	if format == "yaml" {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(d); err != nil {
			return nil, fmt.Errorf("encode yaml: %w", err)
		}
		return buf.Bytes(), nil
	}
	return json.MarshalIndent(d, "", "  ")
}

// Import parses a JSON or YAML document (detected), bounded in size, with
// unknown keys refused, and checks its shape for the expected object kind.
func Import(data []byte, kind ObjectKind) (Document, error) {
	var d Document
	if len(data) == 0 || len(data) > MaxDocumentBytes {
		return d, fmt.Errorf("%w: the document must be 1 byte to %d KiB", shared.ErrValidation, MaxDocumentBytes/1024)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&d); err != nil {
			return d, fmt.Errorf("%w: invalid JSON mapping document", shared.ErrValidation)
		}
	} else {
		dec := yaml.NewDecoder(bytes.NewReader(trimmed))
		dec.KnownFields(true)
		if err := dec.Decode(&d); err != nil {
			return d, fmt.Errorf("%w: invalid YAML mapping document", shared.ErrValidation)
		}
	}
	if d.Schema != SchemaVersion {
		return d, fmt.Errorf("%w: schema must be %q", shared.ErrValidation, SchemaVersion)
	}
	if d.ObjectKind != kind {
		return d, fmt.Errorf("%w: the document maps %q, this profile maps %q", shared.ErrValidation, d.ObjectKind, kind)
	}
	if err := d.Spec.CheckShape(kind); err != nil {
		return d, err
	}
	return d, nil
}
