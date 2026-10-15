package ticketmap

import (
	"fmt"
	"sort"
)

// Severity of a validation issue. Errors block publishing; warnings and
// notes are shown in the mapper.
const (
	IssueError   = "error"
	IssueWarning = "warning"
	IssueInfo    = "info"
)

// Issue is one validation finding, attributed to a row or a status entry.
type Issue struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	RowID    string `json:"row_id,omitempty"`
	FieldID  string `json:"field_id,omitempty"`
	State    string `json:"state,omitempty"` // status map entry
	Message  string `json:"message"`
}

// HasErrors reports whether any issue blocks publishing.
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == IssueError {
			return true
		}
	}
	return false
}

// Validate checks a spec against the destination's metadata. meta may be nil
// (no tracker reachable): then only tracker-independent rules run and a
// warning says so.
//
//nolint:cyclop,gocognit // one pass of independent rules, each short
func Validate(kind ObjectKind, s Spec, meta *ProjectMeta) []Issue {
	var out []Issue
	add := func(sev, code, row, field, msg string) {
		out = append(out, Issue{Severity: sev, Code: code, RowID: row, FieldID: field, Message: msg})
	}
	if err := s.CheckShape(kind); err != nil {
		add(IssueError, "shape", "", "", err.Error())
		return out
	}
	if meta == nil {
		add(IssueWarning, "no_metadata", "", "", "the tracker could not be reached: field types, required fields and the workflow were not checked")
	}

	outTargets := map[string]string{} // field id → row id
	inAttrs := map[string]string{}    // attr path → row id
	for _, r := range s.Fields {
		var attr Attribute
		if r.Source.Kind == SourceAttr {
			a, ok := LookupAttr(kind, r.Source.Attr)
			if !ok {
				add(IssueError, "unknown_attr", r.ID, r.Target.FieldID, fmt.Sprintf("%q is not a %s attribute", r.Source.Attr, kind))
				continue
			}
			attr = a
			if !s.Minimization.Allows(a.Tier) && r.Direction.outbound() {
				add(IssueWarning, "minimized", r.ID, r.Target.FieldID,
					fmt.Sprintf("%q is above the data level %q and will not be sent", a.Path, s.Minimization))
			}
		}
		if r.Source.Kind == SourceTemplate {
			tpl, err := ParseTemplate(kind, r.Source.Template)
			if err != nil {
				add(IssueError, "template", r.ID, r.Target.FieldID, err.Error())
			} else {
				for _, p := range tpl.Paths() {
					if a, _ := LookupAttr(kind, p); !s.Minimization.Allows(a.Tier) {
						add(IssueWarning, "minimized", r.ID, r.Target.FieldID,
							fmt.Sprintf("%q is above the data level %q and renders empty", p, s.Minimization))
					}
				}
			}
		}

		// Conflicts.
		if r.Direction.outbound() {
			if prev, dup := outTargets[r.Target.FieldID]; dup {
				add(IssueError, "duplicate_target", r.ID, r.Target.FieldID,
					fmt.Sprintf("field %s is already written by row %s", r.Target.FieldID, prev))
			}
			outTargets[r.Target.FieldID] = r.ID
		}
		if r.Direction.inbound() {
			// Inbound safety: fixed per attribute, never widened by config.
			if r.Source.Kind != SourceAttr || attr.Inbound == InboundNever || attr.Inbound == "" {
				add(IssueError, "inbound_forbidden", r.ID, r.Target.FieldID,
					fmt.Sprintf("%q cannot be changed from the tracker", r.Source.Attr))
			}
			if prev, dup := inAttrs[r.Source.Attr]; dup {
				add(IssueError, "duplicate_inbound", r.ID, r.Target.FieldID,
					fmt.Sprintf("%q is already updated from row %s", r.Source.Attr, prev))
			}
			inAttrs[r.Source.Attr] = r.ID
		}
		if r.Direction == DirBoth {
			if r.Transform.Kind == TransformValueMap && !bijective(r.Transform.Map) {
				add(IssueWarning, "not_invertible", r.ID, r.Target.FieldID,
					"the value map is not one-to-one: inbound values that several OpenCTEM values map to are ambiguous")
			}
			if r.Winner == WinnerTracker && r.Sync == SyncAlways {
				add(IssueWarning, "winner_sync", r.ID, r.Target.FieldID,
					"the tracker wins this field, so OpenCTEM only writes it on create")
			}
		}

		if meta == nil {
			continue
		}
		f, ok := meta.Field(r.Target.FieldID)
		if !ok {
			add(IssueError, "unknown_field", r.ID, r.Target.FieldID,
				fmt.Sprintf("field %s is not on the %s create screen of %s", fieldLabel(r.Target), meta.IssueType, meta.ProjectKey))
			continue
		}
		out = append(out, typeCheck(kind, r, attr, f)...)
	}

	if meta != nil {
		for _, f := range meta.Fields {
			if f.Required && !f.HasDefault && !alwaysSent[f.ID] && f.ID != "summary" {
				if _, ok := outTargets[f.ID]; !ok {
					add(IssueError, "required_unmapped", "", f.ID, fmt.Sprintf("required field %q has no mapping", f.Name))
				}
			}
		}
		if _, ok := outTargets["summary"]; !ok {
			add(IssueInfo, "summary_default", "", "summary", "no summary row: the default summary is used")
		}
	}

	out = append(out, validateStatus(kind, s.Status, meta)...)
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].Severity) < sevRank(out[j].Severity) })
	return out
}

func sevRank(s string) int {
	switch s {
	case IssueError:
		return 0
	case IssueWarning:
		return 1
	}
	return 2
}

func fieldLabel(t Target) string {
	if t.Name != "" {
		return fmt.Sprintf("%q (%s)", t.Name, t.FieldID)
	}
	return t.FieldID
}

func bijective(m map[string]string) bool {
	seen := map[string]bool{}
	for _, v := range m {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

// typeCheck checks one row's source and transform against the field.
//
//nolint:cyclop // a table of shape pairs
func typeCheck(kind ObjectKind, r Row, attr Attribute, f FieldMeta) []Issue {
	var out []Issue
	bad := func(code, msg string) {
		out = append(out, Issue{Severity: IssueError, Code: code, RowID: r.ID, FieldID: f.ID, Message: msg})
	}
	shape := shapeOf(f.Schema)
	if shape == shapeOther {
		out = append(out, Issue{Severity: IssueWarning, Code: "unsupported_field", RowID: r.ID, FieldID: f.ID,
			Message: fmt.Sprintf("field %q has type %q, which is sent as text and may be refused", f.Name, f.Schema.Type)})
		return out
	}
	// Values a value map or constant can produce must be allowed.
	checkAllowed := func(vals ...string) {
		if len(f.AllowedValues) == 0 {
			return
		}
		for _, v := range vals {
			if v != "" && !allowedHas(f.AllowedValues, v) {
				bad("value_not_allowed", fmt.Sprintf("%q is not an allowed value of %q", v, f.Name))
			}
		}
	}
	src := attr.Type
	switch r.Source.Kind {
	case SourceTemplate:
		src = TypeText
	case SourceConst:
		src = TypeText
	}
	switch shape {
	case shapeText:
		if src == TypeUser {
			bad("type_mismatch", fmt.Sprintf("%q is a text field; a user cannot be written to it", f.Name))
		}
	case shapeNumber:
		if src != TypeNumber {
			bad("type_mismatch", fmt.Sprintf("%q is a number field; map a number attribute", f.Name))
		}
	case shapeDate:
		if src != TypeDate {
			bad("type_mismatch", fmt.Sprintf("%q is a date field; map a date attribute", f.Name))
		}
	case shapeUser:
		if src != TypeUser {
			bad("type_mismatch", fmt.Sprintf("%q is a user field; map a user attribute", f.Name))
		}
	case shapeOption:
		switch {
		case r.Source.Kind == SourceConst:
			checkAllowed(r.Source.Value)
		case r.Transform.Kind == TransformValueMap:
			vals := make([]string, 0, len(r.Transform.Map)+1)
			for _, v := range r.Transform.Map {
				vals = append(vals, v)
			}
			checkAllowed(append(vals, r.Transform.Default)...)
			if attr.Type == TypeEnum {
				for _, e := range attr.Enum {
					if _, ok := r.Transform.Map[e]; !ok && r.Transform.Default == "" {
						out = append(out, Issue{Severity: IssueWarning, Code: "value_map_gap", RowID: r.ID, FieldID: f.ID,
							Message: fmt.Sprintf("%q has no value for %q and no default", f.Name, e)})
					}
				}
			}
		case r.Source.Kind == SourceTemplate:
			bad("type_mismatch", fmt.Sprintf("%q accepts only its listed values; use a value map", f.Name))
		default:
			out = append(out, Issue{Severity: IssueWarning, Code: "unchecked_values", RowID: r.ID, FieldID: f.ID,
				Message: fmt.Sprintf("%q accepts only its listed values; values are sent as they are", f.Name)})
		}
	case shapeLabels, shapeOptions:
		if src != TypeList && src != TypeEnum && r.Source.Kind != SourceConst {
			bad("type_mismatch", fmt.Sprintf("%q is a list field; map a list attribute", f.Name))
		}
		if shape == shapeOptions && r.Transform.Kind == TransformValueMap {
			vals := make([]string, 0, len(r.Transform.Map))
			for _, v := range r.Transform.Map {
				vals = append(vals, v)
			}
			checkAllowed(vals...)
		}
	}
	if r.Direction.inbound() && attr.Inbound == InboundAssign && shape != shapeUser {
		bad("type_mismatch", "an assignee can only be read back from a user field")
	}
	_ = kind
	return out
}

// validateStatus checks the status map against the workflow: every target
// status exists, is reachable, and every required transition field is filled.
func validateStatus(kind ObjectKind, m StatusMap, meta *ProjectMeta) []Issue {
	var out []Issue
	if meta == nil || len(meta.Workflow.Statuses) == 0 {
		if len(m.Outbound) > 0 {
			out = append(out, Issue{Severity: IssueWarning, Code: "no_workflow", Message: "the workflow could not be read: status targets were not checked"})
		}
		return out
	}
	wf := meta.Workflow
	states := OutboundStates(kind)
	for _, st := range states {
		t, ok := m.Outbound[st]
		if !ok {
			continue
		}
		if _, ok := wf.Status(t.StatusID); !ok {
			out = append(out, Issue{Severity: IssueError, Code: "status_missing", State: st,
				Message: fmt.Sprintf("%s → status %s is not in the workflow (removed or renamed?)", st, statusLabel(t))})
			continue
		}
		if t.Resolution != "" && len(wf.Resolutions) > 0 && !allowedHas(wf.Resolutions, t.Resolution) {
			out = append(out, Issue{Severity: IssueError, Code: "resolution_not_allowed", State: st,
				Message: fmt.Sprintf("%s: resolution %q does not exist", st, t.Resolution)})
		}
		reachable, firstErr := 0, error(nil)
		for _, from := range wf.Statuses {
			if from.ID == t.StatusID {
				reachable++
				continue
			}
			if _, err := wf.Plan(from.ID, t); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("from %q: %w", from.Name, err)
				}
				continue
			}
			reachable++
		}
		switch {
		case reachable <= 1 && len(wf.Statuses) > 1:
			out = append(out, Issue{Severity: IssueError, Code: "status_unreachable", State: st,
				Message: fmt.Sprintf("%s → %s cannot be reached: %v", st, statusLabel(t), firstErr)})
		case firstErr != nil:
			out = append(out, Issue{Severity: IssueWarning, Code: "status_partly_reachable", State: st,
				Message: fmt.Sprintf("%s → %s is not reachable from every status (%v); the issue stays put and the error is reported", st, statusLabel(t), firstErr)})
		}
	}
	for i, r := range m.Inbound {
		if r.StatusID != "" {
			if _, ok := wf.Status(r.StatusID); !ok {
				out = append(out, Issue{Severity: IssueError, Code: "status_missing", State: r.StatusID,
					Message: fmt.Sprintf("inbound rule %d names a status that is not in the workflow", i+1)})
			}
		}
	}
	for _, s := range wf.Statuses {
		if _, mapped := m.IntentFor(StatusEvent{StatusID: s.ID, Category: s.Category}); !mapped {
			out = append(out, Issue{Severity: IssueInfo, Code: "status_unmapped", State: s.ID,
				Message: fmt.Sprintf("status %q has no inbound rule: moving an issue there does nothing", s.Name)})
		}
	}
	return out
}

func statusLabel(t StatusTarget) string {
	if t.Name != "" {
		return fmt.Sprintf("%q", t.Name)
	}
	return t.StatusID
}

// Drift compares a version's snapshot with the live metadata and reports what
// changed under the mapping: fields removed or renamed, new required fields,
// allowed values removed, workflow statuses removed.
func Drift(snapshot, live ProjectMeta, s Spec) []Issue {
	var out []Issue
	used := map[string]bool{}
	for _, r := range s.Fields {
		used[r.Target.FieldID] = true
	}
	for _, old := range snapshot.Fields {
		nf, ok := live.Field(old.ID)
		switch {
		case !ok && used[old.ID]:
			out = append(out, Issue{Severity: IssueError, Code: "field_removed", FieldID: old.ID,
				Message: fmt.Sprintf("field %q was removed from the create screen", old.Name)})
		case ok && nf.Name != old.Name && used[old.ID]:
			out = append(out, Issue{Severity: IssueInfo, Code: "field_renamed", FieldID: old.ID,
				Message: fmt.Sprintf("field %q is now called %q (still mapped by id)", old.Name, nf.Name)})
		}
		if ok && used[old.ID] {
			for _, v := range old.AllowedValues {
				if !allowedHas(nf.AllowedValues, v.Name) && len(nf.AllowedValues) > 0 {
					out = append(out, Issue{Severity: IssueWarning, Code: "value_removed", FieldID: old.ID,
						Message: fmt.Sprintf("value %q of %q no longer exists", v.Name, nf.Name)})
				}
			}
		}
	}
	for _, f := range live.Fields {
		if _, existed := snapshot.Field(f.ID); !existed && f.Required && !f.HasDefault && !used[f.ID] {
			out = append(out, Issue{Severity: IssueError, Code: "new_required_field", FieldID: f.ID,
				Message: fmt.Sprintf("new required field %q has no mapping", f.Name)})
		}
	}
	for _, st := range snapshot.Workflow.Statuses {
		if _, ok := live.Workflow.Status(st.ID); !ok {
			out = append(out, Issue{Severity: IssueError, Code: "status_removed", State: st.ID,
				Message: fmt.Sprintf("workflow status %q was removed", st.Name)})
		}
	}
	return out
}
