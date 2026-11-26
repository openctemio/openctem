package ticketmap

import (
	"sort"
	"testing"
)

func attrRow(id, attr, field string, dir Direction, tr Transform) Row {
	return Row{ID: id, Source: Source{Kind: SourceAttr, Attr: attr}, Target: Target{FieldID: field}, Direction: dir, Transform: tr}
}

// Every issue carries a specific code and the values its sentence names, so a
// client can word it in the reader's language; the English message stays.
func TestIssues_CodesAndParams(t *testing.T) {
	odd := secMeta()
	odd.Fields = append(odd.Fields, FieldMeta{ID: "customfield_7", Name: "Odd", Schema: FieldSchema{Type: "weird"}})

	noWorkflow := secMeta()
	noWorkflow.Workflow = Workflow{}

	var all []Issue
	all = append(all, Validate(ObjectFinding, Spec{Minimization: "bogus"}, nil)...)
	all = append(all, Validate(ObjectFinding, Spec{Minimization: MinTitleOnly, Fields: []Row{
		attrRow("a", "finding.nope", "description", DirOut, Transform{}),
		attrRow("b", "finding.description", "description", DirOut, Transform{}),
		{ID: "c", Source: Source{Kind: SourceTemplate, Template: "{{ finding.description }}"}, Target: Target{FieldID: "labels"}, Direction: DirOut},
		{ID: "d", Source: Source{Kind: SourceTemplate, Template: "{{ finding.secret_value }}"}, Target: Target{FieldID: "labels"}, Direction: DirOut},
		attrRow("e", "finding.severity", "customfield_1", DirIn, Transform{}),
		attrRow("f", "finding.assignee", "customfield_2", DirIn, Transform{}),
		attrRow("g", "finding.assignee", "customfield_3", DirIn, Transform{}),
	}}, nil)...)
	all = append(all, Validate(ObjectFinding, Spec{Minimization: MinFull, Fields: []Row{
		attrRow("a", "finding.title", "customfield_10042", DirOut, Transform{}),
		attrRow("b", "finding.assignee", "description", DirOut, Transform{}),
		attrRow("c", "finding.title", "duedate", DirOut, Transform{}),
		attrRow("d", "finding.title", "assignee", DirOut, Transform{}),
		attrRow("e", "finding.title", "labels", DirOut, Transform{}),
		{ID: "f", Source: Source{Kind: SourceTemplate, Template: "{{ finding.title }}"}, Target: Target{FieldID: "priority"}, Direction: DirOut},
		attrRow("g", "finding.severity", "priority", DirOut, Transform{Kind: TransformValueMap, Map: map[string]string{"critical": "Highest"}}),
		attrRow("h", "finding.title", "customfield_10050", DirOut, Transform{}),
		{ID: "i", Source: Source{Kind: SourceConst, Value: "Bad"}, Target: Target{FieldID: "customfield_10050"}, Direction: DirOut},
		attrRow("j", "finding.title", "customfield_7", DirOut, Transform{}),
		attrRow("k", "finding.assignee", "customfield_nope", DirIn, Transform{}),
		attrRow("l", "finding.title", "customfield_nope2", DirOut, Transform{}),
	}}, secMeta())...)
	all = append(all, Validate(ObjectFinding, Spec{Minimization: MinFull, Fields: []Row{
		attrRow("a", "finding.assignee", "description", DirIn, Transform{}),
		attrRow("b", "finding.title", "customfield_7", DirOut, Transform{}),
	}}, odd)...)
	all = append(all, Validate(ObjectFinding, Spec{Minimization: MinFull, Fields: []Row{
		{ID: "a", Source: Source{Kind: SourceAttr, Attr: "finding.assignee"}, Target: Target{FieldID: "assignee"}, Direction: DirBoth,
			Winner: WinnerTracker, Sync: SyncAlways},
		{ID: "b", Source: Source{Kind: SourceAttr, Attr: "finding.severity"}, Target: Target{FieldID: "labels"}, Direction: DirBoth,
			Transform: Transform{Kind: TransformValueMap, Map: map[string]string{"high": "x", "low": "x"}}},
	}}, secMeta())...)
	all = append(all, Validate(ObjectFinding, Spec{Minimization: MinSummary, Status: StatusMap{
		Outbound: map[string]StatusTarget{
			StateVerified:   {StatusID: "10"},
			StateInProgress: {StatusID: "3"},
			StateAccepted:   {StatusID: "77"},
			StateConfirmed:  {StatusID: "1", Resolution: "Bad"},
			StateNew:        {StatusID: "1"},
		},
		Inbound: []InboundRule{{Category: CategoryDone, Intent: IntentFixClaim}, {StatusID: "99", Intent: IntentFixClaim}},
	}}, secMeta())...)
	all = append(all, Validate(ObjectFinding, Spec{Minimization: MinSummary, Status: StatusMap{
		Outbound: map[string]StatusTarget{StateNew: {StatusID: "1"}},
	}}, noWorkflow)...)

	old := *secMeta()
	live := *secMeta()
	var kept []FieldMeta
	for _, f := range live.Fields {
		switch f.ID {
		case "customfield_10042":
			continue
		case "duedate":
			f.Name = "Target date"
		case "customfield_10050":
			f.AllowedValues = f.AllowedValues[:1]
		}
		kept = append(kept, f)
	}
	live.Fields = append(kept, FieldMeta{ID: "customfield_2", Name: "Squad", Required: true, Schema: FieldSchema{Type: "string"}})
	live.Workflow.Statuses = live.Workflow.Statuses[:3]
	all = append(all, Drift(old, live, Spec{Fields: []Row{
		{ID: "a", Target: Target{FieldID: "customfield_10042"}},
		{ID: "b", Target: Target{FieldID: "duedate"}},
		{ID: "c", Target: Target{FieldID: "customfield_10050"}},
	}})...)

	want := map[string][]string{
		"shape":                   {"detail"},
		"unknown_attr":            {"attr", "kind"},
		"minimized":               {"attr", "level"},
		"minimized_render":        {"attr", "level"},
		"template":                {"detail"},
		"inbound_forbidden":       {"attr"},
		"duplicate_inbound":       {"attr", "row"},
		"duplicate_target":        {"field", "row"},
		"unknown_field":           {"field", "issue_type", "project"},
		"required_unmapped":       {"name"},
		"unsupported_field":       {"name", "type"},
		"value_not_allowed":       {"value", "name"},
		"type_mismatch_number":    {"name"},
		"type_mismatch_text":      {"name"},
		"type_mismatch_date":      {"name"},
		"type_mismatch_user":      {"name"},
		"type_mismatch_list":      {"name"},
		"type_mismatch_value_map": {"name"},
		"value_map_gap":           {"name", "value"},
		"unchecked_values":        {"name"},
		"assignee_user_only":      nil,
		"not_invertible":          nil,
		"winner_sync":             nil,
		"tracker_unreachable":     nil,
		"no_metadata":             nil,
		"summary_default":         nil,
		"no_workflow":             nil,
		"status_missing":          {"state", "status"},
		"inbound_status_missing":  {"index"},
		"resolution_not_allowed":  {"state", "resolution"},
		"status_unreachable":      {"state", "status", "reason"},
		"status_partly_reachable": {"state", "status", "reason"},
		"status_unmapped":         {"status"},
		"field_removed":           {"name"},
		"field_renamed":           {"name", "new_name"},
		"value_removed":           {"value", "name"},
		"new_required_field":      {"name"},
		"status_removed":          {"name"},
	}
	all = append(all, TrackerUnreachable())
	byCode := map[string]Issue{}
	for _, i := range all {
		mc := i.MessageCode
		if mc == "" {
			mc = i.Code
		}
		if legacyCode(mc) != i.Code {
			t.Errorf("code %q changed: %q has legacy code %q", i.Code, mc, legacyCode(mc))
		}
		if _, ok := want[mc]; !ok {
			t.Errorf("code %q is not covered by this test (%s)", mc, i.Message)
		}
		byCode[mc] = i
	}
	var codesWanted []string
	for c := range want {
		codesWanted = append(codesWanted, c)
	}
	sort.Strings(codesWanted)
	for _, c := range codesWanted {
		i, ok := byCode[c]
		if !ok {
			t.Errorf("no scenario produced %q", c)
			continue
		}
		for _, k := range want[c] {
			if _, ok := i.Params[k]; !ok {
				t.Errorf("%s: missing param %q in %v", c, k, i.Params)
			}
		}
		if len(want[c]) == 0 && len(i.Params) != 0 {
			t.Errorf("%s: unexpected params %v", c, i.Params)
		}
	}
	// The value in params is the same one the English sentence names.
	if i := byCode["unknown_field"]; i.Params["project"] != "SEC" || i.Params["issue_type"] != "Bug" {
		t.Errorf("unknown_field params: %v", i.Params)
	}
}

func TestStatusInitialOnly_Params(t *testing.T) {
	// Only new issues are in a to-do status when nothing moves back to it.
	meta := secMeta()
	meta.Workflow.Transitions = meta.Workflow.Transitions[:3]
	got := Validate(ObjectFinding, Spec{Minimization: MinSummary, Status: StatusMap{
		Outbound: map[string]StatusTarget{StateNew: {StatusID: "1", Name: "To Do"}},
	}}, meta)
	for _, i := range got {
		if i.Code == "status_initial_only" {
			if i.State != StateNew || i.Params["status"] != `"To Do"` {
				t.Fatalf("params: %v %v", i.State, i.Params)
			}
			return
		}
	}
	t.Fatalf("no status_initial_only in %v", got)
}

func TestRender_NotesAndDroppedHaveCodes(t *testing.T) {
	spec := Spec{Minimization: MinSummary, Fields: []Row{
		attrRow("u1", "finding.assignee", "assignee", DirOut, Transform{Kind: TransformUser, FallbackAccount: "acc"}),
		attrRow("u2", "finding.assignee", "assignee", DirOut, Transform{Kind: TransformUser}),
		{ID: "o", Source: Source{Kind: SourceConst, Value: "Nope"}, Target: Target{FieldID: "customfield_10050"}, Direction: DirOut},
		{ID: "t", Source: Source{Kind: SourceTemplate, Template: "{{ finding.description }}"}, Target: Target{FieldID: "labels"}, Direction: DirOut},
		attrRow("m", "finding.description", "description", DirOut, Transform{}),
	}}
	noAccount := func(UserRef) string { return "" }
	r1 := RenderOutbound(ObjectFinding, spec, Values{"finding.assignee": UserValue(UserRef{Email: "a@example.test"})}, secMeta(), RenderOptions{Account: noAccount})
	r2 := RenderOutbound(ObjectFinding, spec, Values{}, secMeta(), RenderOptions{Account: noAccount})
	got := map[string]Issue{}
	for _, i := range append(append(r1.Notes, r2.Notes...), append(r1.Dropped, r2.Dropped...)...) {
		mc := i.MessageCode
		if mc == "" {
			mc = i.Code
		}
		got[mc] = i
	}
	for _, c := range []string{"note_no_assignee_fallback", "note_no_account_fallback", "note_no_account_unassigned", "note_value_not_allowed", "empty", "minimized"} {
		if _, ok := got[c]; !ok {
			t.Errorf("missing %q in %v", c, got)
		}
	}
	if got["note_value_not_allowed"].Params["value"] != "Nope" {
		t.Errorf("params: %v", got["note_value_not_allowed"].Params)
	}
	for _, i := range append(r1.Notes, r2.Notes...) {
		if i.Code != "note" || i.MessageCode == "" {
			t.Errorf("a note keeps code note and names its sentence: %v", i)
		}
	}
}

// Existing codes never change: a third-party client may read them.
func TestIssues_LegacyCodesStay(t *testing.T) {
	got := Validate(ObjectFinding, Spec{Minimization: MinFull, Fields: []Row{
		attrRow("a", "finding.title", "customfield_10042", DirOut, Transform{}),
	}}, secMeta())
	found := false
	for _, i := range got {
		if i.MessageCode == "type_mismatch_number" {
			found = i.Code == "type_mismatch"
		}
	}
	if !found {
		t.Fatalf("want code type_mismatch with message_code type_mismatch_number: %+v", got)
	}
	if i := TrackerUnreachable(); i.Code != "no_metadata" || i.MessageCode != "tracker_unreachable" {
		t.Fatalf("%+v", i)
	}
}
