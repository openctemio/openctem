package ticketmap

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func secMeta() *ProjectMeta {
	return &ProjectMeta{
		ProjectKey: "SEC", IssueTypeID: "10001", IssueType: "Bug",
		Fields: []FieldMeta{
			{ID: "summary", Name: "Summary", Required: true, Schema: FieldSchema{Type: "string", System: "summary"}},
			{ID: "description", Name: "Description", Schema: FieldSchema{Type: "string", System: "description"}},
			{ID: "priority", Name: "Priority", Schema: FieldSchema{Type: "priority"}, AllowedValues: []AllowedValue{
				{ID: "1", Name: "Highest"}, {ID: "2", Name: "High"}, {ID: "3", Name: "Medium"}, {ID: "4", Name: "Low"}, {ID: "5", Name: "Lowest"}}},
			{ID: "labels", Name: "Labels", Schema: FieldSchema{Type: "array", Items: "string"}},
			{ID: "duedate", Name: "Due date", Schema: FieldSchema{Type: "date"}},
			{ID: "assignee", Name: "Assignee", Schema: FieldSchema{Type: "user"}},
			{ID: "customfield_10042", Name: "CVSS", Schema: FieldSchema{Type: "number"}},
			{ID: "customfield_10050", Name: "Team", Required: true, Schema: FieldSchema{Type: "option"}, AllowedValues: []AllowedValue{{ID: "70", Name: "Payments"}, {ID: "71", Name: "Search"}}},
		},
		Workflow: simpleWorkflow(),
	}
}

func simpleWorkflow() Workflow {
	return Workflow{
		Statuses: []WorkflowStatus{
			{ID: "1", Name: "To Do", Category: CategoryNew},
			{ID: "3", Name: "In Progress", Category: CategoryIndeterminate},
			{ID: "4", Name: "In Review", Category: CategoryIndeterminate},
			{ID: "10", Name: "Done", Category: CategoryDone},
		},
		Transitions: []WorkflowTransition{
			{ID: "11", Name: "Start", From: []string{"1"}, To: "3"},
			{ID: "21", Name: "Review", From: []string{"3"}, To: "4"},
			{ID: "31", Name: "Close", From: []string{"4"}, To: "10", Fields: []TransitionField{
				{ID: "resolution", Name: "Resolution", Required: true, AllowedValues: []AllowedValue{{ID: "1", Name: "Done"}, {ID: "2", Name: "Won't Do"}}},
			}},
			{ID: "41", Name: "Reopen", From: []string{"10"}, To: "1"},
		},
		Resolutions: []AllowedValue{{ID: "1", Name: "Done"}, {ID: "2", Name: "Won't Do"}, {ID: "3", Name: "Duplicate"}, {ID: "4", Name: "Cannot Reproduce"}},
	}
}

func codes(issues []Issue) map[string]bool {
	m := map[string]bool{}
	for _, i := range issues {
		m[i.Code] = true
	}
	return m
}

func TestTemplate_ParseAndRender(t *testing.T) {
	tpl, err := ParseTemplate(ObjectFinding, `[{{ finding.severity | upper }}] {{ finding.title | truncate:10 }} {{ finding.cve_ids | join:" / " }} {{ finding.tool | default:"n/a" }}`)
	if err != nil {
		t.Fatal(err)
	}
	got := tpl.Render(Values{
		"finding.severity": Text("high"),
		"finding.title":    Text("SQL injection in search"),
		"finding.cve_ids":  List("CVE-1", "CVE-2"),
	})
	if got != "[HIGH] SQL injec… CVE-1 / CVE-2 n/a" {
		t.Fatalf("got %q", got)
	}
}

func TestTemplate_RejectsUnknownPathsFiltersAndOtherKinds(t *testing.T) {
	for _, src := range []string{
		"{{ finding.secret_value }}",
		"{{ task.title }}",                 // another object kind
		"{{ finding.title | exec:\"x\" }}", // unknown filter
		"{{ finding.title",                 // unclosed
		"{{ finding.title | truncate:0 }}",
	} {
		if _, err := ParseTemplate(ObjectFinding, src); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q: want validation error, got %v", src, err)
		}
	}
}

func TestValidate_FieldRules(t *testing.T) {
	spec := Spec{Minimization: MinSummary, Fields: []Row{
		{ID: "a", Source: Source{Kind: SourceAttr, Attr: "finding.severity"}, Target: Target{FieldID: "priority"}, Direction: DirOut,
			Transform: Transform{Kind: TransformValueMap, Map: map[string]string{"critical": "Urgent", "high": "High"}}},
		{ID: "b", Source: Source{Kind: SourceAttr, Attr: "finding.title"}, Target: Target{FieldID: "customfield_10042"}, Direction: DirOut},
		{ID: "c", Source: Source{Kind: SourceAttr, Attr: "finding.severity"}, Target: Target{FieldID: "labels"}, Direction: DirBoth},
		{ID: "d", Source: Source{Kind: SourceAttr, Attr: "finding.title"}, Target: Target{FieldID: "customfield_99999"}, Direction: DirOut},
		{ID: "e", Source: Source{Kind: SourceAttr, Attr: "finding.description"}, Target: Target{FieldID: "description"}, Direction: DirOut},
		{ID: "f", Source: Source{Kind: SourceAttr, Attr: "finding.tool"}, Target: Target{FieldID: "description"}, Direction: DirOut},
	}}
	got := codes(Validate(ObjectFinding, spec, secMeta()))
	for _, want := range []string{
		"value_not_allowed", // Urgent not in priority
		"type_mismatch",     // text into a number
		"inbound_forbidden", // severity can never flow in
		"unknown_field",     // customfield_99999
		"required_unmapped", // Team
		"minimized",         // description under summary
		"duplicate_target",  // two rows write description
		"value_map_gap",     // medium/low/info unmapped, no default
		"summary_default",   // no summary row
	} {
		if !got[want] {
			t.Errorf("missing issue %q in %v", want, got)
		}
	}
	if !HasErrors(Validate(ObjectFinding, spec, secMeta())) {
		t.Fatal("want errors")
	}
}

func TestValidate_InboundCapabilityCannotBeWidenedBySpec(t *testing.T) {
	for _, attr := range []string{"finding.severity", "finding.status", "finding.cvss_score", "finding.title"} {
		spec := Spec{Minimization: MinFull, Fields: []Row{{ID: "x", Source: Source{Kind: SourceAttr, Attr: attr},
			Target: Target{FieldID: "customfield_10042"}, Direction: DirIn}}}
		if !codes(Validate(ObjectFinding, spec, nil))["inbound_forbidden"] {
			t.Errorf("%s: inbound must be forbidden", attr)
		}
		// And the engine ignores it even if a stored spec carries it.
		if cmds := EvaluateInbound(ObjectFinding, spec, []FieldChange{{FieldID: "customfield_10042", To: "1"}}); len(cmds) != 0 {
			t.Errorf("%s: engine produced %v", attr, cmds)
		}
	}
}

func TestRender_MinimizationRedactionAndShapes(t *testing.T) {
	spec := Spec{Minimization: MinSummary, Fields: []Row{
		{ID: "s", Source: Source{Kind: SourceTemplate, Template: "{{ finding.title }} {{ finding.description }}"}, Target: Target{FieldID: "summary"}, Direction: DirOut},
		{ID: "p", Source: Source{Kind: SourceAttr, Attr: "finding.severity"}, Target: Target{FieldID: "priority"}, Direction: DirOut,
			Transform: Transform{Kind: TransformValueMap, Map: map[string]string{"high": "High"}, Default: "Medium"}},
		{ID: "l", Source: Source{Kind: SourceAttr, Attr: "finding.cve_ids"}, Target: Target{FieldID: "labels"}, Direction: DirOut, Transform: Transform{Kind: TransformList, Prefix: "cve:"}},
		{ID: "d", Source: Source{Kind: SourceAttr, Attr: "finding.sla_deadline"}, Target: Target{FieldID: "duedate"}, Direction: DirOut},
		{ID: "n", Source: Source{Kind: SourceAttr, Attr: "finding.cvss_score"}, Target: Target{FieldID: "customfield_10042"}, Direction: DirOut, Transform: Transform{Kind: TransformNumber, Round: 1}},
		{ID: "t", Source: Source{Kind: SourceConst, Value: "Payments"}, Target: Target{FieldID: "customfield_10050"}, Direction: DirOut, Sync: SyncCreate},
		{ID: "u", Source: Source{Kind: SourceAttr, Attr: "finding.assignee"}, Target: Target{FieldID: "assignee"}, Direction: DirOut, Transform: Transform{Kind: TransformUser, FallbackAccount: "acc-fallback"}},
	}}
	due := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	vals := Values{
		"finding.title":        Text("Leak AKIAABCDEFGHIJKLMNOP found"),
		"finding.description":  Text("full text that must not leave"),
		"finding.severity":     Text("high"),
		"finding.cve_ids":      List("CVE-2026-1", "CVE 2026 2"),
		"finding.sla_deadline": Date(due),
		"finding.cvss_score":   Number(9.87),
		"finding.assignee":     UserValue(UserRef{Email: "nobody@example.test"}),
	}
	redact := func(s string) string { return strings.ReplaceAll(s, "AKIAABCDEFGHIJKLMNOP", "[REDACTED]") }
	r := RenderOutbound(ObjectFinding, spec, vals, secMeta(), RenderOptions{Redact: redact, Creating: true, Account: func(UserRef) string { return "" }})
	if s := r.Fields["summary"].(string); strings.Contains(s, "AKIA") || strings.Contains(s, "must not leave") {
		t.Fatalf("summary leaked: %q", s)
	}
	if p := r.Fields["priority"].(map[string]string); p["id"] != "2" {
		t.Fatalf("priority by id: %v", p)
	}
	if l := r.Fields["labels"].([]string); strings.Join(l, ",") != "cve:CVE-2026-1,cve:CVE-2026-2" {
		t.Fatalf("labels: %v", l)
	}
	if r.Fields["duedate"] != "2026-10-22" || r.Fields["customfield_10042"] != 9.9 {
		t.Fatalf("date/number: %v %v", r.Fields["duedate"], r.Fields["customfield_10042"])
	}
	if o := r.Fields["customfield_10050"].(map[string]string); o["id"] != "70" {
		t.Fatalf("option: %v", o)
	}
	if a := r.Fields["assignee"].(map[string]string); a["accountId"] != "acc-fallback" {
		t.Fatalf("fallback assignee: %v", a)
	}
	// Create-only rows are not sent on update.
	r2 := RenderOutbound(ObjectFinding, spec, vals, secMeta(), RenderOptions{Redact: redact})
	if _, ok := r2.Fields["customfield_10050"]; ok {
		t.Fatal("create-only row sent on update")
	}
}

func TestWorkflow_PathAndPlan(t *testing.T) {
	wf := simpleWorkflow()
	steps, err := wf.Plan("1", StatusTarget{StatusID: "10", Resolution: "Done"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
	}
	if strings.Join(names, ">") != "Start>Review>Close" || steps[2].Fields["resolution"] != "Done" {
		t.Fatalf("plan: %+v", steps)
	}
	// A required resolution with no value is an error, not a guess.
	if _, err := wf.Plan("1", StatusTarget{StatusID: "10"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want error for missing required field, got %v", err)
	}
	// A resolution that is not allowed.
	if _, err := wf.Plan("4", StatusTarget{StatusID: "10", Resolution: "Fixed"}); err == nil {
		t.Fatal("want error for a resolution not allowed")
	}
	// Unreachable target.
	wf.Statuses = append(wf.Statuses, WorkflowStatus{ID: "99", Name: "Island", Category: CategoryIndeterminate})
	if _, err := wf.Path("1", "99"); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want ErrUnreachable, got %v", err)
	}
	// Global transitions (empty From) are usable from anywhere.
	wf.Transitions = append(wf.Transitions, WorkflowTransition{ID: "99", Name: "Park", To: "99"})
	if p, err := wf.Path("10", "99"); err != nil || len(p) != 1 {
		t.Fatalf("global transition: %v %v", p, err)
	}
}

func TestValidateStatus_UnreachableMissingAndUnmapped(t *testing.T) {
	meta := secMeta()
	meta.Fields = meta.Fields[:1]
	spec := Spec{Minimization: MinSummary, Status: StatusMap{
		Outbound: map[string]StatusTarget{
			StateVerified:   {StatusID: "10"},                   // resolution missing → unreachable
			StateInProgress: {StatusID: "3"},                    // fine (partly reachable: not from Done)
			StateAccepted:   {StatusID: "77"},                   // not in workflow
			StateConfirmed:  {StatusID: "1", Resolution: "Bad"}, // resolution does not exist
		},
		Inbound: []InboundRule{{Category: CategoryDone, Intent: IntentFixClaim}},
	}}
	got := codes(Validate(ObjectFinding, spec, meta))
	for _, want := range []string{"status_unreachable", "status_missing", "resolution_not_allowed", "status_unmapped"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

func TestInbound_IntentsAndDecisions(t *testing.T) {
	m := AutoMapStatus(ObjectFinding, simpleWorkflow())
	cases := []struct {
		ev        StatusEvent
		current   string
		cmd       string
		approval  bool
		mappedReq bool
	}{
		{StatusEvent{StatusID: "10", Category: CategoryDone, Resolution: "Done"}, StateInProgress, CmdClaimFix, false, true},
		{StatusEvent{StatusID: "10", Category: CategoryDone, Resolution: "Won't Do"}, StateConfirmed, CmdRequestAccept, true, true},
		{StatusEvent{StatusID: "10", Category: CategoryDone, Resolution: "Cannot Reproduce"}, StateConfirmed, CmdRequestFP, true, true},
		{StatusEvent{StatusID: "10", Category: CategoryDone, Resolution: "Duplicate"}, StateConfirmed, CmdSuggestDuplicate, false, true},
		{StatusEvent{StatusID: "3", Category: CategoryIndeterminate}, StateNew, CmdStartWork, false, true},
		// Closed in the tracker while OpenCTEM verifies: keep the claim (no ping-pong).
		{StatusEvent{StatusID: "10", Category: CategoryDone, Resolution: "Done"}, StateFixApplied, "", false, true},
		// Moved back to work after a claim: reopen.
		{StatusEvent{StatusID: "3", Category: CategoryIndeterminate}, StateFixApplied, CmdReopen, false, true},
		// A closed finding is never reopened from the tracker.
		{StatusEvent{StatusID: "3", Category: CategoryIndeterminate}, "resolved", "", false, true},
		{StatusEvent{StatusID: "10", Category: CategoryDone, Resolution: "Won't Do"}, StateAccepted, "", false, true},
	}
	for i, c := range cases {
		intent, mapped := m.IntentFor(c.ev)
		if mapped != c.mappedReq {
			t.Fatalf("case %d: mapped=%v", i, mapped)
		}
		d := DecideFinding(intent, c.current)
		if d.Command != c.cmd || d.NeedsApproval != c.approval {
			t.Errorf("case %d (%s on %s): got %+v", i, intent, c.current, d)
		}
	}
	if _, mapped := (StatusMap{}).IntentFor(StatusEvent{StatusID: "3"}); mapped {
		t.Fatal("empty map must report unmapped")
	}
}

func TestIsEcho(t *testing.T) {
	now := time.Now()
	last := LastPush{StatusID: "3", At: now}
	if !IsEcho(StatusEvent{StatusID: "3", At: now.Add(time.Minute)}, last, "") {
		t.Fatal("our own push within the window is an echo")
	}
	if IsEcho(StatusEvent{StatusID: "3", At: now.Add(20 * time.Minute)}, last, "") {
		t.Fatal("outside the window is a real change")
	}
	if IsEcho(StatusEvent{StatusID: "10", At: now.Add(time.Minute)}, last, "") {
		t.Fatal("another status is a real change")
	}
	if !IsEcho(StatusEvent{StatusID: "10", AuthorID: "bot"}, last, "bot") {
		t.Fatal("a change by our own account is an echo")
	}
}

func TestDeriveTaskState_MixedMembers(t *testing.T) {
	cases := []struct {
		c    MemberCounts
		want string
	}{
		{MemberCounts{New: 3}, TaskOpen},
		{MemberCounts{New: 2, InProgress: 1}, TaskInProgress},
		{MemberCounts{New: 1, FixApplied: 2, Resolved: 3, Verified: 3}, TaskInProgress},
		{MemberCounts{FixApplied: 2, Resolved: 3, Verified: 3}, TaskVerifying},
		{MemberCounts{Resolved: 2}, TaskVerifying},
		{MemberCounts{Resolved: 2, Verified: 1, Closed: 1}, TaskDone},
		{MemberCounts{Closed: 2}, TaskDone},
	}
	for _, c := range cases {
		if got := DeriveTaskState(c.c, false, false); got != c.want {
			t.Errorf("%+v: got %s want %s", c.c, got, c.want)
		}
	}
	if DeriveTaskState(MemberCounts{New: 1}, true, false) != TaskBlocked {
		t.Fatal("blocked wins")
	}
	if !strings.Contains(ProgressNote(MemberCounts{New: 1, FixApplied: 2, Resolved: 3, Verified: 3}), "3 of 6") {
		t.Fatal(ProgressNote(MemberCounts{New: 1, FixApplied: 2, Resolved: 3, Verified: 3}))
	}
}

func TestDrift(t *testing.T) {
	old := *secMeta()
	live := *secMeta()
	live.Fields = append([]FieldMeta{}, live.Fields...)
	// Remove CVSS, rename Due date, add a new required field, drop a status.
	var kept []FieldMeta
	for _, f := range live.Fields {
		switch f.ID {
		case "customfield_10042":
			continue
		case "duedate":
			f.Name = "Target date"
		}
		kept = append(kept, f)
	}
	live.Fields = append(kept, FieldMeta{ID: "customfield_2", Name: "Squad", Required: true, Schema: FieldSchema{Type: "string"}})
	live.Workflow.Statuses = live.Workflow.Statuses[:3]
	spec := Spec{Fields: []Row{
		{ID: "a", Target: Target{FieldID: "customfield_10042"}},
		{ID: "b", Target: Target{FieldID: "duedate"}},
	}}
	got := codes(Drift(old, live, spec))
	for _, want := range []string{"field_removed", "field_renamed", "new_required_field", "status_removed"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

func TestExportImport_RoundTripAndStrictness(t *testing.T) {
	p, _ := PresetByID(ObjectFinding, "security_bug")
	p.Spec.Status = AutoMapStatus(ObjectFinding, simpleWorkflow())
	for _, format := range []string{"json", "yaml"} {
		b, err := Export(Document{ObjectKind: ObjectFinding, Spec: p.Spec}, format)
		if err != nil {
			t.Fatal(err)
		}
		d, err := Import(b, ObjectFinding)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if len(d.Spec.Fields) != len(p.Spec.Fields) || len(d.Spec.Status.Inbound) != len(p.Spec.Status.Inbound) {
			t.Fatalf("%s: round trip lost data", format)
		}
		if _, err := Import(b, ObjectTask); err == nil {
			t.Fatalf("%s: wrong object kind accepted", format)
		}
	}
	if _, err := Import([]byte(`{"schema":"openctem.mapping/v1","object_kind":"finding","spec":{"minimization":"full","fields":[]},"exec":"x"}`), ObjectFinding); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := Import([]byte(strings.Repeat(" ", MaxDocumentBytes+1)), ObjectFinding); err == nil {
		t.Fatal("oversized document accepted")
	}
}

func TestPresetsValidateAgainstStockProject(t *testing.T) {
	meta := secMeta()
	meta.Fields = meta.Fields[:7] // without the required custom field
	for _, kind := range []ObjectKind{ObjectFinding, ObjectTask} {
		for _, p := range Presets(kind) {
			p.Spec.Status = AutoMapStatus(kind, meta.Workflow)
			if issues := Validate(kind, p.Spec, meta); HasErrors(issues) {
				t.Errorf("%s/%s: %+v", kind, p.ID, issues)
			}
		}
	}
}

func TestSuggestRows(t *testing.T) {
	rows := SuggestRows(ObjectFinding, Spec{}, *secMeta())
	found := false
	for _, r := range rows {
		if r.Target.FieldID == "customfield_10042" && r.Source.Attr == "finding.cvss_score" {
			found = true
		}
	}
	if !found {
		t.Fatalf("CVSS not suggested: %+v", rows)
	}
}

func TestRender_TemplateLinksSummaryAndLines(t *testing.T) {
	spec := Spec{Minimization: MinSummary, Fields: []Row{
		{ID: "s", Source: Source{Kind: SourceTemplate, Template: "[{{ finding.severity | upper }}] {{ finding.title }}"}, Target: Target{FieldID: "summary", Schema: FieldSchema{Type: "string"}}, Direction: DirOut},
		{ID: "d", Source: Source{Kind: SourceTemplate, Template: "Asset: {{ finding.asset_name }}\nOpen: {{ finding.url }}"}, Target: Target{FieldID: "description", Schema: FieldSchema{Type: "string"}}, Direction: DirOut},
	}}
	inline := func(s string, _ int) string { // stand-in encoder: escape brackets, defang
		return strings.NewReplacer("[", `\[`, "]", `\]`, "http://", "http[:]//", "https://", "https[:]//").Replace(s)
	}
	vals := Values{
		"finding.severity":   Text("high"),
		"finding.title":      Text("XSS [x|https://evil.test]"),
		"finding.asset_name": Text("zzoclink0000000000000000zz https://evil.test"),
		"finding.url":        Text("https://app.example.test/findings/1"),
	}
	r := RenderOutbound(ObjectFinding, spec, vals, nil, RenderOptions{EncodeInline: inline, EncodeSummary: func(s string, n int) string { return s }, Creating: true})
	if got := r.Fields["summary"]; got != "[HIGH] XSS [x|https://evil.test]" {
		t.Fatalf("summary is plain text, got %q", got)
	}
	d := r.Fields["description"].(string)
	if !strings.Contains(d, "Open: https://app.example.test/findings/1") {
		t.Fatalf("platform link not kept: %q", d)
	}
	if strings.Contains(d, "https://evil.test") || !strings.Contains(d, "\n") {
		t.Fatalf("value text not encoded or lines lost: %q", d)
	}
}
