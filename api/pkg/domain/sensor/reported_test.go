package sensor

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEffectiveValues(t *testing.T) {
	cases := []struct {
		name                   string
		declCaps               []string
		declMax                int
		reported               CapabilityReport
		wantTools, wantCaps    []string
		wantMax                int
		wantHasNuclei, wantCap bool
	}{
		{
			name:     "old sensor reports nothing: no tools, declared capabilities",
			declCaps: []string{"nuclei"}, declMax: 5,
			wantTools: []string{}, wantCaps: []string{"nuclei"}, wantMax: 5,
			wantHasNuclei: false, wantCap: true,
		},
		{
			name:      "no admin limit: everything reported (installed only)",
			declMax:   5,
			reported:  CapabilityReport{Tools: []ReportedTool{{Name: "nuclei", Installed: true}, {Name: "semgrep", Installed: false}}, Capabilities: []string{"nuclei", "validate"}, MaxConcurrentJobs: 3},
			wantTools: []string{"nuclei"}, wantCaps: []string{"nuclei", "validate"}, wantMax: 3,
			wantHasNuclei: true, wantCap: true,
		},
		{
			name:     "admin narrows capabilities; tools are every reported installed tool",
			declCaps: []string{"semgrep"}, declMax: 2,
			reported:  CapabilityReport{Tools: []ReportedTool{{Name: "nuclei", Installed: true}, {Name: "semgrep", Installed: true}}, Capabilities: []string{"nuclei", "semgrep"}, MaxConcurrentJobs: 10},
			wantTools: []string{"nuclei", "semgrep"}, wantCaps: []string{"semgrep"}, wantMax: 2,
			wantHasNuclei: true,
		},
		{
			name:     "reported but not installed is never dispatched",
			declCaps: []string{"nuclei"}, declMax: 5,
			reported:  CapabilityReport{Tools: []ReportedTool{{Name: "nuclei", Installed: false}}, Capabilities: []string{}},
			wantTools: []string{}, wantCaps: []string{}, wantMax: 5,
		},
		{
			name:      "reported none installed with no admin list",
			declMax:   5,
			reported:  CapabilityReport{Tools: []ReportedTool{}},
			wantTools: []string{}, wantCaps: []string{}, wantMax: 5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Sensor{Capabilities: tc.declCaps, MaxConcurrentJobs: tc.declMax, Reported: tc.reported}
			if got := a.EffectiveTools(); !reflect.DeepEqual(got, nonNil(tc.wantTools)) {
				t.Errorf("tools = %#v, want %#v", got, tc.wantTools)
			}
			if got := a.EffectiveCapabilities(); !reflect.DeepEqual(got, nonNil(tc.wantCaps)) {
				t.Errorf("caps = %#v, want %#v", got, tc.wantCaps)
			}
			if got := a.EffectiveMaxConcurrentJobs(); got != tc.wantMax {
				t.Errorf("max = %d, want %d", got, tc.wantMax)
			}
			if a.HasTool("nuclei") != tc.wantHasNuclei || a.HasCapability("nuclei") != tc.wantCap {
				t.Errorf("HasTool/HasCapability(nuclei) = %v/%v", a.HasTool("nuclei"), a.HasCapability("nuclei"))
			}
		})
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestCapacityUsesEffectiveMax(t *testing.T) {
	a := &Sensor{MaxConcurrentJobs: 5, CurrentJobs: 2, Reported: CapabilityReport{MaxConcurrentJobs: 2}}
	if a.HasCapacity() || a.AvailableSlots() != 0 || a.JobLoadPercent() != 100 {
		t.Fatalf("reported 2 must cap capacity: has=%v slots=%d load=%v", a.HasCapacity(), a.AvailableSlots(), a.JobLoadPercent())
	}
	a.Reported.MaxConcurrentJobs = 50 // reporting more never widens the admin limit
	if a.EffectiveMaxConcurrentJobs() != 5 || a.AvailableSlots() != 3 {
		t.Fatalf("effective = %d, slots = %d", a.EffectiveMaxConcurrentJobs(), a.AvailableSlots())
	}
}

func TestCapabilityMismatch(t *testing.T) {
	a := &Sensor{Capabilities: []string{"nuclei", "validate"}, MaxConcurrentJobs: 8}
	if !a.CapabilityMismatch().IsEmpty() {
		t.Fatal("no report, no mismatch")
	}
	a.Reported = CapabilityReport{
		Tools:             []ReportedTool{{Name: "semgrep", Installed: true}, {Name: "nuclei", Installed: false}},
		Capabilities:      []string{"nuclei"},
		MaxConcurrentJobs: 4,
	}
	m := a.CapabilityMismatch()
	if !reflect.DeepEqual(m.CapabilitiesNotReported, []string{"validate"}) {
		t.Fatalf("mismatch = %+v", m)
	}
}

func TestSanitizeCapabilityReport(t *testing.T) {
	known := map[string]bool{"nuclei": true, "semgrep": true, "trivy": true}
	caps := map[string]bool{"sast": true}
	in := CapabilityReportInput{
		Tools: []ReportedTool{
			{Name: "Nuclei", Version: "v3.3.0", Installed: true},
			{Name: "semgrep", Version: "1.90.0; rm -rf /", Installed: true},
			{Name: "evil-tool", Installed: true},            // not in the catalog
			{Name: "../../etc/passwd", Installed: true},     // malformed
			{Name: "nuclei", Version: "", Installed: false}, // duplicate: installed wins
			{Name: "trivy", Installed: false},
		},
		Capabilities:      []string{"sast", "validate", "validate:nuclei", "validate:evil", "nuclei", "made-up", "SAST", strings.Repeat("a", 100)},
		MaxConcurrentJobs: 1_000_000,
		OS:                "Linux;id",
		Arch:              "amd64",
	}
	out := in.Sanitize(known, caps)
	wantTools := []ReportedTool{
		{Name: "nuclei", Version: "v3.3.0", Installed: true},
		{Name: "semgrep", Version: "1.90.0rm-rf", Installed: true},
		{Name: "trivy", Installed: false},
	}
	if !reflect.DeepEqual(out.Tools, wantTools) {
		t.Errorf("tools = %#v", out.Tools)
	}
	if want := []string{"sast", "validate", "validate:nuclei", "nuclei"}; !reflect.DeepEqual(out.Capabilities, want) {
		t.Errorf("caps = %#v, want %#v", out.Capabilities, want)
	}
	if out.MaxConcurrentJobs != MaxReportedJobs {
		t.Errorf("max jobs not clamped: %d", out.MaxConcurrentJobs)
	}
	if out.OS != "linuxid" || out.Arch != "amd64" {
		t.Errorf("os/arch = %q/%q", out.OS, out.Arch)
	}

	// Lists that were reported stay non-nil even if nothing survives.
	none := CapabilityReportInput{Tools: []ReportedTool{{Name: "evil", Installed: true}}, Capabilities: []string{"made-up"}}.Sanitize(known, caps)
	if none.Tools == nil || len(none.Tools) != 0 || none.Capabilities == nil || len(none.Capabilities) != 0 {
		t.Errorf("reported-but-unknown must be an empty report: %#v", none)
	}
	// Nothing reported stays nothing.
	if r := (CapabilityReportInput{}).Sanitize(known, caps); r.HasReport() {
		t.Errorf("empty input reported something: %#v", r)
	}
	// Negative concurrency is "not reported".
	if r := (CapabilityReportInput{MaxConcurrentJobs: -3}).Sanitize(known, caps); r.MaxConcurrentJobs != 0 {
		t.Errorf("negative max jobs = %d", r.MaxConcurrentJobs)
	}
}

func TestSanitizeCapsListSizes(t *testing.T) {
	known := map[string]bool{}
	in := CapabilityReportInput{}
	for i := range MaxReportedTools * 3 {
		name := "t" + strings.Repeat("x", i%10) + string(rune('a'+i%26))
		known[name] = true
		in.Tools = append(in.Tools, ReportedTool{Name: name, Installed: true})
	}
	out := in.Sanitize(known, nil)
	if len(out.Tools) > MaxReportedTools {
		t.Fatalf("tools not capped: %d", len(out.Tools))
	}
	tools, _ := in.CatalogCandidates()
	if len(tools) > MaxReportedTools+MaxReportedCapabilities {
		t.Fatalf("candidates not capped: %d", len(tools))
	}
}

func TestCatalogCandidates(t *testing.T) {
	in := CapabilityReportInput{
		Tools:        []ReportedTool{{Name: "Nuclei"}, {Name: "nuclei"}, {Name: "bad name"}},
		Capabilities: []string{"validate:semgrep", "sast", "sast"},
	}
	tools, caps := in.CatalogCandidates()
	if want := []string{"nuclei", "semgrep", "sast"}; !reflect.DeepEqual(tools, want) {
		t.Errorf("tool candidates = %#v, want %#v", tools, want)
	}
	if want := []string{"validate:semgrep", "sast"}; !reflect.DeepEqual(caps, want) {
		t.Errorf("cap candidates = %#v", caps)
	}
}

// Fleet health's no_tools reason looks at the effective tools.
func TestAssessHealth_NoToolsUsesEffectiveTools(t *testing.T) {
	p := testPolicy()
	reportsNuclei := daemon(ago(5 * time.Second))
	reportsNuclei.Reported = CapabilityReport{Tools: []ReportedTool{{Name: "nuclei", Installed: true}}}
	if a := reportsNuclei.AssessHealth(testNow, p); hasCode(a.Reasons, ReasonNoTools) {
		t.Errorf("a sensor reporting nuclei has no_tools: %v", codes(a.Reasons))
	}
	missing := daemon(ago(5 * time.Second)) // reports nuclei installed
	missing.Reported = CapabilityReport{Tools: []ReportedTool{{Name: "nuclei", Installed: false}}}
	a := missing.AssessHealth(testNow, p)
	if !hasCode(a.Reasons, ReasonNoTools) {
		t.Fatalf("reported-but-missing tool not flagged: %v", codes(a.Reasons))
	}
	for _, r := range a.Reasons {
		if r.Code == ReasonNoTools && !strings.Contains(r.Message, "installed") {
			t.Errorf("message does not explain the report: %q", r.Message)
		}
	}
}

// Each tool keeps its kind and its own capabilities (known names only), and
// the catalog lookup covers them.
func TestSanitizeToolKindAndCapabilities(t *testing.T) {
	known := map[string]bool{"nuclei": true, "semgrep": true}
	caps := map[string]bool{"dast": true, "sast": true}
	in := CapabilityReportInput{Tools: []ReportedTool{
		{Name: "nuclei", Kind: "Scanner", Installed: true, Capabilities: []string{"dast", "DAST", "validate:nuclei", "made-up", "validate:evil"}},
		{Name: "semgrep", Kind: "rootkit", Installed: true, Capabilities: []string{}},
	}}
	_, lookup := in.CatalogCandidates()
	if !reflect.DeepEqual(lookup, []string{"dast", "validate:nuclei", "made-up", "validate:evil"}) {
		t.Errorf("catalog lookup = %#v", lookup)
	}
	out := in.Sanitize(known, caps)
	want := []ReportedTool{
		{Name: "nuclei", Kind: ToolKindScanner, Installed: true, Capabilities: []string{"dast", "validate:nuclei"}},
		{Name: "semgrep", Installed: true, Capabilities: []string{}},
	}
	if !reflect.DeepEqual(out.Tools, want) {
		t.Errorf("tools = %#v", out.Tools)
	}
	// An older SDK sends neither: nil stays nil.
	old := CapabilityReportInput{Tools: []ReportedTool{{Name: "nuclei", Installed: true}}}.Sanitize(known, caps)
	if old.Tools[0].Kind != "" || old.Tools[0].Capabilities != nil {
		t.Errorf("old sdk tool = %#v", old.Tools[0])
	}
	// A long list is capped.
	many := make([]string, 0, 3*MaxReportedToolCapabilities)
	for range 3 * MaxReportedToolCapabilities {
		many = append(many, "dast")
	}
	many = append(many, "sast")
	capped := CapabilityReportInput{Tools: []ReportedTool{{Name: "nuclei", Capabilities: many}}}.Sanitize(known, caps)
	if got := capped.Tools[0].Capabilities; !reflect.DeepEqual(got, []string{"dast"}) {
		t.Errorf("capped = %#v", got)
	}
}

// What the sensor can run now (its reported slots) bounds its capacity:
// live, a 4-core sensor reported 64 as its ceiling, 4 slots, and the admin
// limit is 5.
func TestEffectiveMaxJobsBoundedBySlots(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		admin, ceiling, slots int
		want                  int
	}{
		{"live", 5, 64, 4, 4},
		{"slots only", 5, 0, 4, 4},
		{"slots above limits", 5, 3, 8, 3},
		{"no load report", 5, 64, 0, 5},
		{"nothing at all", 0, 0, 0, 0},
		{"no admin limit", 0, 0, 6, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Sensor{MaxConcurrentJobs: tc.admin, Reported: CapabilityReport{MaxConcurrentJobs: tc.ceiling}}
			if tc.slots > 0 {
				a.Load.Capacity = &ReportedCapacity{SlotsTotal: tc.slots}
			}
			if got := a.EffectiveMaxConcurrentJobs(); got != tc.want {
				t.Fatalf("effective = %d, want %d", got, tc.want)
			}
		})
	}
}

// The tools dispatch uses are exactly the installed tools the sensor
// reported, in its order: there is no declared list to narrow or widen them
// (the sensor grant narrows them, grant.go), and a sensor that never
// reported has none, whatever it was created with.
func TestEffectiveToolsAreTheReportedInstalledTools(t *testing.T) {
	a := &Sensor{}
	if got := a.EffectiveTools(); got == nil || len(got) != 0 || a.HasTool("nuclei") {
		t.Fatalf("never reported: %#v", got)
	}
	a.Reported = CapabilityReport{Tools: []ReportedTool{
		{Name: "trivy", Installed: true}, {Name: "nuclei", Installed: false}, {Name: "semgrep", Installed: true},
	}}
	if got := a.EffectiveTools(); !reflect.DeepEqual(got, []string{"trivy", "semgrep"}) {
		t.Fatalf("effective = %#v, want the installed reported tools", got)
	}
	got := a.EffectiveTools()
	got[0] = "x"
	if a.EffectiveTools()[0] != "trivy" {
		t.Fatal("EffectiveTools must return a copy")
	}
}
