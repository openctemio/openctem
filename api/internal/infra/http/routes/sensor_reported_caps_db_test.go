package routes

// Sensor-reported capabilities (RFC-029 §4.3.1), end to end over the real
// sensor routes against a migrated database: a sensor reports its tools,
// capabilities and concurrency on the heartbeat (v2 and v1), the report is
// sanitized and stored, and dispatch (the selector and the command poll)
// uses the effective values: what the sensor reports, narrowed by the
// administrator. Tools a sensor never reported are unverified and get no
// work; capabilities keep the administrator's values for such a sensor.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/command"
	sensorsvc "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func (h *ctlHarness) newLimitedSensor(tenantID, name string, tools, caps []string, maxJobs int) ctlSensor {
	h.t.Helper()
	out, err := h.sensors.CreateSensor(context.Background(), sensorsvc.CreateSensorInput{TenantID: tenantID, Name: name,
		Type: "worker", Capabilities: caps, Tools: tools, ExecutionMode: "daemon", MaxConcurrentJobs: maxJobs})
	if err != nil {
		h.t.Fatalf("create sensor: %v", err)
	}
	return ctlSensor{id: out.Sensor.ID.String(), key: out.APIKey}
}

// verifyTools records the sensor's declared tools as reported installed, as
// a sensor on a current SDK does on its first heartbeat. Dispatch only sends
// a sensor the tools it verified.
func (h *ctlHarness) verifyTools(s ctlSensor) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(),
		`UPDATE sensors SET reported_tool_names = tools, reported_at = now() WHERE id = $1`, s.id); err != nil {
		h.t.Fatalf("verify tools: %v", err)
	}
}

// newVerifiedSensor is newLimitedSensor for a sensor that verified its tools.
func (h *ctlHarness) newVerifiedSensor(tenantID, name string, tools, caps []string, maxJobs int) ctlSensor {
	h.t.Helper()
	s := h.newLimitedSensor(tenantID, name, tools, caps, maxJobs)
	h.verifyTools(s)
	return s
}

func (h *ctlHarness) heartbeatV2(s ctlSensor, body map[string]any) {
	h.t.Helper()
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", body)
	h.want(resp, raw, 200, "")
}

func (h *ctlHarness) load(s ctlSensor) *sensor.Sensor {
	h.t.Helper()
	got, err := h.repo.GetByID(context.Background(), shared.MustIDFromString(s.id))
	if err != nil {
		h.t.Fatal(err)
	}
	return got
}

func (h *ctlHarness) selector() *sensorsvc.SensorSelector {
	return sensorsvc.NewSensorSelector(h.repo, nil, nil, logger.NewNop())
}

func ids(ss []*sensor.Sensor) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.ID.String())
	}
	slices.Sort(out)
	return out
}

func TestReportedCaps_DispatchByReportedTool(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	tid := shared.MustIDFromString(h.tenantID)

	// A: no administrator limits; reports nuclei installed.
	a := h.newLimitedSensor(h.tenantID, "reports-nuclei", nil, nil, 0)
	h.heartbeatV2(a, map[string]any{"status": "running",
		"tools":        []map[string]any{{"name": "nuclei", "version": "3.3.0", "installed": true}, {"name": "semgrep", "installed": false}},
		"capabilities": []string{"nuclei", "dast"}, "max_concurrent_jobs": 3, "os": "linux", "arch": "amd64"})
	// B: the administrator declared nuclei, the sensor reports it missing.
	b := h.newLimitedSensor(h.tenantID, "declared-nuclei", []string{"nuclei"}, []string{"nuclei"}, 0)
	h.heartbeatV2(b, map[string]any{"status": "running",
		"tools": []map[string]any{{"name": "nuclei", "installed": false}}, "capabilities": []string{}})
	// C: an old sensor that reports nothing, declared semgrep (v1 heartbeat).
	c := h.newLimitedSensor(h.tenantID, "old-semgrep", []string{"semgrep"}, []string{"semgrep"}, 0)
	resp, raw := h.call(c.key, http.MethodPost, "/api/v1/agent/heartbeat", map[string]any{"status": "running"})
	h.want(resp, raw, 200, "")

	got := h.load(a)
	if got.Reported.ReportedAt == nil || got.Reported.OS != "linux" || got.Reported.Arch != "amd64" ||
		got.Reported.MaxConcurrentJobs != 3 || len(got.Reported.Tools) != 2 {
		t.Fatalf("A report not stored: %+v", got.Reported)
	}

	nuclei, err := h.repo.FindAvailableWithCapacity(ctx, tid, []string{"nuclei"}, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{a.id}; !slices.Equal(ids(nuclei), want) {
		t.Fatalf("nuclei candidates %v, want only A %v (B lacks the tool)", ids(nuclei), want)
	}
	res, err := h.selector().SelectSensor(ctx, sensorsvc.SelectSensorRequest{TenantID: tid, Capabilities: []string{"nuclei"}, Tool: "nuclei"})
	if err != nil || res.Sensor == nil || res.Sensor.ID.String() != a.id {
		t.Fatalf("selector picked %+v, %v; want A", res, err)
	}

	semgrep, err := h.repo.FindAvailableWithCapacity(ctx, tid, []string{"semgrep"}, "semgrep")
	if err != nil {
		t.Fatal(err)
	}
	if len(semgrep) != 0 {
		t.Fatalf("semgrep candidates %v, want none: A reports semgrep not installed and C never verified its declared semgrep", ids(semgrep))
	}

	tools, err := h.repo.GetAvailableToolsForTenant(ctx, tid)
	if err != nil || strings.Join(tools, ",") != "nuclei" {
		t.Fatalf("available tools %v %v", tools, err)
	}
	if ok, _ := h.repo.HasSensorForTool(ctx, tid, "nuclei"); !ok {
		t.Fatal("HasSensorForTool(nuclei) = false")
	}
	if ok, _ := h.repo.HasSensorForCapability(ctx, tid, "dast"); !ok {
		t.Fatal("HasSensorForCapability(dast) = false: reported capability not used")
	}

	// B: declared but not installed is shown.
	bs := h.load(b)
	if m := bs.CapabilityMismatch(); !slices.Equal(m.ToolsNotInstalled, []string{"nuclei"}) ||
		!slices.Equal(m.CapabilitiesNotReported, []string{"nuclei"}) {
		t.Fatalf("B mismatch %+v", m)
	}
}

// The administrator's list narrows the report and the report never widens
// it; unknown and malformed names, oversized lists and absurd concurrency
// are dropped or clamped.
func TestReportedCaps_MaliciousReportIsBounded(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	tid := shared.MustIDFromString(h.tenantID)
	s := h.newLimitedSensor(h.tenantID, "limited", []string{"semgrep"}, []string{"semgrep"}, 5)

	tools := []map[string]any{
		{"name": "nuclei", "installed": true},
		{"name": "semgrep", "version": "1.90.0$(id)", "installed": true},
		{"name": "evil", "installed": true},
		{"name": "../../etc/passwd", "installed": true},
	}
	for i := range 300 {
		tools = append(tools, map[string]any{"name": "zz" + strings.Repeat("x", i%40), "installed": true})
	}
	h.heartbeatV2(s, map[string]any{"status": "running", "tools": tools,
		"capabilities":        []string{"semgrep", "nuclei", "validate:evil", strings.Repeat("c", 200), "validate"},
		"max_concurrent_jobs": 1_000_000_000, "os": "linux; rm -rf /", "arch": strings.Repeat("a", 500)})

	got := h.load(s)
	names := make([]string, 0, len(got.Reported.Tools))
	for _, t := range got.Reported.Tools {
		names = append(names, t.Name)
	}
	if strings.Join(names, ",") != "nuclei,semgrep" {
		t.Fatalf("stored tools %v: unknown or malformed names kept", names)
	}
	if got.Reported.Tools[1].Version != "1.90.0id" {
		t.Fatalf("version not sanitized: %q", got.Reported.Tools[1].Version)
	}
	if !slices.Equal(got.Reported.Capabilities, []string{"semgrep", "nuclei", "validate"}) {
		t.Fatalf("stored capabilities %v", got.Reported.Capabilities)
	}
	if got.Reported.MaxConcurrentJobs != sensor.MaxReportedJobs || got.Reported.OS != "linuxrmrf" || len(got.Reported.Arch) != sensor.MaxReportedPlatformLen {
		t.Fatalf("not clamped: max=%d os=%q arch=%d", got.Reported.MaxConcurrentJobs, got.Reported.OS, len(got.Reported.Arch))
	}
	// Narrow only: semgrep (allowed and installed), never nuclei; capacity
	// stays at the administrator's 5.
	if !slices.Equal(got.EffectiveTools(), []string{"semgrep"}) || got.EffectiveMaxConcurrentJobs() != 5 {
		t.Fatalf("effective tools %v max %d", got.EffectiveTools(), got.EffectiveMaxConcurrentJobs())
	}
	if c, _ := h.repo.FindAvailableWithCapacity(ctx, tid, []string{"nuclei"}, "nuclei"); len(c) != 0 {
		t.Fatalf("a report widened the administrator's tool list: %v", ids(c))
	}
	var dbTools []string
	var dbMax int
	if err := h.db.QueryRowContext(ctx, `SELECT array_to_json(effective_tools)::text, effective_max_jobs FROM sensors WHERE id = $1`, s.id).
		Scan(jsonStrings(&dbTools), &dbMax); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dbTools, got.EffectiveTools()) || dbMax != got.EffectiveMaxConcurrentJobs() {
		t.Fatalf("database effective %v/%d differs from the domain %v/%d", dbTools, dbMax, got.EffectiveTools(), got.EffectiveMaxConcurrentJobs())
	}
}

// The reported concurrency caps what dispatch hands the sensor: free slots
// are the effective capacity minus the commands it holds (RFC-030 D5).
func TestReportedCaps_CapacityIsTheSmaller(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	tid := shared.MustIDFromString(h.tenantID)
	s := h.newLimitedSensor(h.tenantID, "one-at-a-time", nil, nil, 5)
	h.heartbeatV2(s, map[string]any{"status": "running", "max_concurrent_jobs": 1,
		"tools": []map[string]any{{"name": "nuclei", "installed": true}}})
	id := shared.MustIDFromString(s.id)
	if got, _ := h.repo.FindAvailableWithTool(ctx, tid, "nuclei"); got == nil || got.ID != id {
		t.Fatalf("an idle sensor with one slot was not picked: %v", got)
	}
	cmd, err := h.cmds.Create(ctx, command.CreateInput{TenantID: h.tenantID, Type: "scan", Priority: "normal",
		Payload: json.RawMessage(`{"scanner":"nuclei"}`), ExpiresIn: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.ExecContext(ctx, `UPDATE commands SET status = 'acknowledged', sensor_id = $2 WHERE id = $1`,
		cmd.ID.String(), s.id); err != nil {
		t.Fatal(err)
	}
	got, err := h.repo.GetByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentJobs != 1 || got.FreeSlots(time.Now()) != 0 {
		t.Fatalf("holding one command at a concurrency of 1: current %d, free %d; want 1, 0", got.CurrentJobs, got.FreeSlots(time.Now()))
	}
	if picked, _ := h.repo.FindAvailableWithTool(ctx, tid, "nuclei"); picked != nil {
		t.Fatalf("a full sensor was picked: %v", picked.ID)
	}
}

// The command poll gates capability-scoped commands on the effective
// capabilities; a sensor that never reported keeps its declared ones.
func TestReportedCaps_PollUsesEffectiveCapabilities(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	newValidate := func() string {
		cmd, err := h.cmds.Create(ctx, command.CreateInput{TenantID: h.tenantID, Type: "validate", Priority: "normal",
			Payload: json.RawMessage(`{"required_capabilities":["validate"]}`), ExpiresIn: 3600})
		if err != nil {
			t.Fatal(err)
		}
		return cmd.ID.String()
	}
	polled := func(s ctlSensor, v2 bool) []string {
		t.Helper()
		path := "/api/v1/agent/commands"
		if v2 {
			path = "/api/v2/sensor/commands"
		}
		resp, raw := h.call(s.key, http.MethodGet, path, nil)
		h.want(resp, raw, 200, "")
		type idOnly struct {
			ID string `json:"id"`
		}
		var out []idOnly
		if v2 {
			var l struct {
				Commands []idOnly `json:"commands"`
			}
			_ = json.Unmarshal(raw, &l)
			out = l.Commands
		} else {
			_ = json.Unmarshal(raw, &out) // v1: a bare array
		}
		var got []string
		for _, c := range out {
			got = append(got, c.ID)
		}
		return got
	}

	cmd := newValidate()
	reports := h.newLimitedSensor(h.tenantID, "reports-validate", nil, nil, 0)
	h.heartbeatV2(reports, map[string]any{"capabilities": []string{"validate"}})
	declaredOnly := h.newLimitedSensor(h.tenantID, "declared-validate", nil, []string{"validate"}, 0)
	h.heartbeatV2(declaredOnly, map[string]any{"capabilities": []string{}})
	old := h.newLimitedSensor(h.tenantID, "old-validate", nil, []string{"validate"}, 0)

	if !slices.Contains(polled(reports, true), cmd) {
		t.Fatal("a sensor that reports validate does not see the validate command (v2)")
	}
	if slices.Contains(polled(declaredOnly, true), cmd) || slices.Contains(polled(declaredOnly, false), cmd) {
		t.Fatal("a sensor whose report lacks validate sees the validate command")
	}
	if !slices.Contains(polled(old, false), cmd) {
		t.Fatal("an old sensor lost its declared capability (v1)")
	}
}

// A heartbeat without a report (an old SDK, a connection test) leaves the
// stored report as it is; a report of tools only leaves the capabilities.
func TestReportedCaps_AbsentPartsAreKept(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newLimitedSensor(h.tenantID, "keeps", nil, nil, 0)
	h.heartbeatV2(s, map[string]any{"tools": []map[string]any{{"name": "nuclei", "installed": true}},
		"capabilities": []string{"dast"}, "max_concurrent_jobs": 2})
	first := h.load(s).Reported

	resp, raw := h.call(s.key, http.MethodPost, "/api/v1/agent/heartbeat", map[string]any{"status": "running"})
	h.want(resp, raw, 200, "")
	h.heartbeatV2(s, map[string]any{"tools": []map[string]any{{"name": "semgrep", "installed": true}}})

	got := h.load(s).Reported
	if len(got.Tools) != 1 || got.Tools[0].Name != "semgrep" {
		t.Fatalf("tools not replaced: %+v", got.Tools)
	}
	if !slices.Equal(got.Capabilities, first.Capabilities) || got.MaxConcurrentJobs != 2 {
		t.Fatalf("unreported parts changed: %+v (was %+v)", got, first)
	}
}

// jsonStrings scans a JSON array of strings.
type jsonStringsScanner struct{ dst *[]string }

func jsonStrings(dst *[]string) *jsonStringsScanner { return &jsonStringsScanner{dst} }

func (s *jsonStringsScanner) Scan(src any) error {
	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	case nil:
		*s.dst = nil
		return nil
	}
	return json.Unmarshal(b, s.dst)
}

// A scan for a tool is offered (poll and doorbell count) only to sensors
// whose effective tools include it (the RFC-030 tool gate reads
// effective_tools): the reported inventory narrowed by the limit, or the
// declared tools of a sensor that never reported.
func TestReportedCaps_PollOffersToolScansOnlyToSensorsWithTheTool(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	has := h.newLimitedSensor(h.tenantID, "has-nuclei", nil, nil, 0)
	h.heartbeatV2(has, map[string]any{"tools": []map[string]any{{"name": "nuclei", "installed": true}}})
	lacks := h.newLimitedSensor(h.tenantID, "lacks-nuclei", []string{"nuclei"}, nil, 0)
	h.heartbeatV2(lacks, map[string]any{"tools": []map[string]any{{"name": "nuclei", "installed": false}, {"name": "semgrep", "installed": true}}})
	old := h.newLimitedSensor(h.tenantID, "old", []string{"nuclei"}, nil, 0)
	oldNoTools := h.newLimitedSensor(h.tenantID, "old-no-tools", nil, nil, 0)

	cmd, err := h.cmds.Create(ctx, command.CreateInput{TenantID: h.tenantID, Type: "scan", Priority: "normal",
		Payload: json.RawMessage(`{"scanner":"nuclei","target":"https://example.test"}`), ExpiresIn: 3600})
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.cmds.Create(ctx, command.CreateInput{TenantID: h.tenantID, Type: "health_check", Priority: "normal",
		Payload: json.RawMessage(`{}`), ExpiresIn: 3600})
	if err != nil {
		t.Fatal(err)
	}
	poll := func(s ctlSensor) []string {
		t.Helper()
		resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands", nil)
		h.want(resp, raw, 200, "")
		var l struct {
			Commands []struct {
				ID string `json:"id"`
			} `json:"commands"`
		}
		_ = json.Unmarshal(raw, &l)
		var out []string
		for _, c := range l.Commands {
			out = append(out, c.ID)
		}
		return out
	}
	if got := poll(has); !slices.Contains(got, cmd.ID.String()) {
		t.Fatalf("the sensor with nuclei is not offered the nuclei scan: %v", got)
	}
	if got := poll(lacks); slices.Contains(got, cmd.ID.String()) || !slices.Contains(got, other.ID.String()) {
		t.Fatalf("the sensor without nuclei: %v (must not see the scan, must see the tool-less command)", got)
	}
	if got := poll(old); slices.Contains(got, cmd.ID.String()) || !slices.Contains(got, other.ID.String()) {
		t.Fatalf("a sensor that never reported: %v (its declared nuclei is unverified, so no scan; the tool-less command still)", got)
	}
	if got := poll(oldNoTools); slices.Contains(got, cmd.ID.String()) {
		t.Fatalf("a sensor with no tools at all is offered a nuclei scan: %v", got)
	}
	// The doorbell counts what the poll offers.
	resp, raw := h.call(lacks.key, http.MethodPost, "/api/v2/sensor/heartbeat", map[string]any{"status": "running"})
	h.want(resp, raw, 200, "")
	var hb struct {
		PendingJobs int `json:"pending_jobs"`
	}
	_ = json.Unmarshal(raw, &hb)
	if hb.PendingJobs != 1 {
		t.Fatalf("doorbell pending_jobs = %d for the sensor without nuclei, want 1 (the health check)", hb.PendingJobs)
	}
}

// The live upgrade path (RFC-033 §6.1): a sensor on sdk-go before v0.13
// reported its resource manager's bound 64 as max_concurrent_jobs; on
// v0.13 it reports its slots and no ceiling, which clears the stored 64.
// A heartbeat without a load report (an older SDK) never clears it, and
// per-tool kind and capabilities arrive end to end through the handler.
func TestHeartbeat_NoCeilingClearsTheOldUpperBound(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newLimitedSensor(h.tenantID, "upgraded", nil, nil, 5)
	nuclei := map[string]any{"name": "nuclei", "kind": "scanner", "version": "v3.11.1", "installed": true,
		"capabilities": []string{"dast", "validate:nuclei"}}
	capacity := map[string]any{"slots_total": 4, "slots_free": 4, "active_jobs": 0}

	// sdk-go v0.11: the bound 64 and the slots.
	h.heartbeatV2(s, map[string]any{"status": "running", "tools": []any{nuclei},
		"capabilities": []string{"nuclei", "dast", "validate:nuclei"}, "max_concurrent_jobs": 64, "capacity": capacity})
	got := h.load(s)
	if got.Reported.MaxConcurrentJobs != 64 || got.EffectiveMaxConcurrentJobs() != 4 {
		t.Fatalf("old sdk: ceiling %d effective %d, want 64 and 4", got.Reported.MaxConcurrentJobs, got.EffectiveMaxConcurrentJobs())
	}
	if tl := got.Reported.Tools; len(tl) != 1 || tl[0].Kind != "scanner" || strings.Join(tl[0].Capabilities, ",") != "dast,validate:nuclei" {
		t.Fatalf("per-tool fields not stored: %+v", tl)
	}

	// A heartbeat with a report but no load report keeps it.
	h.heartbeatV2(s, map[string]any{"status": "running", "tools": []any{nuclei},
		"capabilities": []string{"nuclei", "dast", "validate:nuclei"}})
	if got := h.load(s); got.Reported.MaxConcurrentJobs != 64 {
		t.Fatalf("cleared without a load report: %d", got.Reported.MaxConcurrentJobs)
	}

	// sdk-go v0.13: slots, no ceiling.
	h.heartbeatV2(s, map[string]any{"status": "running", "tools": []any{nuclei},
		"capabilities": []string{"nuclei", "dast", "validate:nuclei"}, "capacity": capacity})
	got = h.load(s)
	if got.Reported.MaxConcurrentJobs != 0 || got.EffectiveMaxConcurrentJobs() != 4 {
		t.Fatalf("new sdk: ceiling %d effective %d, want none and 4", got.Reported.MaxConcurrentJobs, got.EffectiveMaxConcurrentJobs())
	}
	var stored *int
	if err := h.db.QueryRowContext(context.Background(), `SELECT reported_max_jobs FROM sensors WHERE id = $1`, s.id).Scan(&stored); err != nil || stored != nil {
		t.Fatalf("reported_max_jobs = %v (%v), want NULL", stored, err)
	}
}
