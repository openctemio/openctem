package routes

// Sensor load and capacity (RFC-030 §5.8, §5.12), end to end over the real
// sensor routes against a migrated database: the heartbeat's load report is
// clamped and stored, dispatch counts the commands a sensor holds and never
// offers it more scans than it has free slots, and a sensor can hand a
// claimed command back with release.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (h *ctlHarness) scanCommand(tenantID, scanner string) string {
	h.t.Helper()
	c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: tenantID, Type: "scan", Priority: "normal",
		Payload: json.RawMessage(`{"scanner":"` + scanner + `","target":"https://example.com/repo"}`), ExpiresIn: 3600})
	if err != nil {
		h.t.Fatal(err)
	}
	return c.ID.String()
}

func (h *ctlHarness) pollIDs(s ctlSensor, path string) []string {
	h.t.Helper()
	resp, raw := h.call(s.key, http.MethodGet, path, nil)
	h.want(resp, raw, 200, "")
	type idOnly struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	var v2 struct {
		Commands []idOnly `json:"commands"`
	}
	var list []idOnly
	if err := json.Unmarshal(raw, &v2); err == nil && v2.Commands != nil {
		list = v2.Commands
	} else if err := json.Unmarshal(raw, &list); err != nil {
		h.t.Fatalf("poll body: %v: %s", err, raw)
	}
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, c.ID)
	}
	return out
}

// The heartbeat's load report is clamped, stored and shown on the sensor;
// it narrows the free slots while fresh and stops counting once stale.
func TestSensorLoad_HeartbeatReportIsStoredAndNarrowsCapacity(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	s := h.newVerifiedSensor(h.tenantID, "loaded", []string{"semgrep"}, nil, 4)
	h.heartbeatV2(s, map[string]any{
		"status": "running",
		"resources": map[string]any{"cpu_cores": 2.5, "cpu_used_pct": 340, "mem_total_bytes": 4 << 30,
			"mem_available_bytes": 8 << 30, "load1": 1.25, "disk_free_bytes": -5},
		"capacity": map[string]any{"slots_total": 3, "slots_free": 1, "active_jobs": 2,
			"per_tool": map[string]any{
				"semgrep":       map[string]any{"est_cpu_s": 12.5, "est_mem_bytes": 512 << 20, "throughput_targets_per_min": 4},
				"bad tool name": map[string]any{"est_cpu_s": 1},
			}},
		"queue": map[string]any{"claimed": 2, "running": 2, "queued_local": 0, "oldest_age_seconds": 30},
	})
	got := h.load(s)
	r := got.Load.Resources
	if r == nil || r.CPUCores != 2.5 || r.CPUUsedPct != 100 || r.MemAvailableBytes != 4<<30 || r.DiskFreeBytes != 0 {
		t.Fatalf("resources not clamped and stored: %+v", r)
	}
	c := got.Load.Capacity
	if c == nil || c.SlotsTotal != 3 || c.SlotsFree != 1 || len(c.PerTool) != 1 || c.PerTool["semgrep"].ThroughputTargetsPerMin != 4 {
		t.Fatalf("capacity not stored or per-tool not sanitized: %+v", c)
	}
	if q := got.Load.Queue; q == nil || q.Claimed != 2 || q.OldestAgeSeconds != 30 {
		t.Fatalf("queue not stored: %+v", q)
	}
	if !got.Load.IsFresh(time.Now()) {
		t.Fatal("a just-written load report is not fresh")
	}
	// Effective capacity 4, nothing held, but the sensor says 1 free.
	if n := got.FreeSlots(time.Now()); n != 1 {
		t.Fatalf("free slots = %d, want 1 (the report narrows 4 to 1)", n)
	}
	// CPU/memory percentages derived from resources for the load score.
	if got.CPUPercent != 100 || got.MemoryPercent != 0 {
		t.Fatalf("load score inputs not derived: cpu %v mem %v", got.CPUPercent, got.MemoryPercent)
	}

	// A report can never widen: slots_free above the server's free count.
	h.heartbeatV2(s, map[string]any{"status": "running",
		"capacity": map[string]any{"slots_total": 50, "slots_free": 50, "active_jobs": 0}})
	if n := h.load(s).FreeSlots(time.Now()); n != 4 {
		t.Fatalf("free slots = %d, want 4 (the report cannot widen the effective capacity)", n)
	}

	// A stale report's free slots stop counting.
	h.heartbeatV2(s, map[string]any{"status": "running",
		"capacity": map[string]any{"slots_total": 3, "slots_free": 0, "active_jobs": 3}})
	if n := h.load(s).FreeSlots(time.Now()); n != 0 {
		t.Fatalf("free slots = %d with a fresh report of 0 free, want 0", n)
	}
	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET load_reported_at = NOW() - INTERVAL '10 minutes' WHERE id = $1`, s.id); err != nil {
		t.Fatal(err)
	}
	// Its free slots no longer count; its slots (3, what the sensor could
	// last run) still bound the capacity, like the last known allocatable
	// of a Kubernetes node (RFC-033).
	if n := h.load(s).FreeSlots(time.Now()); n != 3 {
		t.Fatalf("free slots = %d with a stale report, want 3", n)
	}
}

// The poll never offers more scan commands than the sensor has free slots,
// counted by the server from the commands it holds; other commands are not
// capped. v1 and v2 alike.
func TestSensorLoad_PollOffersAtMostFreeSlots(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	s := h.newVerifiedSensor(h.tenantID, "two-slots", []string{"semgrep"}, nil, 2)
	h.heartbeatV2(s, map[string]any{"status": "running"})
	for range 6 {
		h.scanCommand(h.tenantID, "semgrep")
	}
	collect, err := h.cmds.Create(ctx, command.CreateInput{TenantID: h.tenantID, Type: "collect", Priority: "normal",
		Payload: json.RawMessage(`{}`), ExpiresIn: 3600})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/api/v2/sensor/commands?limit=10", "/api/v1/agent/commands?limit=10"} {
		got := h.pollIDs(s, path)
		if len(got) != 3 { // 2 scans (2 free slots) + the collect
			t.Fatalf("%s offered %d commands, want 2 scans + 1 collect", path, len(got))
		}
	}

	// Claim one: one slot left, so one scan is offered.
	first := h.pollIDs(s, "/api/v2/sensor/commands?limit=10")[0]
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+first+"/claim", map[string]any{})
	h.want(resp, raw, 200, "")
	scans := 0
	for _, id := range h.pollIDs(s, "/api/v2/sensor/commands?limit=10") {
		if id != collect.ID.String() {
			scans++
		}
	}
	if scans != 1 {
		t.Fatalf("with 1 of 2 slots held the poll offered %d scans, want 1", scans)
	}
	if got := h.load(s); got.CurrentJobs != 1 {
		t.Fatalf("current_jobs = %d, want 1 (counted from the commands it holds)", got.CurrentJobs)
	}
}

// Release hands a claimed command back to the queue at once: pending,
// unpinned, claimable by another sensor; idempotent for the releaser,
// refused for anyone else.
func TestSensorLoad_ReleaseReturnsTheCommandToTheQueue(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	a := h.newVerifiedSensor(h.tenantID, "draining", []string{"semgrep"}, nil, 2)
	b := h.newVerifiedSensor(h.tenantID, "other", []string{"semgrep"}, nil, 2)
	id := h.scanCommand(h.tenantID, "semgrep")

	resp, raw := h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", map[string]any{})
	h.want(resp, raw, 200, "")
	// Another sensor cannot release it.
	resp, raw = h.call(b.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/release", map[string]any{"reason": "nope"})
	h.want(resp, raw, 404, "")

	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/release", map[string]any{"reason": "draining"})
	h.want(resp, raw, 200, "")
	var out struct {
		Status       string  `json:"status"`
		SensorID     *string `json:"sensor_id"`
		ErrorMessage string  `json:"error_message"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "pending" || out.SensorID != nil || out.ErrorMessage != "released by sensor: draining" {
		t.Fatalf("released command = %+v, want pending, unpinned, with the reason", out)
	}
	// A repeat is a replay.
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/release", map[string]any{"reason": "draining"})
	h.want(resp, raw, 200, "")

	// The other sensor takes it at once.
	resp, raw = h.call(b.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", map[string]any{})
	h.want(resp, raw, 200, "")
	var holder string
	if err := h.db.QueryRowContext(ctx, `SELECT sensor_id FROM commands WHERE id = $1`, id).Scan(&holder); err != nil {
		t.Fatal(err)
	}
	if holder != b.id {
		t.Fatalf("command held by %s after release and re-claim, want %s", holder, b.id)
	}
	// A running command can be released too; a finished one cannot.
	resp, raw = h.call(b.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/start", map[string]any{})
	h.want(resp, raw, 200, "")
	resp, raw = h.call(b.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/complete", map[string]any{"result": map[string]any{}})
	h.want(resp, raw, 200, "")
	resp, raw = h.call(b.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/release", map[string]any{})
	h.want(resp, raw, 409, "")

	// Hello advertises it.
	resp, raw = h.call(a.key, http.MethodGet, "/api/v2/sensor/hello", nil)
	h.want(resp, raw, 200, "")
	var hello struct {
		Features []string `json:"features"`
	}
	_ = json.Unmarshal(raw, &hello)
	var hasRelease, hasLoad bool
	for _, f := range hello.Features {
		hasRelease = hasRelease || f == "release"
		hasLoad = hasLoad || f == "load"
	}
	if !hasRelease || !hasLoad {
		t.Fatalf("hello features %v lack release/load", hello.Features)
	}
}

// Selection uses the reported free slots and per-tool throughput: a sensor
// that reports no free slot is skipped, and among free ones the faster for
// the tool is picked; with every capable sensor busy the selector queues
// the job for the tenant (never "no sensor").
func TestSensorLoad_SelectionUsesReportedFreeSlots(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	tenant := h.newTenant()
	tid := shared.MustIDFromString(tenant)
	full := h.newVerifiedSensor(tenant, "full", []string{"semgrep"}, nil, 4)
	slow := h.newVerifiedSensor(tenant, "slow", []string{"semgrep"}, nil, 4)
	fast := h.newVerifiedSensor(tenant, "fast", []string{"semgrep"}, nil, 4)
	report := func(s ctlSensor, free int, perMin float64) {
		h.heartbeatV2(s, map[string]any{"status": "running", "capacity": map[string]any{
			"slots_total": 4, "slots_free": free, "active_jobs": 4 - free,
			"per_tool": map[string]any{"semgrep": map[string]any{"throughput_targets_per_min": perMin}}}})
	}
	report(full, 0, 100)
	report(slow, 2, 1)
	report(fast, 2, 30)

	picked, err := h.repo.FindAvailableWithTool(ctx, tid, "semgrep")
	if err != nil || picked == nil || picked.ID.String() != fast.id {
		t.Fatalf("picked %v (err %v), want the fast sensor with free slots", picked, err)
	}

	sel, err := h.selector().SelectSensor(ctx, sensor.SelectSensorRequest{TenantID: tid, Capabilities: nil, Tool: "semgrep", AllowQueue: true})
	if err != nil || sel.Sensor == nil || sel.Sensor.ID.String() == full.id {
		t.Fatalf("selector picked %+v (err %v); a sensor without a free slot must be skipped", sel, err)
	}

	report(slow, 0, 1)
	report(fast, 0, 30)
	sel, err = h.selector().SelectSensor(ctx, sensor.SelectSensorRequest{TenantID: tid, Capabilities: nil, Tool: "semgrep", AllowQueue: true})
	if err != nil || sel.Sensor != nil || !sel.Queued || !sel.TenantBusy {
		t.Fatalf("every sensor busy: got %+v (err %v), want queued for the busy tenant", sel, err)
	}
	// The trigger gate still sees a capable sensor: work queues, it is not refused.
	if avail := h.selector().CheckSensorAvailability(ctx, tid, "semgrep", false); !avail.Available {
		t.Fatalf("a busy fleet refused the trigger: %+v", avail)
	}
}
