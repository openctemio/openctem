package routes

import (
	"context"
	"net/http"
	"sync"
	"testing"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Claim-N (RFC-046 §11, RFC-030 §5.9): a sensor that names the capacity
// feature gets its commands already claimed, at most its free slots of scans,
// and only commands of its own tenant. Without the feature GET /commands only
// lists, as before.

var capacityHeader = []string{protov2.HeaderSensorFeatures, protov2.FeatureCapacity}

func (h *ctlHarness) setMaxJobs(sensorID string, n int) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(),
		`UPDATE sensors SET max_concurrent_jobs = $2, current_jobs = 0 WHERE id = $1`, sensorID, n); err != nil {
		h.t.Fatalf("set max jobs: %v", err)
	}
}

func (h *ctlHarness) commandState(id string) (status string, sensor *string, leased bool) {
	h.t.Helper()
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT status, sensor_id::text, lease_expires_at IS NOT NULL FROM commands WHERE id = $1`, id).
		Scan(&status, &sensor, &leased); err != nil {
		h.t.Fatalf("read command: %v", err)
	}
	return status, sensor, leased
}

func TestSensorV2ClaimN_ClaimsUpToFreeSlotsAndClaimIsAReplay(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "claimer")
	h.setMaxJobs(s.id, 2)
	held := h.newCommand(h.tenantID, s.id)
	ids := []string{h.newCommand(h.tenantID, ""), h.newCommand(h.tenantID, ""), h.newCommand(h.tenantID, "")}

	// It already runs one scan: one slot left.
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+held+"/claim", nil)
	h.want(resp, raw, 200, "")

	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	list := decodeAs[protov2.CommandList](t, raw)
	if len(list.Commands) != 1 {
		t.Fatalf("claimed %d commands, want 1 (2 slots, 1 held): %s", len(list.Commands), raw)
	}
	got := list.Commands[0]
	if got.Status != "acknowledged" || got.SensorID == nil || *got.SensorID != s.id || got.ID != ids[0] {
		t.Fatalf("claimed command %s, want the oldest acknowledged to this sensor", raw)
	}
	if st, sensor, leased := h.commandState(got.ID); st != "acknowledged" || sensor == nil || *sensor != s.id || !leased {
		t.Fatalf("stored: %s %v leased=%v", st, sensor, leased)
	}
	// Its claim of the command is a replay.
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+got.ID+"/claim", nil)
	h.want(resp, raw, 200, "")

	// No slot left: the next claim-N takes nothing; the rest stay pending.
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/commands", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	if l := decodeAs[protov2.CommandList](t, raw); len(l.Commands) != 0 {
		t.Fatalf("claimed past capacity: %s", raw)
	}
	for _, id := range ids[1:] {
		if st, _, _ := h.commandState(id); st != "pending" {
			t.Fatalf("command %s = %s, want pending", id, st)
		}
	}

	// Without the feature the poll lists and claims nothing.
	other := h.newSensor(h.tenantID, "lister")
	resp, raw = h.call(other.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil)
	h.want(resp, raw, 200, "")
	if l := decodeAs[protov2.CommandList](t, raw); len(l.Commands) != 2 || l.Commands[0].Status != "pending" {
		t.Fatalf("listing poll: %s", raw)
	}
	if st, _, _ := h.commandState(ids[1]); st != "pending" {
		t.Fatalf("a listing poll claimed a command: %s", st)
	}
}

// Two sensors claiming at once take disjoint commands, and together never
// more than exist.
func TestSensorV2ClaimN_ConcurrentSensorsNeverShareACommand(t *testing.T) {
	h := newCtlHarness(t)
	a, b := h.newSensor(h.tenantID, "a"), h.newSensor(h.tenantID, "b")
	h.setMaxJobs(a.id, 10)
	h.setMaxJobs(b.id, 10)
	const n = 12
	for i := 0; i < n; i++ {
		h.newCommand(h.tenantID, "")
	}

	var (
		mu  sync.Mutex
		got = map[string]string{}
		wg  sync.WaitGroup
	)
	for _, s := range []ctlSensor{a, b, a, b} {
		wg.Add(1)
		go func(s ctlSensor) {
			defer wg.Done()
			resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
			if resp.StatusCode != 200 {
				t.Errorf("claim: %d %s", resp.StatusCode, raw)
				return
			}
			for _, c := range decodeAs[protov2.CommandList](t, raw).Commands {
				mu.Lock()
				if prev, dup := got[c.ID]; dup {
					t.Errorf("command %s claimed by %s and %s", c.ID, prev, s.id)
				}
				got[c.ID] = s.id
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()
	if len(got) > n {
		t.Fatalf("claimed %d of %d commands", len(got), n)
	}
	for id, holder := range got {
		if st, sensor, _ := h.commandState(id); st != "acknowledged" || sensor == nil || *sensor != holder {
			t.Fatalf("command %s stored as %s by %v, returned to %s", id, st, sensor, holder)
		}
	}
}

// A sensor claims only its own tenant's commands, never one pinned to another
// sensor.
func TestSensorV2ClaimN_TenantAndPinningIsolation(t *testing.T) {
	h := newCtlHarness(t)
	other := h.newTenant()
	a := h.newSensor(h.tenantID, "a")
	b := h.newSensor(h.tenantID, "b")
	x := h.newSensor(other, "x")
	for _, s := range []ctlSensor{a, b, x} {
		h.setMaxJobs(s.id, 10)
	}
	foreign := h.newCommand(other, "")
	pinnedToB := h.newCommand(h.tenantID, b.id)
	mine := h.newCommand(h.tenantID, "")

	resp, raw := h.call(a.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	l := decodeAs[protov2.CommandList](t, raw)
	if len(l.Commands) != 1 || l.Commands[0].ID != mine {
		t.Fatalf("sensor a claimed %s, want only its tenant's unpinned command", raw)
	}
	if st, _, _ := h.commandState(foreign); st != "pending" {
		t.Fatalf("another tenant's command = %s", st)
	}
	if st, sensor, _ := h.commandState(pinnedToB); st != "pending" || sensor == nil || *sensor != b.id {
		t.Fatalf("command pinned to b = %s %v", st, sensor)
	}

	resp, raw = h.call(x.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	if l := decodeAs[protov2.CommandList](t, raw); len(l.Commands) != 1 || l.Commands[0].ID != foreign {
		t.Fatalf("sensor x claimed %s, want only its own tenant's command", raw)
	}
}
