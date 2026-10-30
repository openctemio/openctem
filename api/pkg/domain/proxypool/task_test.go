package proxypool

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCompletedVerdict(t *testing.T) {
	for name, tc := range map[string]struct {
		result string
		want   TaskVerdict
	}{
		"empty":           {``, TaskVerdict{Verdict: VerdictOK}},
		"malformed":       {`{"metadata":`, TaskVerdict{Verdict: VerdictOK}},
		"no gaps":         {`{"findings":2}`, TaskVerdict{Verdict: VerdictOK}},
		"proxy gaps":      {`{"metadata":{"coverage_gaps":[{"host":"a","reason":"proxy_unavailable","detail":"the proxy pool could not carry a connection to port 443 (proxy_down)"},{"host":"b","reason":"proxy_unavailable"}]}}`, TaskVerdict{Verdict: VerdictProxyFault, Faults: 2}},
		"target gaps":     {`{"metadata":{"coverage_gaps":[{"host":"a","reason":"blocked"},{"host":"b","reason":"breaker_open"},{"host":"c","reason":"rate_floor"}]}}`, TaskVerdict{Verdict: VerdictOK}},
		"proxy refused":   {`{"metadata":{"coverage_gaps":[{"host":"a","reason":"proxy_unavailable","detail":"the proxy pool could not carry a connection to port 22 (target_refused)"}]}}`, TaskVerdict{Verdict: VerdictOK}},
		"outcomes only":   {`{"target_outcomes":[{"target":"a","state":"failed","class":"sensor_network_fault","cause":"sensor","reason":"proxy_unavailable"},{"target":"b","state":"failed","class":"timeout"},{"target":"c","state":"failed","class":"edge_blocked"}]}`, TaskVerdict{Verdict: VerdictProxyFault, Faults: 1}},
		"target outcomes": {`{"target_outcomes":[{"target":"b","state":"failed","class":"timeout"},{"target":"c","state":"failed","class":"edge_blocked","reason":"waf"},{"target":"d","state":"failed","class":"sensor_network_fault","cause":"sensor","reason":"control_probe"}]}`, TaskVerdict{Verdict: VerdictOK}},
		// The gap list decides when present: a refused destination is not a
		// proxy fault even though its outcome carries the same reason.
		"gaps win": {`{"metadata":{"coverage_gaps":[{"host":"a","reason":"proxy_unavailable","detail":"(target_refused)"}]},"target_outcomes":[{"target":"a","state":"failed","class":"sensor_network_fault","reason":"proxy_unavailable"}]}`, TaskVerdict{Verdict: VerdictOK}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := CompletedVerdict(json.RawMessage(tc.result)); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestFailedVerdict(t *testing.T) {
	if v, ok := FailedVerdict(ClassPoolExhausted); !ok || !v.Fault() {
		t.Fatalf("pool exhausted: %+v %v", v, ok)
	}
	for _, c := range []string{"infra.tool_crashed", "infra.sensor_network", "target.unreachable", ""} {
		if _, ok := FailedVerdict(c); ok {
			t.Fatalf("%q counted against the pool", c)
		}
	}
}

func TestTaskCountsTrips(t *testing.T) {
	for _, tc := range []struct {
		c    TaskCounts
		want bool
	}{
		{TaskCounts{Faulted: 4, Total: 100}, false},
		{TaskCounts{Faulted: 5, Total: 100}, true},
		{TaskCounts{Faulted: 3, Total: 4}, false}, // too few samples for the ratio
		{TaskCounts{Faulted: 3, Total: 5}, true},  // 60 %
		{TaskCounts{Faulted: 3, Total: 6}, false}, // exactly half
		{TaskCounts{Faulted: 4, Total: 7}, true},
	} {
		if got := tc.c.Trips(); got != tc.want {
			t.Errorf("%+v: got %v", tc.c, got)
		}
	}
}

func TestCountTasksWindowAndEndpoint(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	samples := []TaskSample{
		{EndpointIDs: []string{"e1"}, Fault: true, At: now.Add(-time.Minute)},
		{EndpointIDs: []string{"e1", "e2"}, Fault: false, At: now.Add(-2 * time.Minute)},
		{EndpointIDs: []string{"e2"}, Fault: true, At: now.Add(-3 * time.Minute)},
		{EndpointIDs: []string{"e1"}, Fault: true, At: now.Add(-40 * time.Minute)},
	}
	if c := CountTasks(samples, "e1", now.Add(-TaskWindow)); c != (TaskCounts{Faulted: 1, Total: 2, Sensors: 1, FaultedSensors: 1}) {
		t.Fatalf("e1: %+v", c)
	}
	if c := CountTasks(samples, "e3", now.Add(-TaskWindow)); c != (TaskCounts{}) {
		t.Fatalf("unassigned endpoint counted: %+v", c)
	}
}

func TestTaskWindowStart(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	h := NewHealth(now.Add(-time.Hour))
	if got := h.TaskWindowStart(now); !got.Equal(now.Add(-TaskWindow)) {
		t.Fatalf("old state: %v", got)
	}
	h.Reset(now.Add(-5 * time.Minute))
	if got := h.TaskWindowStart(now); !got.Equal(now.Add(-5 * time.Minute)) {
		t.Fatalf("reset: %v", got)
	}
	until := now.Add(-2 * time.Minute)
	h.State, h.QuarantinedUntil, h.StateChangedAt = StateQuarantined, &until, now.Add(-10*time.Minute)
	if got := h.TaskWindowStart(now); !got.Equal(until) {
		t.Fatalf("expired quarantine: %v", got)
	}
}

func TestApplyTasksQuarantinesAtThreshold(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	h := NewHealth(now.Add(-time.Hour))
	h.State, h.Score = StateHealthy, 0.95
	for i := 1; i <= 4; i++ {
		if h.ApplyTasks(TaskCounts{Faulted: i, Total: 20}, true, "proxy down", now) {
			t.Fatalf("quarantined after %d faulted jobs", i)
		}
	}
	if h.State != StateHealthy || h.LastFailureAt == nil || h.LastError != "proxy down" || h.Score > 0.81 {
		t.Fatalf("after 4: %+v", h)
	}
	if !h.ApplyTasks(TaskCounts{Faulted: 5, Total: 20}, true, "proxy down", now) || h.State != StateQuarantined {
		t.Fatalf("not quarantined at 5: %+v", h)
	}
	// Late verdicts while quarantined change nothing.
	if h.ApplyTasks(TaskCounts{Faulted: 6, Total: 20}, true, "", now.Add(time.Minute)) || h.QuarantineCount != 1 {
		t.Fatalf("re-quarantined while out: %+v", h)
	}
	// After the back-off, the first faulted job quarantines it again with a
	// doubled back-off; a clean one does not promote it.
	later := h.QuarantinedUntil.Add(time.Second)
	if h.ApplyTasks(TaskCounts{Total: 1}, false, "", later) || h.State != StateQuarantined {
		t.Fatalf("clean job moved an expired quarantine: %+v", h)
	}
	if !h.ApplyTasks(TaskCounts{Faulted: 1, Total: 1}, true, "", later) || h.QuarantineCount != 2 ||
		h.QuarantinedUntil.Sub(later) != 2*quarantineBase {
		t.Fatalf("re-probe failure: %+v", h)
	}
}

func TestApplyTasksRatioRuleAndCleanJobs(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	h := NewHealth(now.Add(-time.Hour))
	h.State = StateHealthy
	// A clean job never quarantines, even with faults in the window.
	if h.ApplyTasks(TaskCounts{Faulted: 4, Total: 5}, false, "", now) || h.State != StateHealthy {
		t.Fatalf("clean job quarantined: %+v", h)
	}
	if !h.ApplyTasks(TaskCounts{Faulted: 3, Total: 5}, true, "", now) || h.State != StateQuarantined {
		t.Fatalf("ratio rule: %+v", h)
	}
}

func TestSharedEndpointNeedsTwoSensors(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	mk := func(sensor string, fault bool, n int) []TaskSample {
		out := make([]TaskSample, n)
		for i := range out {
			out[i] = TaskSample{SensorID: sensor, EndpointIDs: []string{"e1"}, Fault: fault, At: now.Add(-time.Minute)}
		}
		return out
	}
	start := now.Add(-TaskWindow)

	// One sensor only: the earlier rule, 5 faulted jobs quarantine.
	single := CountTasks(mk("s1", true, 5), "e1", start)
	if single.Shared() || !single.Trips() {
		t.Fatalf("single sensor: %+v", single)
	}

	// Another sensor used the endpoint cleanly: s1's faults alone do not trip.
	shared := CountTasks(append(mk("s1", true, 8), mk("s2", false, 2)...), "e1", start)
	if !shared.Shared() || shared.FaultedSensors != 1 || shared.Trips() {
		t.Fatalf("one faulting sensor on a shared endpoint tripped: %+v", shared)
	}
	h := NewHealth(now.Add(-time.Hour))
	h.State = StateHealthy
	if h.ApplyTasks(shared, true, "x", now) || h.State != StateHealthy {
		t.Fatalf("quarantined on one sensor's reports: %+v", h)
	}

	// Two sensors reporting faults: quorum, the usual thresholds apply.
	both := CountTasks(append(mk("s1", true, 4), append(mk("s2", true, 1), mk("s3", false, 1)...)...), "e1", start)
	if both.FaultedSensors != 2 || !both.Trips() {
		t.Fatalf("two faulting sensors: %+v", both)
	}
	if !h.ApplyTasks(both, true, "x", now) || h.State != StateQuarantined {
		t.Fatalf("not quarantined with quorum: %+v", h)
	}

	// The re-probe after a back-off also needs the quorum on a shared one.
	later := h.QuarantinedUntil.Add(time.Second)
	if h.ApplyTasks(TaskCounts{Faulted: 1, Total: 2, Sensors: 2, FaultedSensors: 1}, true, "", later) || h.QuarantineCount != 1 {
		t.Fatalf("re-quarantined on one sensor of a shared endpoint: %+v", h)
	}
	if !h.ApplyTasks(TaskCounts{Faulted: 2, Total: 2, Sensors: 2, FaultedSensors: 2}, true, "", later) || h.QuarantineCount != 2 {
		t.Fatalf("re-probe with quorum: %+v", h)
	}
}
