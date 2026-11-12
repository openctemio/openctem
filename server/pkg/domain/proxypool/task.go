package proxypool

// Task-reported proxy faults (docs/architecture/sensor-proxies.md): a job
// that ran through a pool says in its own result when the pool could not
// carry its connections (a coverage gap or a target outcome with the reason
// proxy_unavailable, or a failure of class infra.egress.pool_exhausted). The
// platform recorded which pool and endpoints it handed that job, so it
// charges the fault to them, never to an endpoint the sensor names. Too many
// faulted jobs in a short window quarantine an endpoint, whether or not the
// sensor's separate egress report ever arrives.

import (
	"encoding/json"
	"strings"
	"time"
)

// Task verdicts of a job that ran through a pool.
const (
	// VerdictOK: the job ended and reported no proxy fault.
	VerdictOK = "ok"
	// VerdictProxyFault: the job reported that the pool could not carry
	// some of its connections.
	VerdictProxyFault = "proxy_fault"
)

// ReasonProxyUnavailable is the coverage-gap and target-outcome reason a
// sensor reports when a job's pool could not carry a connection.
const ReasonProxyUnavailable = "proxy_unavailable"

// ClassPoolExhausted is the failure class of a job none of whose pool's
// endpoints carried a connection.
const ClassPoolExhausted = "infra.egress.pool_exhausted"

// classTargetRefused marks a gap whose proxy answered but refused the
// destination (its rules, e.g. CONNECT only to 443): the proxy is up.
const classTargetRefused = "(target_refused)"

// Task window rule: measured defaults, not settings.
const (
	// TaskWindow is how far back task verdicts count.
	TaskWindow = 30 * time.Minute
	// taskFaultLimit faulted jobs in the window quarantine an endpoint.
	taskFaultLimit = 5
	// taskRatioMinSamples is the fewest jobs the fault-ratio rule needs.
	taskRatioMinSamples = 5
	// maxTaskEntries bounds how many gaps or outcomes are read.
	maxTaskEntries = 10_000
)

// TaskVerdict is what one ended job says about its pool.
type TaskVerdict struct {
	// Verdict is VerdictOK or VerdictProxyFault.
	Verdict string
	// Faults counts the hosts or targets the pool could not carry (1 for
	// a job that failed with pool exhaustion).
	Faults int
}

// Fault reports whether the job charged the pool with a fault.
func (v TaskVerdict) Fault() bool { return v.Verdict == VerdictProxyFault }

// CompletedVerdict reads a completed job's result. The result is the
// sensor's and untrusted: only the closed reason proxy_unavailable counts,
// target-side reasons (blocked, breaker_open, rate_floor, timeouts,
// unreachable, edge answers) never do, and nothing in it can name an
// endpoint (the platform charges the endpoints it handed the job).
func CompletedVerdict(result json.RawMessage) TaskVerdict {
	var res struct {
		Metadata struct {
			Gaps []struct {
				Reason string `json:"reason"`
				Detail string `json:"detail"`
			} `json:"coverage_gaps"`
		} `json:"metadata"`
		Outcomes []struct {
			State  string `json:"state"`
			Class  string `json:"class"`
			Reason string `json:"reason"`
		} `json:"target_outcomes"`
	}
	if len(result) == 0 || json.Unmarshal(result, &res) != nil {
		return TaskVerdict{Verdict: VerdictOK}
	}
	gaps, listed := 0, 0
	for i, g := range res.Metadata.Gaps {
		if i == maxTaskEntries {
			break
		}
		if g.Reason != ReasonProxyUnavailable {
			continue
		}
		listed++
		if !strings.Contains(g.Detail, classTargetRefused) {
			gaps++
		}
	}
	faults := gaps
	if listed == 0 {
		// No gap list (or an older sensor): the target outcomes say it.
		for i, o := range res.Outcomes {
			if i == maxTaskEntries {
				break
			}
			if o.State == "failed" && o.Class == "sensor_network_fault" && o.Reason == ReasonProxyUnavailable {
				faults++
			}
		}
	}
	if faults == 0 {
		return TaskVerdict{Verdict: VerdictOK}
	}
	return TaskVerdict{Verdict: VerdictProxyFault, Faults: faults}
}

// FailedVerdict is the verdict of a failed job: a fault only when it failed
// because its pool carried nothing; ok=false for any other failure, which
// says nothing about the pool (the job is then not counted at all).
func FailedVerdict(failureClass string) (TaskVerdict, bool) {
	if failureClass == ClassPoolExhausted {
		return TaskVerdict{Verdict: VerdictProxyFault, Faults: 1}, true
	}
	return TaskVerdict{}, false
}

// TaskSample is one ended job's verdict on the endpoints it was handed.
type TaskSample struct {
	// SensorID is the sensor that held the job (the platform's record).
	SensorID    string
	EndpointIDs []string
	Fault       bool
	At          time.Time
}

// TaskCounts is an endpoint's job verdicts since its window start.
type TaskCounts struct {
	Faulted int
	Total   int
	// Sensors is the distinct sensors whose jobs are counted; FaultedSensors
	// the distinct ones among them that reported a fault.
	Sensors        int
	FaultedSensors int
}

// minSharedFaultSensors is how many distinct sensors must report faults
// before an endpoint used by several sensors is quarantined: one sensor's
// own network problem must not take a shared endpoint from everyone.
const minSharedFaultSensors = 2

// Shared reports whether more than one sensor's jobs went through the
// endpoint in the window.
func (c TaskCounts) Shared() bool { return c.Sensors > 1 }

// Quorum reports whether the faults come from enough sensors to act on:
// always for an endpoint one sensor uses, at least minSharedFaultSensors
// distinct sensors for a shared one.
func (c TaskCounts) Quorum() bool {
	return !c.Shared() || c.FaultedSensors >= minSharedFaultSensors
}

// Trips reports whether the counts quarantine an endpoint: taskFaultLimit
// faulted jobs, or more than half of at least taskRatioMinSamples jobs.
func (c TaskCounts) Trips() bool {
	return c.Quorum() && c.trips()
}

func (c TaskCounts) trips() bool {
	return c.Faulted >= taskFaultLimit || (c.Total >= taskRatioMinSamples && 2*c.Faulted > c.Total)
}

// TaskWindowStart is the earliest verdict that counts for the endpoint now:
// TaskWindow back, and never before its current state began (an endpoint
// reset, re-admitted or promoted starts clean) or, after a quarantine whose
// back-off ended, before that end (the re-probe counts only new jobs).
func (h *Health) TaskWindowStart(now time.Time) time.Time {
	start := now.Add(-TaskWindow)
	if h.StateChangedAt.After(start) {
		start = h.StateChangedAt
	}
	if h.State == StateQuarantined && h.QuarantinedUntil != nil && h.QuarantinedUntil.After(start) {
		start = *h.QuarantinedUntil
	}
	return start
}

// CountTasks counts the samples that charge endpointID since start.
func CountTasks(samples []TaskSample, endpointID string, start time.Time) TaskCounts {
	var c TaskCounts
	all, faulted := map[string]struct{}{}, map[string]struct{}{}
	for _, s := range samples {
		if s.At.Before(start) || !containsID(s.EndpointIDs, endpointID) {
			continue
		}
		c.Total++
		all[s.SensorID] = struct{}{}
		if s.Fault {
			c.Faulted++
			faulted[s.SensorID] = struct{}{}
		}
	}
	c.Sensors, c.FaultedSensors = len(all), len(faulted)
	return c
}

func containsID(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// ApplyTasks folds the job verdicts that charge the endpoint into its health
// after a job ended (fault: that job reported a proxy fault). The score is
// capped by the share of clean jobs; the endpoint is quarantined when the
// counts trip the rule, or at the first faulted job after a quarantine's
// back-off (the re-probe failed), in both cases only when an endpoint shared
// by several sensors has faults from at least two of them (Quorum). Task verdicts never promote an endpoint:
// only the sensor's per-connection report can. Returns true when the state
// changed.
func (h *Health) ApplyTasks(c TaskCounts, fault bool, lastError string, now time.Time) bool {
	if fault {
		t := now
		h.LastFailureAt = &t
		if lastError != "" {
			h.LastError = SanitizeError(lastError)
		}
	}
	if c.Total > 0 && c.Faulted > 0 {
		h.Score = min(h.Score, clamp01(1-float64(c.Faulted)/float64(c.Total)))
	}
	switch {
	case h.State == StateQuarantined && !h.Eligible(now):
		// Already out; a late verdict of an older job changes nothing.
		return false
	case h.State == StateQuarantined:
		if fault && c.Quorum() {
			h.quarantine(now)
			return true
		}
		return false
	case fault && c.Trips():
		h.quarantine(now)
		return true
	}
	return false
}
