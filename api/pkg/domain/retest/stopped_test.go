package retest

import "testing"

// A re-run that did not finish by itself (research/467 F6) never closes or
// clears a finding: the stop is checked after every verdict path, including
// the per-request one (DecideByRequests) that runs first. A match it
// reports still stands.
func TestDecide_StoppedRunNeverProvesAFix(t *testing.T) {
	reach := CheckResult{Outcome: "detected"}
	fixedByRequests := CheckResult{Outcome: "not_detected",
		Requests: []RequestResult{rq(swaggerAt, 404, false)}}
	if v := Decide(fixedByRequests, reach, swaggerAt); v.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("precondition: a clean run with the endpoint's 404 = %s/%s", v.Outcome, v.Code)
	}
	fixedByAttempt := CheckResult{Outcome: "not_detected", Evidence: attempt(swaggerAt, 404)}
	if v := Decide(fixedByAttempt, reach, swaggerAt); v.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("precondition: a clean run with the attempt's 404 = %s/%s", v.Outcome, v.Code)
	}
	bare := CheckResult{Outcome: "not_detected"}
	if v := Decide(bare, reach, swaggerAt); v.Outcome != OutcomeNotReproduced {
		t.Fatalf("precondition: a bare non-match = %s/%s", v.Outcome, v.Code)
	}
	for name, check := range map[string]CheckResult{
		"per-request 404": fixedByRequests, "attempt 404": fixedByAttempt, "bare non-match": bare,
	} {
		check.Stopped = true
		v := Decide(check, reach, swaggerAt)
		if v.Outcome != OutcomeInconclusive || v.Code != ReasonError || v.Reason == "" {
			t.Errorf("%s from a stopped run = %s/%s (%s), want inconclusive", name, v.Outcome, v.Code, v.Reason)
		}
	}
	matched := CheckResult{Outcome: "detected", Stopped: true}
	if v := Decide(matched, reach, swaggerAt); v.Outcome != OutcomeStillVulnerable {
		t.Errorf("a match from a stopped run = %s, want still vulnerable", v.Outcome)
	}
}

// The tool method: a "fixed" verdict in the legacy shape of a killed run
// (exit -1 or 1, status completed) is inconclusive; the same verdict from a
// clean run is unchanged; a match stands.
func TestDecideToolVerdict_StoppedRunNeverProvesAFix(t *testing.T) {
	const fid = "0193a1f0-0000-7000-8000-000000000001"
	const at = "https://h.example/admin"
	ev := `,"evidence":[{"kind":"http_exchange","http":{"request":{"method":"GET","url":"` + at + `"},"response":{"status":404}}}]`
	raw := func(top, verdict, extra string) []byte {
		return []byte(`{` + top + `"metadata":{"retest":{"verdicts":[{"ref":"` + fid + `","verdict":"` + verdict + `"` + extra + `}]}}}`)
	}
	if got := DecideToolVerdict(raw(`"status":"completed","exit_code":0,`, "fixed", ev), fid, at); got.Verdict.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("precondition: clean fixed = %s", got.Verdict.Outcome)
	}
	for name, top := range map[string]string{
		"exit -1": `"status":"completed","exit_code":-1,`,
		"exit 1":  `"status":"completed","exit_code":1,`,
		"partial": `"status":"partial",`,
		"stopped": `"stop_reason":"drain",`,
	} {
		for _, extra := range []string{ev, ""} {
			got := DecideToolVerdict(raw(top, "fixed", extra), fid, at)
			if got.Verdict.Outcome != OutcomeInconclusive || got.Verdict.Code != ReasonError {
				t.Errorf("%s, fixed (evidence %v) = %s/%s, want inconclusive", name, extra != "", got.Verdict.Outcome, got.Verdict.Code)
			}
		}
		if got := DecideToolVerdict(raw(top, "still_present", ""), fid, at); got.Verdict.Outcome != OutcomeStillVulnerable {
			t.Errorf("%s, still present = %s, want still vulnerable", name, got.Verdict.Outcome)
		}
	}
}
