package retest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

const swaggerAt = "https://api.example.com/webjars/swagger-ui/index.html"

func rq(url string, status int, matched bool) RequestResult {
	return RequestResult{URL: url, Status: status, Matched: matched}
}

// The settlement decides on the finding's own endpoint, not on whichever
// path of a multi-path template the sensor kept as evidence.
func TestDecideByRequests(t *testing.T) {
	other := "https://api.example.com/developers/documentation"
	cases := []struct {
		name     string
		reqs     []RequestResult
		want     Outcome
		code     ReasonCode
		contains string
	}{
		{"original matched", []RequestResult{rq(other, 404, false), rq(swaggerAt, 200, true)}, OutcomeStillVulnerable, ReasonMatched, ""},
		{"original answered 200 and did not match, nothing else matched: fixed",
			[]RequestResult{rq(other, 404, false), rq(swaggerAt, 200, false)}, OutcomeConfirmedFixed, ReasonNotMatched, "answered 200"},
		{"original 404, another path matched: exposed elsewhere",
			[]RequestResult{rq(swaggerAt, 404, false), rq(other, 200, true)}, OutcomeStillExposedElsewhere, ReasonMatchedElsewhere, "developers/documentation"},
		{"original not requested, another path matched: exposed elsewhere",
			[]RequestResult{rq(other, 200, true)}, OutcomeStillExposedElsewhere, ReasonMatchedElsewhere, "was not requested"},
		{"original not requested, nothing matched: inconclusive",
			[]RequestResult{rq(other, 404, false), rq("https://api.example.com/v2/api-docs", 404, false)}, OutcomeInconclusive, ReasonEndpointMismatch, "did not request"},
		{"original no answer: unreachable", []RequestResult{{URL: swaggerAt, Error: "timeout"}}, OutcomeInconclusive, ReasonUnreachable, ""},
		{"original 403 from the origin: blocked (usual rule)", []RequestResult{rq(swaggerAt, 403, false)}, OutcomeInconclusive, ReasonBlocked, ""},
		{"original 503: server error (usual rule)", []RequestResult{rq(swaggerAt, 503, false)}, OutcomeInconclusive, ReasonServerError, ""},
		{"original 401: auth changed (usual rule)", []RequestResult{rq(swaggerAt, 401, false)}, OutcomeInconclusive, ReasonAuthChanged, ""},
		{"original answered by an edge challenge on a 200: never a fix",
			[]RequestResult{{URL: swaggerAt, Status: 200, EdgeVendor: "cloudflare", EdgeState: "challenged"}}, OutcomeInconclusive, ReasonBlocked, "cloudflare"},
		{"the same path with another query value is the original",
			[]RequestResult{rq(swaggerAt+"?x=1", 200, false)}, OutcomeInconclusive, ReasonEndpointMismatch, ""},
		{"host case and default port do not make another endpoint",
			[]RequestResult{rq("HTTPS://API.example.com:443/webjars/swagger-ui/index.html", 200, false)}, OutcomeConfirmedFixed, ReasonNotMatched, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, ok := DecideByRequests(c.reqs, swaggerAt)
			if !ok {
				t.Fatal("not decided")
			}
			if v.Outcome != c.want || v.Code != c.code {
				t.Fatalf("got %s/%s (%s), want %s/%s", v.Outcome, v.Code, v.Reason, c.want, c.code)
			}
			if c.contains != "" && !strings.Contains(v.Reason, c.contains) {
				t.Errorf("reason %q lacks %q", v.Reason, c.contains)
			}
			if v.Outcome == OutcomeStillExposedElsewhere && len(v.OtherPaths) == 0 {
				t.Error("other paths not named")
			}
		})
	}
}

// Without per-request data (an older sensor) or a recorded endpoint, nothing
// is decided here: the caller keeps today's behavior.
func TestDecideByRequestsNeedsData(t *testing.T) {
	if _, ok := DecideByRequests(nil, swaggerAt); ok {
		t.Error("decided without requests")
	}
	if _, ok := DecideByRequests([]RequestResult{rq(swaggerAt, 200, true)}, ""); ok {
		t.Error("decided without a recorded endpoint")
	}
}

func TestDecideByRequestsHidesQueryValues(t *testing.T) {
	v, _ := DecideByRequests([]RequestResult{rq("https://api.example.com/other?token=SECRET", 200, true)}, swaggerAt)
	if strings.Contains(v.Reason, "SECRET") || strings.Contains(strings.Join(v.OtherPaths, " "), "SECRET") {
		t.Fatalf("a query value reached the reason: %+v", v)
	}
}

func TestDecodeRequestsBoundsAndCleans(t *testing.T) {
	var in []RequestResult
	for i := 0; i < maxRequestResults+10; i++ {
		in = append(in, rq("https://a.example/p", 200, false))
	}
	in = append(in, RequestResult{URL: "https://a.example/x\ny", Status: 99999})
	raw, _ := json.Marshal(in)
	if got := DecodeRequests(raw); len(got) != maxRequestResults {
		t.Fatalf("got %d", len(got))
	}
	raw, _ = json.Marshal([]RequestResult{{URL: "https://a.example/x\ny", Status: 99999}, {URL: ""}})
	got := DecodeRequests(raw)
	if len(got) != 1 || got[0].URL != "https://a.example/xy" || got[0].Status != 0 {
		t.Fatalf("%+v", got)
	}
	if DecodeRequests(json.RawMessage(`{"not":"a list"}`)) != nil {
		t.Error("unreadable must give none")
	}
}

// Decide (validate path): per-request results override the single exchange.
func TestDecideUsesRequests(t *testing.T) {
	reach := CheckResult{Outcome: "detected"}
	// The old reading: the only exchange kept was another path.
	old := CheckResult{Outcome: "not_detected", Evidence: attempt("https://api.example.com/developers/documentation", 200)}
	if v := Decide(old, reach, swaggerAt); v.Code != ReasonEndpointMismatch {
		t.Fatalf("old sensor: %s/%s", v.Outcome, v.Code)
	}
	fixed := old
	fixed.Requests = []RequestResult{rq(swaggerAt, 404, false), rq("https://api.example.com/developers/documentation", 200, false)}
	if v := Decide(fixed, reach, swaggerAt); v.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("original answered 404: %s/%s (%s)", v.Outcome, v.Code, v.Reason)
	}
	det := CheckResult{Outcome: "detected", Requests: []RequestResult{rq(swaggerAt, 404, false), rq("https://api.example.com/x", 200, true)}}
	if v := Decide(det, reach, swaggerAt); v.Outcome != OutcomeStillExposedElsewhere {
		t.Fatalf("detected elsewhere: %s/%s", v.Outcome, v.Code)
	}
	// A match, no per-request data: as before.
	if v := Decide(CheckResult{Outcome: "detected"}, reach, swaggerAt); v.Outcome != OutcomeStillVulnerable {
		t.Fatalf("detected, no requests: %s", v.Outcome)
	}
}

func TestToolVerdictUsesRequests(t *testing.T) {
	mk := func(verdict, reqs string) json.RawMessage {
		return json.RawMessage(`{"metadata":{"retest":{"verdicts":[{"ref":"F1","verdict":"` + verdict + `","requests":` + reqs + `}]}}}`)
	}
	elsewhere := `[{"url":"` + swaggerAt + `","status":404},{"url":"https://api.example.com/docs","status":200,"matched":true}]`
	if r := DecideToolVerdict(mk("still_present", elsewhere), "F1", swaggerAt); r.Verdict.Outcome != OutcomeStillExposedElsewhere {
		t.Fatalf("still_present elsewhere: %+v", r.Verdict)
	}
	if r := DecideToolVerdict(mk("still_present", `[{"url":"`+swaggerAt+`","status":200,"matched":true}]`), "F1", swaggerAt); r.Verdict.Outcome != OutcomeStillVulnerable {
		t.Fatalf("still_present at original: %+v", r.Verdict)
	}
	// An older sensor: no requests, still_present stays still vulnerable.
	if r := DecideToolVerdict(mk("still_present", `null`), "F1", swaggerAt); r.Verdict.Outcome != OutcomeStillVulnerable {
		t.Fatalf("no requests: %+v", r.Verdict)
	}
	// A tool that claims a match while no request matched cannot close the finding.
	if r := DecideToolVerdict(mk("still_present", `[{"url":"`+swaggerAt+`","status":404}]`), "F1", swaggerAt); r.Verdict.Outcome != OutcomeInconclusive {
		t.Fatalf("contradiction: %+v", r.Verdict)
	}
	fixed := `[{"url":"` + swaggerAt + `","status":404},{"url":"https://api.example.com/docs","status":200}]`
	if r := DecideToolVerdict(mk("fixed", fixed), "F1", swaggerAt); r.Verdict.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("fixed: %+v", r.Verdict)
	}
}

func TestExposedElsewhereMovesNothing(t *testing.T) {
	for _, st := range []string{"new", "confirmed", "in_progress", "fix_applied", "resolved"} {
		next, change := NextStatus(vulnerability.FindingStatus(st), OutcomeStillExposedElsewhere, true)
		if change || string(next) != st {
			t.Errorf("%s moved to %s", st, next)
		}
	}
	if ValidationOutcome(OutcomeStillExposedElsewhere) != "" {
		t.Error("an exposed-elsewhere retest must not stamp the finding's validation")
	}
}
