package retest

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
)

// RequestResult is what one request of a re-run saw, as the sensor reports it
// (sdk-go tool.RequestResult). A check that probes several paths makes many;
// the evidence keeps the exchange of only a few, so these lines are what says
// what the finding's own endpoint did. They are untrusted input: bounded,
// printable, and never more than the evidence already allows a sensor to say.
type RequestResult struct {
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Matched    bool   `json:"matched"`
	Error      string `json:"error"`
	EdgeVendor string `json:"edge_vendor"`
	EdgeState  string `json:"edge_state"`
}

const (
	maxRequestResults = 64
	maxRequestURL     = 2048
	// maxOtherPaths bounds the other matching paths a reason names.
	maxOtherPaths = 3
)

// DecodeRequests reads the per-request results of a verdict or a validation
// result. Anything unreadable gives none (the platform then judges by the
// evidence alone, as for a sensor that does not report them).
func DecodeRequests(raw json.RawMessage) []RequestResult {
	if len(raw) == 0 {
		return nil
	}
	var in []RequestResult
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	out := make([]RequestResult, 0, min(len(in), maxRequestResults))
	for _, r := range in {
		if len(out) == maxRequestResults {
			break
		}
		r.URL = strings.Map(func(c rune) rune {
			if unicode.IsSpace(c) || unicode.IsControl(c) {
				return -1
			}
			return c
		}, r.URL)
		if r.URL == "" || len(r.URL) > maxRequestURL {
			continue
		}
		if r.Status < 0 || r.Status > 999 {
			r.Status = 0
		}
		r.Error = CleanDetail(r.Error)
		r.EdgeVendor = CleanDetail(r.EdgeVendor)
		r.EdgeState = CleanDetail(r.EdgeState)
		out = append(out, r)
	}
	return out
}

// edgeStops: the answer was an edge challenge, block or throttle, which says
// nothing about the service behind it.
func (r RequestResult) edgeStops() bool {
	switch r.EdgeState {
	case "challenged", "blocked", "rate_limited":
		return true
	}
	return false
}

// DecideByRequests judges a re-run by what the finding's own endpoint did,
// from the per-request results of a check that may probe many paths. ok is
// false when there is nothing to judge by (an older sensor reports no
// requests, or the finding has no recorded endpoint): the caller then
// decides as before.
//
//   - the original endpoint matched: still vulnerable;
//   - another path matched and the original did not (or was not requested):
//     still exposed at another path. The finding stays as it is, the paths are
//     named, and nothing closes it;
//   - nothing matched: the original endpoint's answer goes through the usual
//     rules for a non-match (a fix only when it answered and was not an
//     edge block, an auth failure or a server error); a re-run that never
//     requested it is inconclusive.
func DecideByRequests(reqs []RequestResult, matchedAt string) (Verdict, bool) {
	want, wantOK := endpointKey(matchedAt)
	if len(reqs) == 0 || !wantOK {
		return Verdict{}, false
	}
	var orig []RequestResult
	var others []string
	for _, r := range reqs {
		if got, ok := endpointKey(r.URL); ok && got == want {
			orig = append(orig, r)
			continue
		}
		if r.Matched && len(others) < maxOtherPaths {
			others = append(others, DisplayURL(r.URL))
		}
	}
	shown := nonEmpty(DisplayURL(matchedAt), "the original endpoint")
	for _, r := range orig {
		if r.Matched {
			return Verdict{Outcome: OutcomeStillVulnerable, Code: ReasonMatched,
				Reason: "the check matched again at " + shown}, true
		}
	}
	if len(others) > 0 {
		state := shown + " was not requested"
		if best, ok := answeredBest(orig); ok {
			state = shown + " answered " + strconv.Itoa(best.Status) + " and did not match"
		} else if len(orig) > 0 {
			state = shown + " gave no answer"
		}
		return Verdict{Outcome: OutcomeStillExposedElsewhere, Code: ReasonMatchedElsewhere,
			Reason:     state + ", but the check matched at another path: " + strings.Join(others, ", "),
			OtherPaths: others}, true
	}
	if len(orig) == 0 {
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonEndpointMismatch,
			Reason: "the check did not request " + shown + " (it requested " + strconv.Itoa(len(reqs)) +
				" other path(s) and none matched), so it proves nothing about that endpoint"}, true
	}
	r, answered := answeredBest(orig)
	if !answered {
		r = orig[0]
	}
	if answered && r.edgeStops() {
		vendor := nonEmpty(r.EdgeVendor, "a CDN or WAF")
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonBlocked,
			Reason: DisplayURL(r.URL) + " was answered by " + vendor + " (" + r.EdgeState + "): the request never reached the service"}, true
	}
	a := Attempt{Found: true, URL: r.URL, EndpointMatches: true, Responded: answered, Status: r.Status}
	return decideNotMatched(a, matchedAt, true, ""), true
}

// answeredBest is the original endpoint's request that got an HTTP answer
// (the first one), if any did.
func answeredBest(rs []RequestResult) (RequestResult, bool) {
	for _, r := range rs {
		if r.Status > 0 {
			return r, true
		}
	}
	return RequestResult{}, false
}

// DecodeRequestsFromAny reads the per-request results from a decoded JSON
// value (a validation result's evidence map).
func DecodeRequestsFromAny(v any) []RequestResult {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return DecodeRequests(b)
}
