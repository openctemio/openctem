package retest

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
)

// Attempt is what a re-run's evidence proves about the request it made.
type Attempt struct {
	// Found: the re-run reported at least one HTTP exchange.
	Found bool
	// URL is the request URL of the exchange considered (the one at the
	// finding's endpoint when there is one).
	URL string
	// EndpointMatches: that request went to the finding's own endpoint
	// (scheme, host, port, path and parameter names of its matched-at).
	EndpointMatches bool
	// Responded: an HTTP response came back.
	Responded bool
	// Status is the response status (0 without a response).
	Status int
}

// AnalyzeAttempt reads a re-run's evidence: the exchange at the finding's
// endpoint when there is one, else the first exchange.
func AnalyzeAttempt(items []evidence.Item, matchedAt string) Attempt {
	want, wantOK := endpointKey(matchedAt)
	var first *evidence.Item
	for i := range items {
		it := &items[i]
		if it.Kind != evidence.KindHTTPExchange || it.HTTP == nil || it.HTTP.Request == nil {
			continue
		}
		if first == nil {
			first = it
		}
		if got, ok := endpointKey(it.HTTP.Request.URL); ok && wantOK && got == want {
			return attemptOf(it, true)
		}
	}
	if first == nil {
		return Attempt{}
	}
	return attemptOf(first, false)
}

func attemptOf(it *evidence.Item, matches bool) Attempt {
	a := Attempt{Found: true, URL: it.HTTP.Request.URL, EndpointMatches: matches}
	if r := it.HTTP.Response; r != nil && r.Status > 0 {
		a.Responded, a.Status = true, r.Status
	}
	return a
}

// endpointKey is a URL reduced to what identifies an endpoint: scheme, host,
// port (default ports dropped), path, and the sorted parameter names. Values
// are not compared: a token in the query differs between runs and is masked.
func endpointKey(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	names := make([]string, 0)
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	return scheme + "://" + host + ":" + port + path + "?" + strings.Join(names, "&"), true
}

// DisplayURL is a URL safe for a reason or a ticket: no userinfo, and query
// values replaced by "…" (a token in a URL must not reach Jira).
func DisplayURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return evidence.RedactText(raw)
	}
	u.User = nil
	u.Fragment = ""
	if q := u.Query(); len(q) > 0 {
		names := make([]string, 0, len(q))
		for k := range q {
			names = append(names, k+"=…")
		}
		sort.Strings(names)
		u.RawQuery = strings.Join(names, "&")
	}
	return u.String()
}

// decideNotMatched turns a re-run that did not match into an outcome, from
// what its evidence proves. reached says whether a separate reachability
// probe (or the tool runtime) saw the target answer.
func decideNotMatched(a Attempt, matchedAt string, reached bool, unreachableDetail string) Verdict {
	if !a.Found {
		if !reached {
			return Verdict{Outcome: OutcomeInconclusive, Code: ReasonUnreachable,
				Reason: "target unreachable: " + nonEmpty(unreachableDetail, "the reachability probe did not connect")}
		}
		return Verdict{Outcome: OutcomeNotReproduced, Code: ReasonNoEndpointProof,
			Reason: "the check did not match, but the sensor reported no request evidence, so it is not proven that " +
				nonEmpty(DisplayURL(matchedAt), "the original endpoint") + " was checked"}
	}
	shown := DisplayURL(a.URL)
	switch {
	case !a.EndpointMatches:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonEndpointMismatch,
			Reason: "the re-run requested " + shown + ", not the original endpoint " + nonEmpty(DisplayURL(matchedAt), "(unknown)")}
	case !a.Responded:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonUnreachable,
			Reason: "no HTTP response from " + shown}
	case a.Status == 401 || a.Status == 407:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonAuthChanged,
			Reason: shown + " answered " + strconv.Itoa(a.Status) + ": authentication is required now, so the check could not see the issue"}
	case a.Status == 403 || a.Status == 429:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonBlocked,
			Reason: shown + " answered " + strconv.Itoa(a.Status) + ": the request was blocked or rate limited"}
	case a.Status >= 500:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonServerError,
			Reason: shown + " answered " + strconv.Itoa(a.Status) + ": a server error proves nothing about the fix"}
	}
	return Verdict{Outcome: OutcomeConfirmedFixed, Code: ReasonNotMatched,
		Reason: shown + " answered " + strconv.Itoa(a.Status) + " and the check did not match"}
}
