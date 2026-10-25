package retest

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/edgeprotect"

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
	// Edge is what an edge protection (CDN or WAF) did with the request,
	// read from the response's headers and body. Direct when no vendor
	// marker is present: a bare 403 is the origin's own answer.
	Edge edgeprotect.Verdict
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
		a.Edge = classifyEdge(r)
	}
	return a
}

// classifyEdge runs the edge detector over a recorded response. The body
// is read as stored (text, or base64 decoded); a body that cannot be decoded
// is classified on headers alone.
func classifyEdge(r *evidence.HTTPResponse) edgeprotect.Verdict {
	h := http.Header{}
	for _, kv := range r.Headers {
		h.Add(kv.Name, kv.Value)
	}
	body := []byte(r.Body)
	if r.BodyEncoding == "base64" {
		b, err := base64.StdEncoding.DecodeString(r.Body)
		if err != nil {
			b = nil
		}
		body = b
	}
	return edgeprotect.Classify(r.Status, h, "", body)
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
func decideNotMatched(a Attempt, matchedAt string, reached bool, unreachableDetail string, cls Class) Verdict {
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
	case a.Edge.State.Stops() || a.Edge.State == edgeprotect.RateLimited:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonEdgeBlocked,
			Reason: shown + " answered " + strconv.Itoa(a.Status) + ": " + edgeLabel(a.Edge) +
				" stopped the request before it reached the service, so the check could not see the issue. " +
				"Allow the scanner at the edge, then retest"}
	case a.Status == 401 || a.Status == 403:
		return decideAccessDenied(a, shown, cls)
	case a.Status == 407:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonAuthChanged,
			Reason: shown + " answered " + strconv.Itoa(a.Status) + ": authentication is required now, so the check could not see the issue"}
	case a.Status == 429:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonBlocked,
			Reason: shown + " answered " + strconv.Itoa(a.Status) + ": the request was blocked or rate limited"}
	case a.Status >= 500:
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonServerError,
			Reason: shown + " answered " + strconv.Itoa(a.Status) + ": a server error proves nothing about the fix"}
	}
	return Verdict{Outcome: OutcomeConfirmedFixed, Code: ReasonNotMatched,
		Reason: shown + " answered " + strconv.Itoa(a.Status) + " and the check did not match"}
}

// edgeLabel names the edge that stopped a request.
func edgeLabel(v edgeprotect.Verdict) string {
	if v.Vendor == "" {
		return "an edge protection (CDN or WAF)"
	}
	return "the " + strings.ReplaceAll(v.Vendor, "_", " ") + " edge protection"
}

// decideAccessDenied settles an origin 401 or 403 (no edge marker). For an
// exposure class check (an exposed page, document or panel) the server now
// refusing the request is the fix, once it is seen twice: on two consecutive
// retests at least MinDenialGap apart, both answered by the origin.
// For any other class a refusal says nothing about the weakness, because the
// check may simply have been refused before reaching the vulnerable code.
func decideAccessDenied(a Attempt, shown string, cls Class) Verdict {
	status := strconv.Itoa(a.Status)
	if !cls.Exposure {
		return Verdict{Outcome: OutcomeInconclusive, Code: ReasonAccessDenied,
			Reason: shown + " answered " + status + ": access denied: cannot confirm the fix"}
	}
	if cls.PriorAccessDenied {
		return Verdict{Outcome: OutcomeConfirmedFixed, Code: ReasonAccessDenied,
			Reason: shown + " answered " + status + ": access now denied by the server"}
	}
	return Verdict{Outcome: OutcomeInconclusive, Code: ReasonAccessDenied,
		Reason: shown + " answered " + status + ": access denied by the server; the next retest confirms the fix if it is denied again"}
}
