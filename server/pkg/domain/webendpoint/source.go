package webendpoint

// How an endpoint was found is decided by the platform from the command the
// report is bound to, not by the report (docs/architecture/web-discovery.md).
// A hostile or buggy tool cannot dress a guessed path as a crawled one, or
// the reverse: a path discovery job's endpoints are always `guess`, and no
// other job can produce `guess`.

import (
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// SourceGuess is the source of an endpoint found by path discovery: a
// candidate path the platform listed, requested and confirmed to differ from
// the origin's not-found answer. It is never taken from a report.
const SourceGuess = "guess"

// Capabilities whose endpoints the platform labels itself.
const (
	// CapabilityEnumerateWebPaths requests candidate paths on an origin.
	CapabilityEnumerateWebPaths = "enumerate.web_paths"
	// CapabilityEnumerateWebParams requests endpoints with candidate
	// parameter names (reserved; no job runs it yet).
	CapabilityEnumerateWebParams = "enumerate.web_params"
	// CapabilityCrawlWeb follows links.
	CapabilityCrawlWeb = "crawl.web"
)

// crawlSources are the sources a crawl may claim; anything else it claims
// is stored as crawl.
var crawlSources = []string{
	string(ctis.EndpointSourceCrawl), string(ctis.EndpointSourceJS),
	string(ctis.EndpointSourceSitemap), string(ctis.EndpointSourceRobots),
}

// Evidence is what a path discovery hit proves about the response: the
// body size and the first 16 hex characters of the sha-256 of the
// normalised body. The body never leaves the sensor.
type Evidence struct {
	Size int    `json:"size"`
	Hash string `json:"hash"`
}

// EvidenceNamespace and EvidenceKey locate the evidence in a CTIS endpoint:
// extensions["io.openctem"].response = {"size": int, "hash": "16 hex"}.
const (
	EvidenceNamespace = "io.openctem"
	EvidenceKey       = "response"
	evidenceHashLen   = 16
)

// ErrNoEvidence refuses a path discovery endpoint whose report carries no
// valid response evidence: without it nothing shows that the path answered
// differently from a path that does not exist.
var ErrNoEvidence = errors.New("guessed endpoint without response evidence")

// CapabilityWord is a capability id without its version, lower-cased
// ("enumerate.web_paths@1" gives "enumerate.web_paths").
func CapabilityWord(capability string) string {
	w, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(capability)), "@")
	return w
}

// GuessCapability reports whether a job of the capability produces guessed
// endpoints.
func GuessCapability(capability string) bool {
	switch CapabilityWord(capability) {
	case CapabilityEnumerateWebPaths, CapabilityEnumerateWebParams:
		return true
	}
	return false
}

// BindSource sets the observation's source from the capability of the
// command the report is bound to ("" for a report bound to no capability):
//
//   - path discovery (enumerate.web_paths, enumerate.web_params): `guess`,
//     whatever the report claims, and only with valid response evidence
//     (ErrNoEvidence otherwise: the endpoint is refused, not stored);
//   - crawl.web: the claimed crawl, js, sitemap or robots, else crawl;
//   - anything else: the claimed source, never `guess`.
//
// Evidence is kept only on a guessed endpoint.
func BindSource(obs *Observation, capability string, e ctis.Endpoint) error {
	obs.Evidence = nil
	if GuessCapability(capability) {
		ev, ok := EvidenceOf(e)
		if !ok {
			return ErrNoEvidence
		}
		obs.Sources = []string{SourceGuess}
		obs.Evidence = &ev
		return nil
	}
	claimed := sourceOf(e.Source)
	if claimed == SourceGuess || (CapabilityWord(capability) == CapabilityCrawlWeb && !slices.Contains(crawlSources, claimed)) {
		claimed = string(ctis.EndpointSourceCrawl)
	}
	obs.Sources = []string{claimed}
	return nil
}

// EvidenceOf reads the response evidence of a CTIS endpoint: a size that is
// a whole number from 0 to 2^31-1 and a hash of exactly 16 lower-case hex
// characters. Anything else is no evidence.
func EvidenceOf(e ctis.Endpoint) (Evidence, bool) {
	raw, ok := e.Extensions.Get(EvidenceNamespace, EvidenceKey)
	if !ok {
		return Evidence{}, false
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return Evidence{}, false
	}
	size, ok := wholeNumber(m["size"])
	if !ok {
		return Evidence{}, false
	}
	hash, ok := m["hash"].(string)
	if !ok || !validEvidenceHash(hash) {
		return Evidence{}, false
	}
	return Evidence{Size: size, Hash: hash}, true
}

// wholeNumber reads a JSON number that is a whole number from 0 to
// math.MaxInt32 (the column is an integer).
func wholeNumber(v any) (int, bool) {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		f = float64(i)
	default:
		return 0, false
	}
	if f < 0 || f > math.MaxInt32 || f != math.Trunc(f) {
		return 0, false
	}
	return int(f), true
}

func validEvidenceHash(h string) bool {
	if len(h) != evidenceHashLen {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
