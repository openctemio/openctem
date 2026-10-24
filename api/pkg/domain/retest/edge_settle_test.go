package retest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
)

// answer is one exchange at url with the given status, headers and body.
func answer(url string, status int, body string, headers ...evidence.Header) []evidence.Item {
	return []evidence.Item{{Kind: evidence.KindHTTPExchange, HTTP: &evidence.HTTP{
		Request:  &evidence.HTTPRequest{Method: "GET", URL: url},
		Response: &evidence.HTTPResponse{Status: status, Headers: headers, Body: body},
	}}}
}

const swaggerAt = "https://api.example.com/webjars/swagger-ui/index.html"

var (
	probeUp    = CheckResult{Outcome: "detected", Summary: "target is still reachable"}
	probeDown  = CheckResult{Outcome: "not_detected", Summary: "connection refused"}
	cloudflare = answer(swaggerAt, 403,
		`<html><head><title>Attention Required! | Cloudflare</title></head><body>Sorry, you have been blocked. Cloudflare Ray ID</body></html>`,
		evidence.Header{Name: "Server", Value: "cloudflare"})
	origin403 = answer(swaggerAt, 403, `<html><body>Forbidden</body></html>`,
		evidence.Header{Name: "Server", Value: "nginx"})
)

func nm(items []evidence.Item) CheckResult {
	return CheckResult{Outcome: "not_detected", Evidence: items}
}

var (
	exposure = ExposureClass([]string{"exposure", "swagger", "api"})
	rce      = ExposureClass([]string{"cve", "rce", "exposure"})
)

func TestEdgeBlockedIsNeverFixed(t *testing.T) {
	for _, cls := range []Class{{}, {Exposure: true, PriorAccessDenied: true}} {
		v := Decide(nm(cloudflare), probeUp, swaggerAt, cls)
		if v.Outcome != OutcomeInconclusive || v.Code != ReasonEdgeBlocked {
			t.Fatalf("edge 403 = %s/%s (%s)", v.Outcome, v.Code, v.Reason)
		}
		if !strings.Contains(v.Reason, "cloudflare") || !strings.Contains(v.Reason, "Allow the scanner") {
			t.Errorf("reason lacks the vendor or the guidance: %s", v.Reason)
		}
	}
	// A challenge page answered with 200 is an edge decision as well.
	ch := answer(swaggerAt, 200, "x", evidence.Header{Name: "Cf-Mitigated", Value: "challenge"})
	if v := Decide(nm(ch), probeUp, swaggerAt, Class{Exposure: true, PriorAccessDenied: true}); v.Code != ReasonEdgeBlocked {
		t.Fatalf("challenge on 200 = %s/%s", v.Outcome, v.Code)
	}
}

func TestOriginDeniedExposureNeedsTwoSightings(t *testing.T) {
	// Second sighting by a previous retest: fixed.
	v := Decide(nm(origin403), probeDown, swaggerAt, Class{Exposure: exposure, PriorAccessDenied: true})
	if v.Outcome != OutcomeConfirmedFixed || v.Code != ReasonAccessDenied || !strings.Contains(v.Reason, "access now denied by the server") {
		t.Fatalf("two sightings = %s/%s (%s)", v.Outcome, v.Code, v.Reason)
	}
	// One retest plus the reach check that saw the host answer: fixed.
	v = Decide(nm(origin403), probeUp, swaggerAt, Class{Exposure: exposure})
	if v.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("retest plus reach = %s (%s)", v.Outcome, v.Reason)
	}
	// One sighting, nothing else: inconclusive.
	v = Decide(nm(origin403), probeDown, swaggerAt, Class{Exposure: exposure})
	if v.Outcome != OutcomeInconclusive || v.Code != ReasonAccessDenied {
		t.Fatalf("one sighting = %s/%s", v.Outcome, v.Code)
	}
	// The tool path has no separate probe: its first sighting never fixes.
	raw := json.RawMessage(`{"retest":{"verdicts":[{"ref":"f1","verdict":"fixed","evidence":[{"kind":"http_exchange","http":{"request":{"method":"GET","url":"` + swaggerAt + `"},"response":{"status":403}}}]}]}}`)
	if r := DecideToolVerdict(raw, "f1", swaggerAt, Class{Exposure: true}); r.Verdict.Outcome != OutcomeInconclusive {
		t.Fatalf("tool first sighting = %s", r.Verdict.Outcome)
	}
	if r := DecideToolVerdict(raw, "f1", swaggerAt, Class{Exposure: true, PriorAccessDenied: true}); r.Verdict.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("tool second sighting = %s", r.Verdict.Outcome)
	}
}

func TestOriginDeniedOtherClassStaysInconclusive(t *testing.T) {
	for _, status := range []int{401, 403} {
		v := Decide(nm(answer(swaggerAt, status, "no", evidence.Header{Name: "Server", Value: "nginx"})), probeUp, swaggerAt,
			Class{Exposure: rce, PriorAccessDenied: true})
		if v.Outcome != OutcomeInconclusive || v.Code != ReasonAccessDenied || !strings.Contains(v.Reason, "cannot confirm the fix") {
			t.Fatalf("%d on an RCE check = %s/%s (%s)", status, v.Outcome, v.Code, v.Reason)
		}
	}
}

func TestExposureClass(t *testing.T) {
	yes := [][]string{{"exposure"}, {"Swagger", "api"}, {"exposed-panel"}, {"config", "files"}, {"debug"}}
	no := [][]string{nil, {"cve", "rce", "exposure"}, {"sqli"}, {"auth-bypass", "panel"}, {"tech"}}
	for _, tags := range yes {
		if !ExposureClass(tags) {
			t.Errorf("%v should be exposure", tags)
		}
	}
	for _, tags := range no {
		if ExposureClass(tags) {
			t.Errorf("%v should not be exposure", tags)
		}
	}
}
