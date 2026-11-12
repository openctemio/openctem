package routes

// The sensor posture end to end (RFC-040 §11.4): hello lists "posture", a
// manifest's posture and local_policy.required are stored sanitized, and
// the management list and detail derive the posture block from the stored
// local policy and the current manifest, within the tenant.

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func postureManifest(localPolicy, posture map[string]any) map[string]any {
	body := manifestBody("v3.11.1")
	body["local_policy"] = localPolicy
	if posture != nil {
		body["posture"] = posture
	}
	return body
}

func TestSensorPosture_ListAndDetail_DB(t *testing.T) {
	h := newCtlHarness(t)
	m := newActivityRouteHarness(t)

	// A legacy install: no policy and none required, unpinned, unconfined,
	// bearer key.
	weak := h.newSensor(h.tenantID, "posture-weak")
	resp, raw := h.call(weak.key, http.MethodGet, protov2.PathPrefix+protov2.HelloPath, nil)
	h.want(resp, raw, 200, "")
	if !strings.Contains(string(raw), `"`+protov2.FeaturePosture+`"`) {
		t.Fatalf("hello does not list posture: %s", raw)
	}

	reg := h.putManifest(weak, postureManifest(map[string]any{"state": "absent", "required": false},
		map[string]any{"platform_tls": map[string]any{"pin": "none"},
			"sandbox": map[string]any{"mode": "auto", "sandboxed": true, "network_enforced": false}}))
	if slices.ContainsFunc(reg.Ignored, func(i protov2.ManifestIgnored) bool { return i.Path == "posture" }) {
		t.Fatalf("posture ignored as an unknown member: %+v", reg.Ignored)
	}
	h.heartbeatActions(weak, map[string]any{"status": "running", "manifest_digest": reg.ManifestDigest,
		"local_policy": map[string]any{"state": "absent", "required": false}})

	// A hardened one: enforced policy, pinned CA, confined tools, key-bound.
	strong := h.newSensor(h.tenantID, "posture-strong")
	digest := "sha256:" + strings.Repeat("b", 64)
	policy := map[string]any{"state": "enforced", "source": "file", "digest": digest}
	reg = h.putManifest(strong, postureManifest(policy,
		map[string]any{"platform_tls": map[string]any{"pin": "fingerprint"},
			"sandbox": map[string]any{"mode": "required", "sandboxed": true, "network_enforced": true}}))
	h.heartbeatActions(strong, map[string]any{"status": "running", "manifest_digest": reg.ManifestDigest, "local_policy": policy})

	// Fails closed without a policy; the posture values are made up.
	closed := h.newSensor(h.tenantID, "posture-closed")
	reg = h.putManifest(closed, postureManifest(map[string]any{"state": "absent", "required": true},
		map[string]any{"platform_tls": map[string]any{"pin": "trust-me"}, "extra": true}))
	h.heartbeatActions(closed, map[string]any{"status": "running", "manifest_digest": reg.ManifestDigest,
		"local_policy": map[string]any{"state": "absent", "required": true}})

	// Key-bound after its last request (the harness speaks bearer).
	if _, err := h.db.Exec(`UPDATE sensors SET auth_kind = 'key_bound' WHERE id = $1`, strong.id); err != nil {
		t.Fatal(err)
	}

	viewer := m.member(h.tenantID, "viewer")
	detail := func(id string) handler.SensorResponse {
		var r handler.SensorResponse
		mustJSON(t, m.expect(viewer, http.MethodGet, "/api/v1/sensors/"+id, "", http.StatusOK), &r)
		return r
	}
	check := func(where string, r handler.SensorResponse, lp, pin string, net *bool, unhardened ...string) {
		t.Helper()
		p := r.Posture
		if p.LocalPolicy != lp || p.PlatformPin != pin || (p.NetworkEnforced == nil) != (net == nil) ||
			(net != nil && *p.NetworkEnforced != *net) || !slices.Equal(p.Unhardened, append([]string{}, unhardened...)) {
			t.Fatalf("%s %s: posture %+v (network_enforced %v)", where, r.Name, p, p.NetworkEnforced)
		}
	}
	no, yes := false, true

	w, s, c := detail(weak.id), detail(strong.id), detail(closed.id)
	check("detail", w, "absent_legacy", "none", &no, "policy_none", "pin_none", "network_unenforced", "bearer_key")
	check("detail", s, "enforced", "fingerprint", &yes)
	check("detail", c, "absent_required", "unknown", nil, "bearer_key")
	if w.LocalPolicy.Required || !c.LocalPolicy.Required {
		t.Fatalf("local_policy.required: weak %+v closed %+v", w.LocalPolicy, c.LocalPolicy)
	}

	var list struct {
		Items []handler.SensorResponse `json:"items"`
	}
	mustJSON(t, m.expect(viewer, http.MethodGet, "/api/v1/sensors?per_page=100", "", http.StatusOK), &list)
	seen := 0
	for _, r := range list.Items {
		switch r.ID {
		case weak.id:
			check("list", r, "absent_legacy", "none", &no, "policy_none", "pin_none", "network_unenforced", "bearer_key")
		case strong.id:
			check("list", r, "enforced", "fingerprint", &yes)
		case closed.id:
			check("list", r, "absent_required", "unknown", nil, "bearer_key")
		default:
			continue
		}
		seen++
	}
	if seen != 3 {
		t.Fatalf("list has %d of the 3 sensors", seen)
	}

	// Another organization sees none of them.
	outsider := m.member(m.tenant(), "admin")
	m.expect(outsider, http.MethodGet, "/api/v1/sensors/"+weak.id, "", http.StatusNotFound)
	if b := m.expect(outsider, http.MethodGet, "/api/v1/sensors?per_page=100", "", http.StatusOK); strings.Contains(b, weak.id) {
		t.Fatalf("another organization lists the sensor")
	}
}
