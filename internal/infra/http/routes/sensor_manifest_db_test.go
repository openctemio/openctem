package routes

// The sensor manifest end to end (docs/rfcs/RFC-033-sensor-manifest.md):
// PUT /api/v2/sensor/manifest through the v2 edge chain and handler, the
// projection dispatch reads, version history, the heartbeat's
// manifest_digest and send_manifest, and manifests derived from the
// heartbeat of a sensor that registers none.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/sensor"
	protov2 "github.com/openctemio/api/pkg/sensorproto/v2"
)

func manifestBody(nucleiVersion string) map[string]any {
	return map[string]any{
		"schema":       1,
		"sensor":       map[string]any{"name": "openctemio-sensor", "version": "v0.7.0"},
		"sdk":          map[string]any{"name": "openctem-sdk-go", "version": "v0.13.0"},
		"platform":     map[string]any{"os": "linux", "arch": "amd64"},
		"resources":    map[string]any{"cpu_cores": 4, "mem_total_bytes": 8 << 30},
		"concurrency":  map[string]any{"ceiling": 0, "model": "dynamic"},
		"capabilities": []string{"validate"},
		"labels":       map[string]any{"from": "a newer sensor"},
		"tools": []any{
			map[string]any{"name": "nuclei", "kind": "scanner", "version": nucleiVersion, "installed": true,
				"capabilities": []string{"dast", "validate:nuclei", "xss-v2"}},
			map[string]any{"name": "semgrep", "kind": "scanner", "version": "1.179.0", "installed": true, "capabilities": []string{"sast"}},
			map[string]any{"name": "not-a-catalog-tool", "installed": true},
		},
	}
}

func (h *ctlHarness) putManifest(s ctlSensor, body any) protov2.ManifestResponse {
	h.t.Helper()
	resp, raw := h.call(s.key, http.MethodPut, protov2.PathPrefix+protov2.ManifestPath, body)
	h.want(resp, raw, 200, "")
	var out protov2.ManifestResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		h.t.Fatalf("manifest answer %s: %v", raw, err)
	}
	return out
}

func (h *ctlHarness) heartbeatActions(s ctlSensor, body map[string]any) []string {
	h.t.Helper()
	resp, raw := h.call(s.key, http.MethodPost, protov2.PathPrefix+protov2.HeartbeatPath, body)
	h.want(resp, raw, 200, "")
	var out protov2.HeartbeatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		h.t.Fatal(err)
	}
	return out.Actions
}

func (h *ctlHarness) manifestRows(s ctlSensor) (n int, sources []string) {
	h.t.Helper()
	rows, err := h.db.QueryContext(context.Background(),
		`SELECT source FROM sensor_manifests WHERE sensor_id = $1 ORDER BY current_since`, s.id)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			h.t.Fatal(err)
		}
		sources = append(sources, src)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return len(sources), sources
}

func TestSensorManifest_RegisterProjectAndAnswer(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newLimitedSensor(h.tenantID, "manifest", nil, nil, 5)

	// Hello advertises the feature.
	resp, raw := h.call(s.key, http.MethodGet, protov2.PathPrefix+protov2.HelloPath, nil)
	h.want(resp, raw, 200, "")
	if !strings.Contains(string(raw), `"manifest"`) {
		t.Fatalf("hello does not list the manifest feature: %s", raw)
	}

	first := h.putManifest(s, manifestBody("v3.11.1"))
	if !first.Changed || !strings.HasPrefix(first.ManifestDigest, "sha256:") {
		t.Fatalf("first answer %+v", first)
	}
	if !slices.Equal(first.Accepted.Tools, []string{"nuclei", "semgrep"}) {
		t.Fatalf("accepted tools %v", first.Accepted.Tools)
	}
	for _, c := range []string{"nuclei", "dast", "validate:nuclei", "semgrep", "sast", "validate"} {
		if !slices.Contains(first.Accepted.Capabilities, c) {
			t.Fatalf("accepted capabilities %v miss %s", first.Accepted.Capabilities, c)
		}
	}
	reasons := map[string]string{}
	for _, i := range first.Ignored {
		reasons[i.Path] = i.Reason
	}
	if reasons["labels"] != "unknown-member" || reasons["tools[2]"] != "unknown-tool" || reasons["tools[0].capabilities[2]"] != "unknown-capability" {
		t.Fatalf("ignored %+v", first.Ignored)
	}

	// The projection dispatch reads.
	got := h.load(s)
	if got.ManifestDigest != first.ManifestDigest || got.ManifestSource != sensor.ManifestSourceSensor || got.ManifestAt == nil {
		t.Fatalf("pointer %q %q %v", got.ManifestDigest, got.ManifestSource, got.ManifestAt)
	}
	if tl := got.Reported.Tools; len(tl) != 2 || tl[0].Kind != "scanner" || !slices.Equal(tl[0].Capabilities, []string{"dast", "validate:nuclei"}) {
		t.Fatalf("reported tools %+v", tl)
	}
	if got.Reported.OS != "linux" || got.Reported.MaxConcurrentJobs != 0 {
		t.Fatalf("platform/ceiling %q %d", got.Reported.OS, got.Reported.MaxConcurrentJobs)
	}
	if !slices.Contains(got.EffectiveTools(), "nuclei") || !got.HasCapability("validate:nuclei") {
		t.Fatalf("effective tools %v caps %v", got.EffectiveTools(), got.EffectiveCapabilities())
	}

	// Unchanged: no new version.
	again := h.putManifest(s, manifestBody("v3.11.1"))
	if again.Changed || again.ManifestDigest != first.ManifestDigest {
		t.Fatalf("repeat answer %+v", again)
	}
	if n, _ := h.manifestRows(s); n != 1 {
		t.Fatalf("%d versions after a repeat, want 1", n)
	}

	// The heartbeat echoes the digest: nothing to ask. A digest the
	// platform does not have: send_manifest.
	if a := h.heartbeatActions(s, map[string]any{"status": "running", "manifest_digest": first.ManifestDigest}); slices.Contains(a, protov2.ActionSendManifest) {
		t.Fatalf("current digest still asked for the manifest: %v", a)
	}
	if a := h.heartbeatActions(s, map[string]any{"status": "running", "manifest_digest": "sha256:" + strings.Repeat("0", 64)}); !slices.Contains(a, protov2.ActionSendManifest) {
		t.Fatalf("unknown digest not asked for: %v", a)
	}
	// A sensor that sends a digest does not get manifests derived.
	if n, _ := h.manifestRows(s); n != 1 {
		t.Fatalf("%d versions after digest heartbeats, want 1", n)
	}

	// A new nuclei: a new version, the history lists both, and the change
	// is on the timeline with both digests.
	h.sensors.SetEventRepository(postgres.NewSensorEventRepository(&postgres.DB{DB: h.db}), sensor.DefaultEventLimits())
	second := h.putManifest(s, manifestBody("v3.12.0"))
	if !second.Changed || second.ManifestDigest == first.ManifestDigest {
		t.Fatalf("second answer %+v", second)
	}
	versions, err := h.sensors.ListManifests(context.Background(), h.tenantID, s.id, 10)
	if err != nil || len(versions) != 2 || versions[0].Digest != second.ManifestDigest || versions[1].Digest != first.ManifestDigest {
		t.Fatalf("history %v %+v", err, versions)
	}
	cur, err := h.sensors.CurrentManifest(context.Background(), h.tenantID, s.id)
	if err != nil || cur.Digest != second.ManifestDigest || cur.Manifest.Tools[0].Version != "v3.12.0" || len(cur.Ignored) != 3 {
		t.Fatalf("current %v %+v", err, cur)
	}
	var details []byte
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT details FROM sensor_events WHERE sensor_id = $1 AND type = 'tools_changed' ORDER BY at DESC LIMIT 1`, s.id).Scan(&details); err != nil {
		t.Fatalf("no tools_changed event: %v", err)
	}
	if !strings.Contains(string(details), second.ManifestDigest) || !strings.Contains(string(details), first.ManifestDigest) {
		t.Fatalf("event details miss the digests: %s", details)
	}

	// Another tenant cannot read it.
	other := h.newTenant()
	if _, err := h.sensors.CurrentManifest(context.Background(), other, s.id); err == nil {
		t.Fatal("another tenant read the manifest")
	}
}

func TestSensorManifest_Problems(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "manifest-problems")
	path := protov2.PathPrefix + protov2.ManifestPath
	for name, tc := range map[string]struct {
		body    any
		problem protov2.ProblemType
	}{
		"no schema":     {map[string]any{"tools": []any{}}, protov2.ProblemManifestInvalid},
		"not an object": {[]int{1}, protov2.ProblemManifestInvalid},
		"schema 2":      {map[string]any{"schema": 2}, protov2.ProblemManifestSchemaUnsupported},
		"too large":     {map[string]any{"schema": 1, "x": strings.Repeat("a", sensor.MaxManifestBytes)}, protov2.ProblemContentTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			resp, raw := h.call(s.key, http.MethodPut, path, tc.body)
			h.want(resp, raw, tc.problem.Status(), tc.problem.URI())
		})
	}
	// Without a key: 401.
	resp, raw := h.call("", http.MethodPut, path, map[string]any{"schema": 1})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no key: %d %s", resp.StatusCode, raw)
	}
}

// A sensor that registers no manifest (protocol v1, older SDKs) gets one
// derived from its heartbeat: a version when its report changes, none when
// it does not.
func TestSensorManifest_DerivedFromHeartbeat(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newLimitedSensor(h.tenantID, "old-sdk", nil, nil, 5)
	nuclei := func(v string) map[string]any {
		return map[string]any{"name": "nuclei", "kind": "scanner", "version": v, "installed": true}
	}
	hb := func(v string) map[string]any {
		return map[string]any{"status": "running", "tools": []any{nuclei(v)},
			"capabilities": []string{"nuclei", "validate"}, "max_concurrent_jobs": 64,
			"sdk": map[string]any{"name": "openctem-sdk-go", "version": "v0.11.0"}}
	}
	if a := h.heartbeatActions(s, hb("")); slices.Contains(a, protov2.ActionSendManifest) {
		t.Fatalf("a sensor without a digest was asked for a manifest: %v", a)
	}
	h.heartbeatV2(s, hb(""))
	if n, src := h.manifestRows(s); n != 1 || src[0] != sensor.ManifestSourceHeartbeat {
		t.Fatalf("after two identical heartbeats: %d %v", n, src)
	}
	h.heartbeatV2(s, hb("v3.11.1"))
	if n, _ := h.manifestRows(s); n != 2 {
		t.Fatalf("a version bump made %d versions, want 2", n)
	}
	cur, err := h.sensors.CurrentManifest(context.Background(), h.tenantID, s.id)
	if err != nil || cur.Source != sensor.ManifestSourceHeartbeat || cur.Manifest.Tools[0].Version != "v3.11.1" ||
		!slices.Equal(cur.Manifest.Capabilities, []string{"validate"}) || cur.Manifest.Concurrency.Ceiling != 64 {
		t.Fatalf("derived current %v %+v", err, cur)
	}

	// The SDK upgrade: it registers its own; the heartbeat then echoes it
	// and no more manifests are derived.
	reg := h.putManifest(s, manifestBody("v3.11.1"))
	h.heartbeatV2(s, map[string]any{"status": "running", "manifest_digest": reg.ManifestDigest, "tools": []any{nuclei("v3.11.1")}})
	n, src := h.manifestRows(s)
	if n != 3 || src[2] != sensor.ManifestSourceSensor || h.load(s).ManifestSource != sensor.ManifestSourceSensor {
		t.Fatalf("after registration: %d %v", n, src)
	}
}
