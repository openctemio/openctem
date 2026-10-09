package routes

// Hostile sensor suite, lookups (research/84 F-BOLA-2, F-BOLA-3): a
// compromised sensor in one scan zone asks the fingerprint check, the
// baseline diff and the suppression list about another zone. It gets the
// answer it would get for something that does not exist; the legitimate
// callers (a sensor asking about its zone or its command's targets, a
// collector) keep their answers.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// lookupWorld is one tenant with two zones, a sensor in each, an asset with
// a finding in each and a repository with a finding open on its base branch.
type lookupWorld struct {
	h                      *ctlHarness
	zoneA, zoneB           ctlSensor
	assetA, assetB, repo   string
	fpA, fpB, fpRepo       string
	repoName, repoBaseName string
}

func newLookupWorld(t *testing.T) *lookupWorld {
	t.Helper()
	h := newCtlHarness(t)
	w := &lookupWorld{h: h, zoneA: h.newSensor(h.tenantID, "zone-a"), zoneB: h.newSensor(h.tenantID, "zone-b"),
		assetA: shared.NewID().String(), assetB: shared.NewID().String(), repo: shared.NewID().String(),
		fpA: "fp-zone-a-" + shared.NewID().String(), fpB: "fp-zone-b-" + shared.NewID().String(),
		fpRepo: "fp-repo-" + shared.NewID().String(), repoName: "github.com/acme/zone-b-app", repoBaseName: "main"}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tid := h.tenantID
	zA, zB := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, 'dmz', '{10.1.0.0/16}')`, zA, tid)
	exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, 'core', '{10.2.0.0/16}')`, zB, tid)
	exec(`INSERT INTO scan_zone_sensors (tenant_id, zone_id, sensor_id) VALUES ($1, $2, $3)`, tid, zA, w.zoneA.id)
	exec(`INSERT INTO scan_zone_sensors (tenant_id, zone_id, sensor_id) VALUES ($1, $2, $3)`, tid, zB, w.zoneB.id)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, '10.1.0.5', 'host')`, w.assetA, tid)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, '10.2.0.7', 'host')`, w.assetB, tid)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`, w.repo, tid, w.repoName)
	finding := func(assetID, fp string) string {
		id := shared.NewID().String()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, 'sast', 'semgrep', 'lookup reach', 'high', $4, 'confirmed')`, id, tid, assetID, fp)
		return id
	}
	finding(w.assetA, w.fpA)
	finding(w.assetB, w.fpB)
	repoFinding := finding(w.repo, w.fpRepo)
	exec(`INSERT INTO asset_repositories (asset_id) VALUES ($1)`, w.repo)
	branchID := shared.NewID().String()
	exec(`INSERT INTO repository_branches (id, repository_id, name, is_default) VALUES ($1, $2, $3, true)`, branchID, w.repo, w.repoBaseName)
	exec(`INSERT INTO finding_branch_occurrences (tenant_id, finding_id, branch_id, repository_id, status)
		VALUES ($1, $2, $3, $4, 'open')`, tid, repoFinding, branchID, w.repo)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM repository_branches WHERE id = $1`, branchID)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = $1`, tid)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM assets WHERE tenant_id = $1`, tid)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM scan_zones WHERE tenant_id = $1`, tid)
	})
	return w
}

// commandFor creates a scan command assigned to the sensor with the targets.
func (w *lookupWorld) commandFor(t *testing.T, s ctlSensor, targets ...string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"scanner": "semgrep", "targets": targets})
	if _, err := w.h.cmds.Create(context.Background(), command.CreateInput{TenantID: w.h.tenantID, SensorID: s.id,
		Type: "scan", Priority: "normal", Payload: payload, ExpiresIn: 3600}); err != nil {
		t.Fatalf("create command: %v", err)
	}
}

func (w *lookupWorld) check(t *testing.T, s ctlSensor, fps ...string) protov2.FingerprintsCheckResponse {
	t.Helper()
	resp, raw := w.h.call(s.key, http.MethodPost, "/api/v2/sensor/fingerprints/check", map[string]any{"fingerprints": fps})
	w.h.want(resp, raw, 200, "")
	return decodeAs[protov2.FingerprintsCheckResponse](t, raw)
}

func (w *lookupWorld) baselineDiff(t *testing.T, s ctlSensor, repository string, fps ...string) string {
	t.Helper()
	resp, raw := w.h.call(s.key, http.MethodPost, "/api/v2/sensor/fingerprints/baseline-diff",
		map[string]any{"repository": repository, "base_branch": w.repoBaseName, "fingerprints": fps})
	w.h.want(resp, raw, 200, "")
	return string(raw)
}

// F-BOLA-2: a zone-A sensor gets "missing" for a fingerprint that exists
// only on a zone-B asset; it still gets "existing" for its own zone.
func TestHostileSensor_FingerprintCheckOtherZoneIsMissing(t *testing.T) {
	w := newLookupWorld(t)
	got := w.check(t, w.zoneA, w.fpA, w.fpB, "fp-nobody")
	if !slices.Equal(got.Existing, []string{w.fpA}) || !slices.Equal(got.Missing, []string{w.fpB, "fp-nobody"}) {
		t.Fatalf("zone-A sensor: existing=%v missing=%v, want only its own zone's fingerprint known", got.Existing, got.Missing)
	}
	got = w.check(t, w.zoneB, w.fpA, w.fpB)
	if !slices.Equal(got.Existing, []string{w.fpB}) || !slices.Equal(got.Missing, []string{w.fpA}) {
		t.Fatalf("zone-B sensor: existing=%v missing=%v", got.Existing, got.Missing)
	}
}

// The legitimate callers keep their answers: a sensor without a zone that
// holds a command on the asset, and a collector (tenant-wide by role).
func TestHostileSensor_FingerprintCheckLegitimateReach(t *testing.T) {
	w := newLookupWorld(t)
	runner := w.h.newSensor(w.h.tenantID, "runner")
	if got := w.check(t, runner, w.fpA, w.fpB); len(got.Existing) != 0 {
		t.Fatalf("sensor with no zone and no command: existing=%v, want none", got.Existing)
	}
	w.commandFor(t, runner, "10.2.0.0/24")
	if got := w.check(t, runner, w.fpA, w.fpB); !slices.Equal(got.Existing, []string{w.fpB}) {
		t.Fatalf("sensor holding a command on zone B: existing=%v, want %s", got.Existing, w.fpB)
	}

	out, err := w.h.sensors.CreateSensor(context.Background(), sensor.CreateSensorInput{TenantID: w.h.tenantID,
		Name: "collector", Type: "collector", Capabilities: []string{"sast"}, ExecutionMode: "daemon"})
	if err != nil {
		t.Fatal(err)
	}
	collector := ctlSensor{id: out.Sensor.ID.String(), key: out.APIKey}
	if got := w.check(t, collector, w.fpA, w.fpB); len(got.Existing) != 2 {
		t.Fatalf("collector: existing=%v, want both (tenant-wide role)", got.Existing)
	}
}

// F-BOLA-3: baseline diff for a repository the sensor does not reach
// answers exactly like a repository that does not exist; the sensor holding
// a command on the repository gets the real diff.
func TestHostileSensor_BaselineDiffUnreachableRepoIsUnknown(t *testing.T) {
	w := newLookupWorld(t)
	unknown := w.baselineDiff(t, w.zoneA, "github.com/acme/does-not-exist", w.fpRepo)
	got := w.baselineDiff(t, w.zoneA, w.repoName, w.fpRepo)
	if got != unknown {
		t.Fatalf("unreachable repository answered %s, an unknown one %s: an existence oracle", got, unknown)
	}
	var d protov2.BaselineDiffResponse
	if err := json.Unmarshal([]byte(got), &d); err != nil || d.BaseBranchScanned || !slices.Equal(d.NewFingerprints, []string{w.fpRepo}) {
		t.Fatalf("unreachable repository: %s", got)
	}

	w.commandFor(t, w.zoneB, "https://github.com/acme/zone-b-app.git")
	got = w.baselineDiff(t, w.zoneB, w.repoName, w.fpRepo, "fp-new")
	if err := json.Unmarshal([]byte(got), &d); err != nil || !d.BaseBranchScanned ||
		!slices.Equal(d.PreExistingFingerprints, []string{w.fpRepo}) || !slices.Equal(d.NewFingerprints, []string{"fp-new"}) {
		t.Fatalf("repository of the sensor's command: %s", got)
	}
}

// F-BOLA-3: the suppression list leaves out rules on assets the sensor does
// not reach; rules tied to no asset and rules on its own zone stay.
func TestHostileSensor_SuppressionsOmitUnreachableAssets(t *testing.T) {
	w := newLookupWorld(t)
	h := w.h
	userID := shared.NewID().String()
	if _, err := h.db.ExecContext(context.Background(), `INSERT INTO users (id, email, name) VALUES ($1, $2, 'sup')`,
		userID, "sup-"+userID+"@openctem-test.local"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM suppression_rules WHERE requested_by = $1`, userID)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	for _, r := range []struct {
		ruleID string
		asset  any
	}{{"rule-any-asset", nil}, {"rule-zone-a", w.assetA}, {"rule-zone-b", w.assetB}} {
		if _, err := h.db.ExecContext(context.Background(), `INSERT INTO suppression_rules
			(tenant_id, rule_id, tool_name, name, status, requested_by, asset_id, path_pattern)
			VALUES ($1, $2, 'semgrep', $2, 'approved', $3, $4, 'internal/secret/**')`, h.tenantID, r.ruleID, userID, r.asset); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(s ctlSensor) []string {
		resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/suppressions", nil)
		h.want(resp, raw, 200, "")
		l := decodeAs[protov2.SuppressionList](t, raw)
		out := make([]string, 0, len(l.Rules))
		for _, r := range l.Rules {
			out = append(out, r.RuleID)
		}
		slices.Sort(out)
		if l.Count != len(out) {
			t.Fatalf("count %d, %d rules", l.Count, len(out))
		}
		return out
	}
	if got := ids(w.zoneA); !slices.Equal(got, []string{"rule-any-asset", "rule-zone-a"}) {
		t.Fatalf("zone-A sensor got rules %v, want the asset-free rule and its own zone's", got)
	}
	if got := ids(w.zoneB); !slices.Equal(got, []string{"rule-any-asset", "rule-zone-b"}) {
		t.Fatalf("zone-B sensor got rules %v", got)
	}
}
