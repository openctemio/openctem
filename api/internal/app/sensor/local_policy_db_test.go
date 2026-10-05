package sensor_test

import (
	"context"
	"strings"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// TestSensorLocalPolicy_HeartbeatsAndRefusals_DB (RFC-040 §5.7): a heartbeat's
// local policy report is sanitized and stored, a slim heartbeat keeps the
// stored summary, state changes and the kill switch reach the timeline, and a
// command the sensor refused under its policy is recorded as a job event
// (identical refusals fold into one).
func TestSensorLocalPolicy_HeartbeatsAndRefusals_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	id := h.sensor(tid)
	ctx := context.Background()
	digest := "sha256:" + strings.Repeat("cd", 32)

	read := func() *sensordom.Sensor {
		t.Helper()
		a, err := h.svc.GetSensor(ctx, tid.String(), id.String())
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// A full report, with values the sanitizer must drop.
	h.heartbeat(id, sensorapp.SensorHeartbeatData{LocalPolicy: &sensordom.LocalPolicyReport{
		State: "enforced", Source: "file", Digest: digest,
		Summary:  &sensordom.LocalPolicySummary{TargetsAllow: 3, Ports: "443", Tools: []string{"nuclei", "bad tool"}},
		Warnings: []string{"w\u202e"},
	}})
	a := read()
	if a.LocalPolicy == nil || a.LocalPolicy.State != sensordom.LocalPolicyEnforced || a.LocalPolicy.Digest != digest ||
		a.LocalPolicy.Summary == nil || strings.Join(a.LocalPolicy.Summary.Tools, ",") != "nuclei" ||
		strings.ContainsRune(a.LocalPolicy.Warnings[0], '\u202e') {
		t.Fatalf("stored %+v", a.LocalPolicy)
	}
	if e, ok := h.events(tid, id)[string(sensordom.EventLocalPolicyChanged)]; !ok || e.Summary != "Local policy enforced" {
		t.Fatalf("first report event: %+v %v", e, ok)
	}

	// A slim heartbeat (no summary) of the same policy with the kill switch:
	// the summary stays, the state shows paused.
	h.heartbeat(id, sensorapp.SensorHeartbeatData{LocalPolicy: &sensordom.LocalPolicyReport{
		State: "enforced", Source: "file", Digest: digest, KillSwitch: true}})
	a = read()
	if a.LocalPolicy.Summary == nil || a.LocalPolicy.Summary.TargetsAllow != 3 || a.LocalPolicy.DisplayState() != sensordom.LocalPolicyPaused {
		t.Fatalf("slim heartbeat: %+v", a.LocalPolicy)
	}
	if e := h.events(tid, id)[string(sensordom.EventLocalPolicyChanged)]; e.Summary != "Paused by the local kill switch" {
		t.Fatalf("kill switch event: %+v", e)
	}

	// A heartbeat without a report (an older SDK) keeps it; a report with a
	// state the platform does not know is not stored.
	h.heartbeat(id, sensorapp.SensorHeartbeatData{})
	h.heartbeat(id, sensorapp.SensorHeartbeatData{LocalPolicy: &sensordom.LocalPolicyReport{State: "whatever"}})
	if a = read(); a.LocalPolicy == nil || a.LocalPolicy.Digest != digest {
		t.Fatalf("report lost: %+v", a.LocalPolicy)
	}

	// Refusals: recorded as a job event; the same rule folds into one row.
	for _, cmd := range []string{"c1", "c2"} {
		h.svc.ObserveLocalPolicyRefusal(ctx, tid, id, cmd, "refused by local policy: targets.deny: 10.20.5.9 is in 10.20.5.0/24")
	}
	h.svc.ObserveLocalPolicyRefusal(ctx, tid, id, "c3", "scan failed: exit status 2") // not a refusal
	e, ok := h.events(tid, id)[string(sensordom.EventJobRefusedByLocalPolicy)]
	if !ok || e.Category != sensordom.CategoryJobs || e.RepeatCount != 2 || !strings.Contains(e.Summary, "targets.deny") {
		t.Fatalf("refusal event: %+v %v", e, ok)
	}
}

// TestSensorLocalPolicy_FromManifest_DB: a manifest's local_policy is a known
// member (not ignored), stored with its summary, and the live kill switch the
// heartbeat reported is kept.
func TestSensorLocalPolicy_FromManifest_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	id := h.sensor(tid)
	ctx := context.Background()
	digest := "sha256:" + strings.Repeat("ef", 32)

	// A slim report with the kill switch arrives first.
	h.heartbeat(id, sensorapp.SensorHeartbeatData{LocalPolicy: &sensordom.LocalPolicyReport{State: "enforced", Digest: digest, KillSwitch: true}})
	a, err := h.svc.GetSensor(ctx, tid.String(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schema":1,"tools":[],"local_policy":{"state":"enforced","source":"file","digest":"` + digest +
		`","kill_switch":false,"summary":{"targets_allow":4,"targets_deny":1,"allow_private":true,"allow_custom_templates":false,"allow_interactsh":false}}}`)
	res, err := h.svc.RegisterManifest(ctx, a, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range res.Ignored {
		if i.Path == "local_policy" {
			t.Fatalf("local_policy ignored: %+v", res.Ignored)
		}
	}
	a, _ = h.svc.GetSensor(ctx, tid.String(), id.String())
	if a.LocalPolicy == nil || a.LocalPolicy.Summary == nil || a.LocalPolicy.Summary.TargetsAllow != 4 || !a.LocalPolicy.KillSwitch {
		t.Fatalf("manifest report %+v", a.LocalPolicy)
	}
}

// TestSensorManifest_ToolContracts_DB (sdk-go docs/rfcs/sensor-sdk-v2.md): a
// registered manifest keeps each tool's contract, drops an invalid one with
// the reason, and the stored contract is read back only within the sensor's
// tenant: another tenant asking for the same sensor id gets nothing.
func TestSensorManifest_ToolContracts_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	other := h.tenant()
	id := h.sensor(tid)
	ctx := context.Background()
	a, err := h.svc.GetSensor(ctx, tid.String(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	good := `{"api_version":"openctem.io/tool/v1","digest":"sha256:` + strings.Repeat("ab", 32) +
		`","version":"1.0.0","class":"target-scan","tier":"T1","network":"targets","consumes":["domain"],"produces":["finding:vulnerability"]}`
	bad := `{"api_version":"openctem.io/tool/v1","digest":"sha256:short","version":"1","class":"target-scan","tier":"T1","produces":[]}`
	raw := []byte(`{"schema":1,"tools":[` +
		`{"name":"nuclei","kind":"scanner","installed":true,"capabilities":["dast"],"contract":` + good + `},` +
		`{"name":"trivy","kind":"scanner","installed":true,"capabilities":["sca"],"contract":` + bad + `}]}`)
	res, err := h.svc.RegisterManifest(ctx, a, raw)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range res.Ignored {
		if i.Reason == sensordom.IgnoredInvalidContract {
			found = i.Path == "tools[1].contract"
		}
	}
	if !found {
		t.Fatalf("invalid contract not reported as ignored: %+v", res.Ignored)
	}
	v, err := h.svc.CurrentManifest(ctx, tid.String(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	if c := v.Manifest.ToolContract("nuclei"); c == nil || c.Digest != "sha256:"+strings.Repeat("ab", 32) || !c.Declares(sensordom.ProduceFinding, "vulnerability") {
		t.Fatalf("nuclei contract = %+v", c)
	}
	if v.Manifest.ToolContract("trivy") != nil {
		t.Fatal("an invalid contract was stored")
	}
	if _, err := h.svc.CurrentManifest(ctx, other.String(), id.String()); err == nil {
		t.Fatal("another tenant read the sensor's manifest and its contracts")
	}
}
