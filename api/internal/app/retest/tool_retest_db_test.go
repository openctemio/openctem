package retest_test

// Tool retest (RFC-039 §12): a finding whose tool has a retest handler on a
// tenant sensor is re-checked by one `retest` command to that tool, and the
// tool's verdict on the finding settles the retest. DB-gated like the rest.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/app/validation"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// toolSensors: a tenant sensor is online whose listed tools have a retest
// handler (and a validate:nuclei sensor too).
type toolSensors map[string]bool

func (toolSensors) HasNucleiValidationSensor(context.Context, shared.ID) (bool, error) {
	return true, nil
}

func (s toolSensors) HasRetestSensor(_ context.Context, _ shared.ID, tool string) (bool, error) {
	return s[tool], nil
}

// finishTool completes a retest command with the verdicts the sensor's kit
// reports (metadata.retest.verdicts), or fails it when verdicts is nil.
func (fx *fixture) finishTool(cmd *shared.ID, verdicts []map[string]string) {
	fx.t.Helper()
	if cmd == nil {
		fx.t.Fatal("retest has no command")
	}
	if verdicts == nil {
		fx.exec(`UPDATE commands SET status = 'failed', error_message = 'retest: this sensor has no tool that retests', completed_at = NOW() WHERE id = $1`, cmd.String())
		return
	}
	res, _ := json.Marshal(map[string]any{"status": "completed", "metadata": map[string]any{
		"retest": map[string]any{"tool": "nuclei", "status": "ok", "verdicts": verdicts}}})
	fx.exec(`UPDATE commands SET status = 'completed', result = $2, completed_at = NOW() WHERE id = $1`, cmd.String(), res)
}

func verdict(ref shared.ID, v string) []map[string]string {
	return []map[string]string{{"ref": ref.String(), "verdict": v, "detail": "checked"}}
}

// One retest command, routed to retest:<tool>, naming the tool as "scanner",
// the finding's own address as the only target, and the finding as the only
// item; no reachability probe is queued.
func TestRetestDB_ToolRetestQueuesOneRetestCommand(t *testing.T) {
	fx := newFixture(t)
	svc := fx.serviceWith(toolSensors{"nuclei": true})
	f := fx.newFinding(fx.asset, "confirmed", "CVE-2024-1234")
	rt := fx.request(svc, f)
	if rt.CheckCommandID == nil || rt.ReachCommandID != nil || rt.Method != retestdom.MethodTool {
		t.Fatalf("retest %+v", rt)
	}
	var typ string
	var raw []byte
	if err := fx.db.QueryRow(`SELECT type, payload FROM commands WHERE tenant_id = $1`, fx.tenant.String()).Scan(&typ, &raw); err != nil {
		t.Fatal(err)
	}
	if n := fx.commandCount(); n != 1 {
		t.Fatalf("%d commands, want 1", n)
	}
	var p validation.RetestCommandPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	// The origin of the matched-at URL https://shop.example.com/admin: the
	// template appends its own path to the input.
	const addr = "https://shop.example.com"
	if typ != "retest" || p.Scanner != "nuclei" || p.RetestID != rt.ID.String() ||
		len(p.Targets) != 1 || p.Targets[0] != addr ||
		len(p.Items) != 1 || p.Items[0].Ref != f.String() || p.Items[0].Target != addr || p.Items[0].Kind != "finding" ||
		p.Items[0].RuleID != "CVE-2024-1234" || p.Items[0].Fingerprint != f.String() ||
		len(p.RequiredCapabilities) != 1 || p.RequiredCapabilities[0] != "retest:nuclei" {
		t.Fatalf("command %s %s", typ, raw)
	}
}

func TestRetestDB_ToolVerdictSettlesTheFinding(t *testing.T) {
	fx := newFixture(t)
	svc := fx.serviceWith(toolSensors{"nuclei": true})
	ctx := context.Background()

	// fixed: an open finding is resolved by the retest.
	open := fx.newFinding(fx.asset, "confirmed", "tpl-open")
	rt := fx.request(svc, open)
	fx.finishTool(rt.CheckCommandID, verdict(open, "fixed"))
	svc.OnCommandFinished(ctx, fx.tenant, *rt.CheckCommandID)
	if st, method, by := fx.findingState(open); st != "resolved" || method != "retest_verified" || by != fx.user.String() {
		t.Fatalf("fixed: status %s method %s by %s", st, method, by)
	}
	if got := fx.retest(rt.ID); got.Outcome != retestdom.OutcomeFixed {
		t.Fatalf("fixed: retest %+v", got)
	}

	// still_present: a resolved finding is reopened (regression).
	resolved := fx.newFinding(fx.newAsset("api.example.com"), "resolved", "tpl-back")
	rt = fx.request(svc, resolved)
	fx.finishTool(rt.CheckCommandID, verdict(resolved, "still_present"))
	svc.OnCommandFinished(ctx, fx.tenant, *rt.CheckCommandID)
	if st, _, _ := fx.findingState(resolved); st != "confirmed" {
		t.Fatalf("still_present: status %s", st)
	}

	// unverifiable, a verdict for another finding, a failed command: unknown,
	// the finding does not move.
	for name, finish := range map[string]func(f shared.ID, rt *retestdom.Retest){
		"unverifiable": func(f shared.ID, rt *retestdom.Retest) { fx.finishTool(rt.CheckCommandID, verdict(f, "unverifiable")) },
		"other finding's ref": func(_ shared.ID, rt *retestdom.Retest) {
			fx.finishTool(rt.CheckCommandID, verdict(shared.NewID(), "fixed"))
		},
		"failed command":       func(_ shared.ID, rt *retestdom.Retest) { fx.finishTool(rt.CheckCommandID, nil) },
		"garbage verdict word": func(f shared.ID, rt *retestdom.Retest) { fx.finishTool(rt.CheckCommandID, verdict(f, "gone")) },
	} {
		f := fx.newFinding(fx.newAsset("h"+strings.ReplaceAll(shared.NewID().String(), "-", "")[20:]+".example.com"), "confirmed", "tpl-"+strings.NewReplacer(" ", "-", "\x27", "").Replace(name))
		rt := fx.request(svc, f)
		finish(f, rt)
		svc.OnCommandFinished(ctx, fx.tenant, *rt.CheckCommandID)
		got := fx.retest(rt.ID)
		if got.Status != retestdom.StatusCompleted || got.Outcome != retestdom.OutcomeUnknown {
			t.Errorf("%s: retest %+v", name, got)
		}
		if st, _, _ := fx.findingState(f); st != "confirmed" {
			t.Errorf("%s: finding moved to %s", name, st)
		}
	}
}

// A finding of a tool other than nuclei is retested only through its tool's
// retest handler, and the tool is the one the command names.
func TestRetestDB_AnyToolWithARetestHandler(t *testing.T) {
	fx := newFixture(t)
	f := fx.newFinding(fx.asset, "confirmed", "weak-tls-cipher")
	fx.exec(`UPDATE findings SET tool_name = 'httpx' WHERE id = $1`, f.String())
	user := fx.user
	in := retestapp.RequestInput{TenantID: fx.tenant, FindingID: f, Trigger: retestdom.TriggerManual, RequestedBy: &user}
	if _, err := fx.serviceWith(toolSensors{"nuclei": true}).Request(context.Background(), in); !errors.Is(err, retestdom.ErrNoSensor) {
		t.Fatalf("no httpx retest sensor: err = %v", err)
	}
	rt, err := fx.serviceWith(toolSensors{"httpx": true}).Request(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := fx.db.QueryRow(`SELECT payload FROM commands WHERE id = $1`, rt.CheckCommandID.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var p validation.RetestCommandPayload
	_ = json.Unmarshal(raw, &p)
	if p.Scanner != "httpx" || p.RequiredCapabilities[0] != "retest:httpx" || p.Items[0].RuleID != "weak-tls-cipher" {
		t.Fatalf("payload %s", raw)
	}
}

// A finding of another tenant is not found, and nothing is queued.
func TestRetestDB_ToolRetestCrossTenantIsNotFound(t *testing.T) {
	fx := newFixture(t)
	other := newFixture(t)
	f := other.newFinding(other.asset, "confirmed", "tpl-other")
	user := fx.user
	_, err := fx.serviceWith(toolSensors{"nuclei": true}).Request(context.Background(), retestapp.RequestInput{
		TenantID: fx.tenant, FindingID: f, Trigger: retestdom.TriggerManual, RequestedBy: &user})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
	if fx.commandCount() != 0 || other.commandCount() != 0 {
		t.Fatal("a command was queued for another tenant's finding")
	}
}
