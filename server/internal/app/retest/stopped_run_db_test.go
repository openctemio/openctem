package retest_test

import (
	"context"
	"encoding/json"
	"testing"

	retestdom "github.com/openctemio/openctem/server/pkg/domain/retest"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// finishStopped completes a command with the legacy shape of a killed run:
// status "completed" and a non-zero exit code, with metadata that would
// otherwise prove a fix.
func (fx *fixture) finishStopped(cmd *shared.ID, exitCode int, metadata map[string]any) {
	fx.t.Helper()
	res, _ := json.Marshal(map[string]any{"status": "completed", "exit_code": exitCode, "metadata": metadata})
	fx.exec(`UPDATE commands SET status = 'completed', result = $2, completed_at = NOW() WHERE id = $1`, cmd.String(), res)
}

// A stopped re-run never closes a finding, even with auto-resolve on and
// evidence that the endpoint answered 404 (research/467 F6). The validate
// method's per-request path decides before the attempt path, so it is
// covered too.
func TestRetestDB_StoppedRunNeverClosesAFinding(t *testing.T) {
	const at = "https://shop.example.com/admin"
	for _, exitCode := range []int{-1, 1} {
		t.Run("validate", func(t *testing.T) {
			fx := newFixture(t)
			svc := fx.service()
			fx.autoResolve(true)
			f := fx.newFinding(fx.asset, "confirmed", "exposed-admin-panel")
			rt := fx.request(svc, f)
			fx.finishStopped(rt.CheckCommandID, exitCode, map[string]any{"outcome": "not_detected", "summary": "re-run",
				"evidence": map[string]any{"evidence_items": attemptItems(at, 404),
					"requests": []map[string]any{{"url": at, "status": 404}}}})
			fx.finish(rt.ReachCommandID, "detected", "target answered")
			svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)
			got := fx.retest(rt.ID)
			if got.Outcome != retestdom.OutcomeInconclusive {
				t.Fatalf("exit %d: retest = %s (%s), want inconclusive", exitCode, got.Outcome, got.Reason)
			}
			if st, _, _ := fx.findingState(f); st != "confirmed" {
				t.Fatalf("exit %d: a stopped re-run moved the finding to %s", exitCode, st)
			}
		})
		t.Run("tool", func(t *testing.T) {
			fx := newFixture(t)
			svc := fx.serviceWith(toolSensors{"nuclei": true})
			fx.autoResolve(true)
			f := fx.newFinding(fx.newAsset("open.example.com"), "confirmed", "tpl-open")
			fx.exec(`UPDATE findings SET file_path = 'https://open.example.com/admin' WHERE id = $1`, f.String())
			rt := fx.request(svc, f)
			fx.finishStopped(rt.CheckCommandID, exitCode, map[string]any{"retest": map[string]any{"tool": "nuclei", "status": "ok",
				"verdicts": verdictWithAttempt(f, "fixed", "https://open.example.com/admin", 404)}})
			svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)
			got := fx.retest(rt.ID)
			if got.Outcome != retestdom.OutcomeInconclusive {
				t.Fatalf("exit %d: retest = %s (%s), want inconclusive", exitCode, got.Outcome, got.Reason)
			}
			if st, _, _ := fx.findingState(f); st != "confirmed" {
				t.Fatalf("exit %d: a stopped tool retest moved the finding to %s", exitCode, st)
			}
		})
	}
}
