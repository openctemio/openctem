package retest_test

// Template digest drift (research/18 O6, sensor#134): a retest counts only
// when it re-ran the template content the finding was last seen with.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// finishWithDigest completes a template re-run with its evidence digest
// ("" leaves it out, as an older sensor does).
func (fx *fixture) finishWithDigest(cmd *shared.ID, outcome, digest string) {
	fx.t.Helper()
	ev := map[string]any{"address": "https://shop.example.com/admin", "evidence_items": attemptItems("https://shop.example.com/admin", 404)}
	if digest != "" {
		ev["template_digest"] = digest
	}
	res, _ := json.Marshal(map[string]any{"metadata": map[string]any{"outcome": outcome, "summary": "re-run", "evidence": ev}})
	fx.exec(`UPDATE commands SET status = 'completed', result = $2, completed_at = NOW() WHERE id = $1`, cmd.String(), res)
}

func (fx *fixture) baseline(finding shared.ID, digest string) {
	fx.exec(`UPDATE findings SET template_digest = $2, template_seen_at = NOW() WHERE id = $1`, finding.String(), digest)
}

func (fx *fixture) settle(finding shared.ID, digest, outcome string) *retestdom.Retest {
	fx.t.Helper()
	svc := fx.service()
	rt := fx.request(svc, finding)
	fx.finishWithDigest(rt.CheckCommandID, outcome, digest)
	fx.finish(rt.ReachCommandID, "detected", "target answered")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)
	return fx.retest(rt.ID)
}

func TestRetestDB_TemplateDigestDriftIsInconclusive(t *testing.T) {
	cases := []struct {
		name        string
		retestRan   string
		outcome     string
		wantOutcome retestdom.Outcome
		wantStatus  string
		wantReason  string
	}{
		{"same digest, no match: confirmed fixed", digestA, "not_detected", retestdom.OutcomeConfirmedFixed, "validated_fixed", ""},
		{"other digest, no match: inconclusive", digestB, "not_detected", retestdom.OutcomeInconclusive, "confirmed", "template changed"},
		{"no digest reported: inconclusive", "", "not_detected", retestdom.OutcomeInconclusive, "confirmed", "no template digest"},
		{"garbage digest counts as none", "md5:abc", "not_detected", retestdom.OutcomeInconclusive, "confirmed", "no template digest"},
		{"other digest, match: inconclusive too", digestB, "detected", retestdom.OutcomeInconclusive, "confirmed", "template changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			f := fx.newFinding(fx.asset, "confirmed", "exposed-admin-panel")
			fx.baseline(f, digestA)
			got := fx.settle(f, tc.retestRan, tc.outcome)
			if got.Outcome != tc.wantOutcome {
				t.Fatalf("outcome = %s (%s), want %s", got.Outcome, got.Reason, tc.wantOutcome)
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("reason %q does not say %q", got.Reason, tc.wantReason)
			}
			if status, _, _ := fx.findingState(f); status != tc.wantStatus {
				t.Errorf("finding status = %s, want %s", status, tc.wantStatus)
			}
		})
	}
}

// A finding without a recorded baseline (seen before provenance existed)
// is decided as before; a new sighting re-baselines it.
func TestRetestDB_NoBaselineDecidesAsBefore(t *testing.T) {
	fx := newFixture(t)
	f := fx.newFinding(fx.asset, "confirmed", "exposed-admin-panel")
	if got := fx.settle(f, "", "not_detected"); got.Outcome != retestdom.OutcomeConfirmedFixed {
		t.Fatalf("no baseline: %s (%s), want fixed", got.Outcome, got.Reason)
	}

	// Re-baselined to B by a new sighting: a re-run on B is conclusive.
	g := fx.newFinding(fx.asset, "confirmed", "exposed-admin-panel-2")
	fx.baseline(g, digestA)
	fx.baseline(g, digestB)
	if got := fx.settle(g, digestB, "not_detected"); got.Outcome != retestdom.OutcomeConfirmedFixed {
		t.Fatalf("re-baselined: %s (%s), want fixed", got.Outcome, got.Reason)
	}
}
