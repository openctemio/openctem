package retest

import (
	"context"
	"testing"

	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordedFinish struct {
	called, unable, succeeded bool
	code                      string
}

type fakeRuns struct{ got recordedFinish }

func (f *fakeRuns) StartRetestRun(context.Context, *retestdom.Retest) (shared.ID, shared.ID, error) {
	return shared.ID{}, shared.ID{}, nil
}

func (f *fakeRuns) FinishRetestRun(_ context.Context, _, _ shared.ID, succeeded bool, _, code string) error {
	f.got = recordedFinish{called: true, succeeded: succeeded, code: code}
	return nil
}

func (f *fakeRuns) FinishRetestRunUnable(_ context.Context, _, _ shared.ID, _, code string) error {
	f.got = recordedFinish{called: true, unable: true, code: code}
	return nil
}

// A retest whose tool could not run the check blocks its run with its own
// code (never a red failure labeled unreachable); a retest whose target
// could not be reached still fails it, and an answer completes it.
func TestFinishRunToolUnableBlocksTheRun(t *testing.T) {
	runID := shared.NewID()
	cases := []struct {
		name string
		v    retestdom.Verdict
		want recordedFinish
	}{
		{"tool unable", retestdom.Inconclusive(retestdom.ReasonError, "the tool could not run this check"),
			recordedFinish{called: true, unable: true, code: RunCodeToolUnable}},
		{"target unreachable", retestdom.Inconclusive(retestdom.ReasonUnreachable, "no answer"),
			recordedFinish{called: true, code: "UNREACHABLE"}},
		{"answer", retestdom.Verdict{Outcome: retestdom.OutcomeStillVulnerable, Code: retestdom.ReasonMatched, Reason: "matched"},
			recordedFinish{called: true, succeeded: true, code: "MATCHED"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runs := &fakeRuns{}
			s := &Service{runs: runs, logger: logger.NewNop()}
			s.finishRun(context.Background(), &retestdom.Retest{RunID: &runID}, tc.v)
			if runs.got != tc.want {
				t.Fatalf("settled %+v, want %+v", runs.got, tc.want)
			}
		})
	}
}
