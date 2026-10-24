package approvalpolicy

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A request an automation made is never decided by one person: not with the
// organization's false-positive level off, not when the owner it acts for
// holds the approve permission (RFC-125 D9). Without the flag the same
// request is single-person, which proves the flag is what refuses it.
func TestEvaluate_AutomationRequestNeverSinglePerson(t *testing.T) {
	requester := shared.NewID()
	for _, kind := range []Kind{KindFalsePositive, KindAccepted} {
		req := Request{Kind: kind, RequesterID: requester, RequesterCanApprove: true, FPLevel: FPLevelOff}
		person := Evaluate(Policy{}, req)
		req.AutomationMade = true
		auto := Evaluate(Policy{}, req)
		if auto.SinglePerson() || auto.Required < 1 {
			t.Fatalf("%s: automation request tier %s required %d, want a second person", kind, auto.Tier, auto.Required)
		}
		if kind == KindFalsePositive && !person.SinglePerson() {
			t.Fatalf("control: a person's false positive at level off is %s, want single", person.Tier)
		}
		found := false
		for _, r := range auto.Reasons {
			found = found || r == ReasonAutomationCannotSelf
		}
		if kind == KindFalsePositive && !found {
			t.Fatalf("%s: reasons %v miss %s", kind, auto.Reasons, ReasonAutomationCannotSelf)
		}
	}
}
