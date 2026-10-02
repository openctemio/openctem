package simulation

import (
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// RecordResult used to cast whatever string arrived straight into the entity
// and persist it. Nothing else checked: RecordControlTestResult does
// `simulation.ControlTestStatus(input.Status)` on the raw request field, and
// control_tests has no CHECK constraint on status — unlike compensating_controls,
// which does.
//
// The consequence is quiet. A control recorded as "Pass" or "passed" is stored
// happily and then matches neither `status === 'pass'` nor `'fail'` in the
// Control Testing page's own summary, so it reads as neither passed nor failed —
// a tested control that looks untested.

func TestRecordResult_RejectsUnknownStatus(t *testing.T) {
	bad := []string{
		"Pass",           // capitalised
		"passed",         // near-miss
		"PARTIAL",        //
		"not-applicable", // hyphen instead of underscore
		"",               // empty
		"untested ",      // trailing space
	}

	for _, in := range bad {
		t.Run(in, func(t *testing.T) {
			ct := &ControlTest{status: ControlTestStatusUntested}

			err := ct.RecordResult(ControlTestStatus(in), "evidence", "notes", shared.NewID())
			if err == nil {
				t.Fatalf("status %q was accepted; it will persist and then match none "+
					"of the status filters, so the control reads as neither passed nor "+
					"failed", in)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("error should be a validation error, got %v", err)
			}
			if ct.status != ControlTestStatusUntested {
				t.Errorf("the entity was mutated despite the rejection: status = %q", ct.status)
			}
			if ct.lastTestedAt != nil {
				t.Error("lastTestedAt was set despite the rejection — the control would " +
					"show a test date for a test that was refused")
			}
		})
	}
}

func TestRecordResult_AcceptsEveryKnownStatus(t *testing.T) {
	for _, status := range AllControlTestStatuses() {
		t.Run(string(status), func(t *testing.T) {
			ct := &ControlTest{status: ControlTestStatusUntested}
			tester := shared.NewID()

			if err := ct.RecordResult(status, "evidence", "notes", tester); err != nil {
				t.Fatalf("a status from AllControlTestStatuses was rejected: %v", err)
			}
			if ct.status != status {
				t.Errorf("status = %q, want %q", ct.status, status)
			}
			if ct.lastTestedAt == nil {
				t.Error("lastTestedAt was not set on a successful record")
			}
			if ct.lastTestedBy == nil || *ct.lastTestedBy != tester {
				t.Error("lastTestedBy was not recorded")
			}
		})
	}
}

// The vocabulary must stay closed. A constant added above without being listed
// in AllControlTestStatuses is silently unusable — IsValid would reject it and
// the failure would look like a client bug.
func TestAllControlTestStatuses_CoversEveryConstant(t *testing.T) {
	declared := []ControlTestStatus{
		ControlTestStatusUntested,
		ControlTestStatusPass,
		ControlTestStatusFail,
		ControlTestStatusPartial,
		ControlTestStatusNotApplicable,
	}

	for _, c := range declared {
		if !c.IsValid() {
			t.Errorf("%q is a declared constant but AllControlTestStatuses omits it, "+
				"so RecordResult would reject a value the platform defines", c)
		}
	}
	if got, want := len(AllControlTestStatuses()), len(declared); got != want {
		t.Errorf("AllControlTestStatuses has %d entries, %d constants are declared "+
			"in this test — add the new one to both", got, want)
	}
}
