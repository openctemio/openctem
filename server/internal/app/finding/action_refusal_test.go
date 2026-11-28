package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Approving a CVE group in the verification queue verifies the findings the
// transition engine allows and reports every other one with its refusal
// code. A critical finding with no confirmed retest and no checklist
// completed by another person used to be dropped silently, so the approve
// answered "0 verified" as a success.
func TestBulkVerifyByFilter_ReportsRefusedFindings(t *testing.T) {
	tenantID := shared.NewID()
	critical := fixAppliedFindingOf(t, tenantID, vulnerability.SeverityCritical)
	medium := fixAppliedFindingOf(t, tenantID, vulnerability.SeverityMedium)
	repo := &fixAppliedRepo{list: []*vulnerability.Finding{critical, medium}}
	s := NewFindingActionsService(repo, nil, nil, nil, nil, nil, logger.NewNop())

	res, err := s.BulkVerifyByFilter(context.Background(), tenantID.String(), shared.NewID().String(),
		VerifyByFilterInput{Note: "checked"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 1 || len(repo.written) != 1 || repo.written[0] != medium.ID() {
		t.Fatalf("updated %d written %v, want only the medium finding", res.Updated, repo.written)
	}
	if res.Failed != 1 || len(res.Rows) != 1 || res.Rows[0].FindingID != critical.ID().String() ||
		res.Rows[0].Code != RefusalEvidenceRequired {
		t.Fatalf("rows %+v, want the critical finding refused with %s", res.Rows, RefusalEvidenceRequired)
	}
}

// Nothing allowed: nothing is written and the refusal is still reported.
func TestBulkVerifyByFilter_NothingAllowed(t *testing.T) {
	tenantID := shared.NewID()
	high := fixAppliedFindingOf(t, tenantID, vulnerability.SeverityHigh)
	repo := &fixAppliedRepo{list: []*vulnerability.Finding{high}}
	s := NewFindingActionsService(repo, nil, nil, nil, nil, nil, logger.NewNop())

	res, err := s.BulkVerifyByFilter(context.Background(), tenantID.String(), shared.NewID().String(),
		VerifyByFilterInput{Note: "checked"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 0 || len(repo.written) != 0 {
		t.Fatalf("updated %d written %v, want nothing", res.Updated, repo.written)
	}
	if len(res.Rows) != 1 || res.Rows[0].Code != RefusalChecklistRequired {
		t.Fatalf("rows %+v, want one %s", res.Rows, RefusalChecklistRequired)
	}
}

func TestRefusalCodeOf(t *testing.T) {
	if got := RefusalCodeOf(&ActionRefusal{Code: RefusalLifecycle, err: ErrLifecycleMove}); got != RefusalLifecycle {
		t.Fatalf("code = %s", got)
	}
	if got := RefusalCodeOf(ErrNoteRequired); got != RefusalNotAllowed {
		t.Fatalf("an error without a code = %s, want %s", got, RefusalNotAllowed)
	}
	// The wrapper keeps the error kind for the callers that check it.
	wrapped := &ActionRefusal{Code: RefusalNoteRequired, err: ErrNoteRequired}
	if !errors.Is(wrapped, shared.ErrValidation) {
		t.Fatal("ActionRefusal must unwrap to the engine's error")
	}
	if refusalOfLoad(vulnerability.FindingNotFoundError(shared.NewID())) != RefusalNotFound ||
		refusalOfLoad(errInvalidActionID) != RefusalNotFound {
		t.Fatal("a missing, out-of-scope or malformed finding must read as not_found")
	}
	seen := map[string]bool{}
	for _, c := range RefusalCodes {
		if c == "" || seen[c] {
			t.Fatalf("refusal codes must be unique and non-empty: %q", c)
		}
		seen[c] = true
	}
}
