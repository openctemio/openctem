package finding

import (
	"context"
	"errors"
	"strings"
	"testing"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestParseProposalIDs(t *testing.T) {
	a, b := shared.NewID().String(), shared.NewID().String()
	got, err := parseProposalIDs([]string{a, b, a})
	if err != nil || len(got) != 2 {
		t.Fatalf("dedupe = %v, %v", got, err)
	}
	tooMany := make([]string, vulnerability.MaxClosureDecisionBatch+1)
	for i := range tooMany {
		tooMany[i] = shared.NewID().String()
	}
	for name, in := range map[string][]string{"empty": nil, "bad id": {"x"}, "zero": {shared.ID{}.String()}, "over cap": tooMany} {
		if _, err := parseProposalIDs(in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want validation", name, err)
		}
	}
}

func TestDecideClosureProposals_Validation(t *testing.T) {
	// Not wired: the store is unavailable, never a silent success.
	s := &VulnerabilityService{}
	if _, err := s.DecideClosureProposals(context.Background(), DecideClosureInput{}); !errors.Is(err, ErrClosureReviewUnavailable) {
		t.Fatalf("unwired = %v", err)
	}
	if _, err := vulnerability.ParseClosureDismissReason("other", " "); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("other without a note must be refused")
	}
	if _, err := vulnerability.ParseClosureDismissReason("seen_again", ""); err == nil {
		t.Fatal("a system reason is not a person's dismissal reason")
	}
	if _, err := cleanClosureNote(strings.Repeat("é", vulnerability.MaxClosureNoteLen+1)); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("an over-long note must be refused")
	}
}

// The audit row names every finding and proposal the request moved (up to the
// 200 batch cap), plus the methods.
func TestAuditClosureDecision_ListsAllIDs(t *testing.T) {
	aud := &captureAudit{}
	s := &VulnerabilityService{logger: logger.NewNop()}
	s.SetAuditService(aud)
	res := vulnerability.ClosureDecisionResult{Methods: []string{"covered_scan"}}
	for i := 0; i < vulnerability.MaxClosureDecisionBatch; i++ {
		res.Applied = append(res.Applied, shared.NewID())
		res.Findings = append(res.Findings, shared.NewID())
	}
	s.auditClosureDecision(context.Background(), shared.NewID(), DecideClosureInput{Decision: ClosureDecisionConfirm}, auditdom.ActionFindingClosureConfirmed, "m", res)
	if len(aud.events) != 1 {
		t.Fatalf("events = %d", len(aud.events))
	}
	md := aud.events[0].Metadata
	if ids, _ := md["finding_ids"].([]string); len(ids) != 200 {
		t.Fatalf("finding_ids = %v", md["finding_ids"])
	}
	if ids, _ := md["proposal_ids"].([]string); len(ids) != 200 {
		t.Fatalf("proposal_ids = %v", md["proposal_ids"])
	}
	if m, _ := md["methods"].([]string); len(m) != 1 || m[0] != "covered_scan" {
		t.Fatalf("methods = %v", md["methods"])
	}
}
