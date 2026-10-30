package finding

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
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
