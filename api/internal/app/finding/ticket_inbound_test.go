package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Only a verified Jira/GitHub ticket move is exempt from the person-only
// fix-claim rules. Another integration (VEX, coverage) carrying actor type
// "integration" is not, and the flag ignores any other source.
func TestTicketInboundExemptionIsDedicated(t *testing.T) {
	s := &VulnerabilityService{}
	claim := func(ctx context.Context) error {
		return s.authorizePersonClaimOrClose(ctx, vulnerability.FindingStatusFixApplied,
			vulnerability.ResolutionMethodAdminDirect, "fixed", "", true, nil)
	}
	vex := vulnerability.WithStatusTransition(context.Background(), vulnerability.StatusTransition{
		Source: "vex", ActorType: IntegrationActorType,
	})
	if err := claim(vex); !errors.Is(err, ErrFixApplyNotAPerson) {
		t.Errorf("a VEX integration move claimed a fix: err = %v, want ErrFixApplyNotAPerson", err)
	}
	if err := claim(vulnerability.WithTicketInbound(vex, "vex")); !errors.Is(err, ErrFixApplyNotAPerson) {
		t.Errorf("an unknown ticket source was exempt: err = %v", err)
	}
	if err := claim(vulnerability.WithTicketInbound(context.Background(), "jira")); err != nil {
		t.Errorf("a verified Jira move was refused: %v", err)
	}
}

func TestTicketTransitionRecordsTheExternalAccount(t *testing.T) {
	tr := TicketTransition("jira", "SEC-1", "acct-42")
	if tr.ActorName != "jira:acct-42" || tr.Changes["jira_account_id"] != "acct-42" || tr.Changes["ticket"] != "SEC-1" {
		t.Fatalf("transition = %+v", tr)
	}
}
