package finding

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Only a verified Jira/GitHub ticket move is the ticket actor (work state
// only). Another integration (VEX, coverage) carrying actor type
// "integration" is not, and the flag ignores any other source.
func TestTicketInboundActorIsDedicated(t *testing.T) {
	kind := func(ctx context.Context) vulnerability.TransitionActorKind {
		return transitionActor(ctx, "", TransitionPermissions{FixApply: true}).Kind
	}
	vex := vulnerability.WithStatusTransition(context.Background(), vulnerability.StatusTransition{
		Source: "vex", ActorType: IntegrationActorType,
	})
	if k := kind(vex); k != vulnerability.TransitionActorAPIKey {
		t.Errorf("a VEX integration move is %q, want api_key (no person, no exemption)", k)
	}
	if k := kind(vulnerability.WithTicketInbound(vex, "vex")); k != vulnerability.TransitionActorAPIKey {
		t.Errorf("an unknown ticket source is %q", k)
	}
	jira := vulnerability.WithTicketInbound(context.Background(), "jira")
	if k := kind(jira); k != vulnerability.TransitionActorTicket {
		t.Fatalf("a verified Jira move is %q, want ticket_inbound", k)
	}
	a := transitionActor(jira, "", TransitionPermissions{})
	for _, to := range []vulnerability.FindingStatus{vulnerability.FindingStatusFixApplied, vulnerability.FindingStatusInProgress} {
		if d := vulnerability.EvaluateTransitionRequest(a, to); !d.Allowed {
			t.Errorf("a ticket may report %s: %+v", to, d)
		}
	}
	for _, to := range []vulnerability.FindingStatus{vulnerability.FindingStatusResolved, vulnerability.FindingStatusFalsePositive} {
		if d := vulnerability.EvaluateTransitionRequest(a, to); d.Allowed {
			t.Errorf("a ticket closed a finding: %s", to)
		}
	}
}

func TestTicketTransitionRecordsTheExternalAccount(t *testing.T) {
	tr := TicketTransition("jira", "SEC-1", "acct-42")
	if tr.ActorName != "jira:acct-42" || tr.Changes["jira_account_id"] != "acct-42" || tr.Changes["ticket"] != "SEC-1" {
		t.Fatalf("transition = %+v", tr)
	}
}
