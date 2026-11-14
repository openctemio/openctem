package automation

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type countingJira struct{ creates int }

func (j *countingJira) CreateTicketFromFinding(context.Context, string, string, string, string) (TicketRef, error) {
	j.creates++
	return TicketRef{}, nil
}

func (j *countingJira) SyncFindingStatus(context.Context, shared.ID, shared.ID) error { return nil }

type heldOnly map[shared.ID]bool

func (h heldOnly) IsHeld(_ context.Context, _ shared.ID, id shared.ID) (bool, error) {
	return h[id], nil
}

// create_ticket files nothing for a held finding and says why; a finding
// that is not held gets its ticket.
func TestCreateTicket_SkipsHeldFinding(t *testing.T) {
	held, open := shared.NewID(), shared.NewID()
	jira := &countingJira{}
	h := NewTicketActionHandler(nil, jira, nil, logger.NewNop())
	h.SetHeldChecker(heldOnly{held: true})
	in := func(id shared.ID) *ActionInput {
		return &ActionInput{TenantID: shared.NewID(), ActionConfig: map[string]any{"finding_id": id.String(), "project_key": "SEC"}}
	}
	out, err := h.createTicket(context.Background(), in(held))
	if err != nil || out["skipped"] != true || out["reason"] != "finding_held" || jira.creates != 0 {
		t.Fatalf("held: %v %v (creates %d)", out, err, jira.creates)
	}
	if _, err := h.createTicket(context.Background(), in(open)); err != nil || jira.creates != 1 {
		t.Fatalf("open: %v (creates %d)", err, jira.creates)
	}
}
