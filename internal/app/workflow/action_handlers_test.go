package workflow

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/logger"
)

// Still-unimplemented finding action handlers must fail loudly rather than
// return a false success map. (assign_team / update_priority are separate,
// tracked gaps — the ticket actions ARE now implemented, see ticket tests.)
func TestUnimplementedActions_FailLoud(t *testing.T) {
	ctx := context.Background()
	finder := NewFindingActionHandler(nil, logger.NewNop())

	cases := []struct {
		name string
		run  func() (map[string]any, error)
	}{
		{"assign_team", func() (map[string]any, error) {
			return finder.assignTeam(ctx, &ActionInput{
				ActionConfig: map[string]any{"finding_id": "f1", "team_id": "t1"},
			})
		}},
		{"update_priority", func() (map[string]any, error) {
			return finder.updatePriority(ctx, &ActionInput{
				ActionConfig: map[string]any{"finding_id": "f1", "priority": "high"},
			})
		}},
	}

	for _, tc := range cases {
		res, err := tc.run()
		if err == nil {
			t.Errorf("%s: expected a not-implemented error, got nil (result=%v)", tc.name, res)
			continue
		}
		if res != nil {
			t.Errorf("%s: expected nil result alongside the error, got %v", tc.name, res)
		}
		if !strings.Contains(err.Error(), "not implemented") {
			t.Errorf("%s: expected 'not implemented' error, got %q", tc.name, err.Error())
		}
	}
}

// A ticket action with no configured provider service must fail loudly ("not
// configured"), never a false {"created": true}.
func TestTicketAction_NoProvider_FailsLoud(t *testing.T) {
	ctx := context.Background()
	ticketer := NewTicketActionHandler(nil, nil, nil, logger.NewNop())
	_, err := ticketer.createTicket(ctx, &ActionInput{ActionConfig: map[string]any{"finding_id": "f1"}})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected 'not configured' error, got %v", err)
	}
}

// The target finding must be resolvable from config or trigger data before any
// provider call.
func TestTicketAction_MissingFindingID(t *testing.T) {
	ctx := context.Background()
	ticketer := NewTicketActionHandler(nil, nil, nil, logger.NewNop())
	if _, err := ticketer.createTicket(ctx, &ActionInput{ActionConfig: map[string]any{}}); err == nil ||
		!strings.Contains(err.Error(), "finding_id not found") {
		t.Fatalf("expected finding_id-not-found error, got %v", err)
	}
}
