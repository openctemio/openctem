package workflow

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/logger"
)

// Unimplemented action handlers must fail loudly rather than return a false
// success map. A silent no-op makes operators believe findings were routed /
// tickets were filed when nothing happened.
func TestUnimplementedActions_FailLoud(t *testing.T) {
	ctx := context.Background()
	finder := NewFindingActionHandler(nil, logger.NewNop())
	ticketer := NewTicketActionHandler(nil, logger.NewNop())

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
		{"create_ticket", func() (map[string]any, error) {
			return ticketer.createTicket(ctx, &ActionInput{
				ActionConfig: map[string]any{"integration_id": "i1", "title": "x"},
			})
		}},
		{"update_ticket", func() (map[string]any, error) {
			return ticketer.updateTicket(ctx, &ActionInput{
				ActionConfig: map[string]any{"integration_id": "i1", "ticket_id": "t1"},
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

// Config validation still runs first, so a misconfigured node reports the
// precise config problem (not the generic not-implemented error).
func TestUnimplementedActions_ConfigValidatedFirst(t *testing.T) {
	ctx := context.Background()
	ticketer := NewTicketActionHandler(nil, logger.NewNop())
	if _, err := ticketer.createTicket(ctx, &ActionInput{ActionConfig: map[string]any{}}); err == nil ||
		!strings.Contains(err.Error(), "integration_id is required") {
		t.Fatalf("expected integration_id required error, got %v", err)
	}
}
