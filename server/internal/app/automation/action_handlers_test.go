package automation

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

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
