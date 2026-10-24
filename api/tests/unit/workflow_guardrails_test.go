package unit

// No automation closes risk (RFC-125 D9): for every action type and every
// finding status, an automation never writes false positive, accepted,
// resolved or duplicate; the request actions only create a request marked as
// an automation's, which no single person may decide.

import (
	"context"
	"errors"
	"testing"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// closingStatuses is every finding status an automation may not set.
func closingStatuses() []string {
	var out []string
	for _, st := range vulnerability.AllFindingStatuses() {
		if !automation.StatusTargetAllowed(string(st)) {
			out = append(out, string(st))
		}
	}
	return out
}

type recordingRequester struct {
	got []finding.RequestApprovalInput
}

func (r *recordingRequester) RequestApproval(_ context.Context, in finding.RequestApprovalInput) (*vulnerability.Approval, error) {
	r.got = append(r.got, in)
	return &vulnerability.Approval{ID: shared.NewID(), Status: vulnerability.ApprovalStatusPending}, nil
}

func TestWorkflowGuardrails_NoActionClosesRisk(t *testing.T) {
	findingID := shared.NewID().String()
	if len(closingStatuses()) < 4 {
		t.Fatalf("closing statuses = %v", closingStatuses())
	}
	for _, a := range automation.ActionTypes() {
		for _, st := range closingStatuses() {
			cfg := automation.NodeConfig{ActionType: a, ActionConfig: map[string]any{"status": st}}
			if a == automation.ActionTypeUpdateStatus {
				err := automation.ValidateStatusTargets(cfg)
				var de *shared.DomainError
				if !errors.As(err, &de) || de.Code != automation.ErrCodeStatusNotAllowed {
					t.Errorf("update_status %s accepted on save (%v)", st, err)
				}
				// A stored node is refused at run time, before any service call.
				h := automationsvc.NewFindingActionHandler(nil, logger.NewNop())
				_, err = h.Execute(context.Background(), &automationsvc.ActionInput{ActionType: a, ActionConfig: map[string]any{"status": st, "finding_id": findingID}})
				if !errors.As(err, &de) || de.Code != automation.ErrCodeStatusNotAllowed {
					t.Errorf("update_status %s ran (%v)", st, err)
				}
			}
		}
	}
	for _, st := range []string{"confirmed", "in_progress"} {
		if err := automation.ValidateStatusTargets(automation.NodeConfig{ActionType: automation.ActionTypeUpdateStatus, ActionConfig: map[string]any{"status": st}}); err != nil {
			t.Errorf("update_status %s refused: %v", st, err)
		}
	}
}

func TestWorkflowGuardrails_RequestActionsOnlyRequest(t *testing.T) {
	rec := &recordingRequester{}
	h := automationsvc.NewRequestActionHandler(rec)
	principal := shared.NewID()
	findingID := shared.NewID().String()
	cases := []struct {
		action automation.ActionType
		cfg    map[string]any
		want   string
	}{
		{automation.ActionTypeRequestFalsePositive, map[string]any{"closure_reason": "code_not_reachable", "justification": "j"}, "false_positive"},
		{automation.ActionTypeRequestRiskAcceptance, map[string]any{"closure_reason": "risk_accepted", "justification": "j", "expires_in_days": float64(30)}, "accepted"},
	}
	for _, c := range cases {
		c.cfg["finding_id"] = findingID
		out, err := h.Execute(context.Background(), &automationsvc.ActionInput{
			TenantID: shared.NewID(), ActionType: c.action, ActionConfig: c.cfg, Principal: principal,
		})
		if err != nil || out["requested"] != true {
			t.Fatalf("%s: %v %v", c.action, out, err)
		}
	}
	if len(rec.got) != 2 {
		t.Fatalf("requests = %d", len(rec.got))
	}
	for i, in := range rec.got {
		if !in.ByAutomation || in.CanApprove || in.RequestedStatus != cases[i].want || in.RequestedBy != principal.String() {
			t.Errorf("request %d = %+v: must be an automation's request that its owner cannot decide alone", i, in)
		}
	}
	if rec.got[1].ExpiresAt == nil {
		t.Error("a risk acceptance request without an end")
	}
	// Without a reason, a note or an end the action refuses.
	for _, cfg := range []map[string]any{
		{"justification": "j"},
		{"closure_reason": "risk_accepted", "justification": "j", "expires_in_days": float64(400)},
	} {
		cfg["finding_id"] = findingID
		action := automation.ActionTypeRequestFalsePositive
		if _, ok := cfg["expires_in_days"]; ok {
			action = automation.ActionTypeRequestRiskAcceptance
		}
		if _, err := h.Execute(context.Background(), &automationsvc.ActionInput{TenantID: shared.NewID(), ActionType: action, ActionConfig: cfg, Principal: principal}); err == nil {
			t.Errorf("%s with %v ran", action, cfg)
		}
	}
	if automation.ActionRisk(automation.ActionTypeRequestFalsePositive) != automation.RiskHigh ||
		automation.ActionRisk(automation.ActionTypeRequestRiskAcceptance) != automation.RiskHigh {
		t.Error("request actions must be high risk")
	}
}

// A change cap above the default makes an automation high risk.
func TestWorkflowGuardrails_RaisedCapIsHighRisk(t *testing.T) {
	d := automation.Definition{Nodes: []automation.DefinitionNode{{NodeKey: "a", Config: automation.NodeConfig{ActionType: automation.ActionTypeAddTags}}}}
	if d.Risk() != automation.RiskLow {
		t.Fatalf("tags = %s", d.Risk())
	}
	d.MaxChangesPerRun = automation.DefaultMaxChangesPerRun + 1
	if d.Risk() != automation.RiskHigh {
		t.Fatalf("raised cap = %s, want high", d.Risk())
	}
	if automation.ValidateMaxChanges(1001) == nil || automation.ValidateMaxChanges(1000) != nil {
		t.Fatal("cap bounds")
	}
}

// Case and whitespace variants of a status are not the allowed target: the
// allow-list matches exactly, on save and when a stored step runs.
func TestUpdateStatusAllowList_Variants(t *testing.T) {
	for _, v := range []string{"Resolved", "RESOLVED", " resolved", "resolved ", "false_positive\n", "Confirmed", " confirmed", "IN_PROGRESS", "in-progress"} {
		cfg := automation.NodeConfig{ActionType: automation.ActionTypeUpdateStatus, ActionConfig: map[string]any{"status": v}}
		if err := automation.ValidateStatusTargets(cfg); err == nil {
			t.Errorf("status %q accepted on save", v)
		}
		if automation.StatusTargetAllowed(v) {
			t.Errorf("status %q allowed at run time", v)
		}
	}
}
