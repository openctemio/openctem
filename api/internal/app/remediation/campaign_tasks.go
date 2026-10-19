package remediation

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CampaignTasks is what a remediation campaign asks of its tasks
// (exposure.CampaignTasks): the caller's write check, deadline re-derivation
// after a campaign change, the live tasks of a campaign, and the inbound
// epic's fix claim.
type CampaignTasks struct{ s *TaskService }

// CampaignTasks returns the campaign view of the task service.
func (s *TaskService) CampaignTasks() CampaignTasks { return CampaignTasks{s: s} }

// CheckTaskWritable refuses a task the caller may not change.
func (c CampaignTasks) CheckTaskWritable(ctx context.Context, tenantID, taskID shared.ID) error {
	_, err := c.s.writableTask(ctx, tenantID, taskID)
	return err
}

// RecomputeTasks re-derives the tasks' state, deadline and counters.
func (c CampaignTasks) RecomputeTasks(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID) error {
	return c.s.repo.Recompute(ctx, tenantID, taskIDs, nil)
}

// CampaignTaskIDs lists the campaign's live tasks.
func (c CampaignTasks) CampaignTaskIDs(ctx context.Context, tenantID, campaignID shared.ID) ([]shared.ID, error) {
	return c.s.repo.LiveTaskIDsByCampaign(ctx, tenantID, campaignID)
}

// ClaimTaskFixed marks a task fixed as the platform (the campaign's epic
// moved to done): each open finding gets a fix claim it then verifies on its
// own. A task with nothing left to claim is no refusal.
func (c CampaignTasks) ClaimTaskFixed(ctx context.Context, tenantID, taskID shared.ID, note string) ([]string, error) {
	t, err := c.s.repo.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}
	res, err := c.s.MarkFixed(ctx, MarkFixedInput{
		TenantID: tenantID, TaskID: taskID, Version: t.Version, Note: note, HasFixApplyPermission: true,
	}, auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: "system"})
	if errors.Is(err, remediationdom.ErrTaskTerminal) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var refusals []string
	for _, r := range res.Rows {
		if r.Outcome == "failed" {
			refusals = append(refusals, fmt.Sprintf("%s: %s", r.FindingID, r.Reason))
		}
	}
	return refusals, nil
}
