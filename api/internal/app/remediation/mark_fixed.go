package remediation

// Marking a remediation task fixed: docs/rfcs/RFC-098-remediation-tasks.md §8.
//
// "Mark fixed" is a fix claim on each open finding of the task: every one
// goes to fix_applied through the legal steps of the finding bulk path (a
// note, findings:fix_apply, the person's own findings only, the abuse
// guard), and a proof-of-fix re-check is queued per finding. Nothing closes
// here: each finding closes only on its own evidence, and the task is done
// once every finding is closed and at least one was verified fixed.

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TaskFixClaimer claims the fix of findings: the finding bulk path with the
// legal steps to fix_applied (*finding.VulnerabilityService).
type TaskFixClaimer interface {
	BulkUpdateFindingsStatus(ctx context.Context, tenantID string, in finding.BulkUpdateStatusInput) (*finding.BulkUpdateResult, error)
}

// TaskBulkGuard is the bulk abuse guard (*finding.BulkGuard).
type TaskBulkGuard interface {
	CheckBulk(ctx context.Context, tenantID shared.ID, size int, operatorApproved bool) error
}

// SetFixClaimer wires the finding bulk path and the abuse guard (guard may
// be nil). Without a claimer "mark fixed" is refused.
func (s *TaskService) SetFixClaimer(c TaskFixClaimer, g TaskBulkGuard) {
	s.claimer, s.guard = c, g
}

// MarkFixedInput marks a task's findings fixed.
type MarkFixedInput struct {
	TenantID shared.ID
	TaskID   shared.ID
	Version  int
	Note     string
	ActorID  *shared.ID
	// HasFixApplyPermission: findings:fix_apply (the route requires it too).
	HasFixApplyPermission bool
	// Approved lets an over-ceiling bulk through the abuse guard.
	Approved bool
}

// MarkFixedResult is the outcome per finding, and the task after it.
type MarkFixedResult struct {
	Updated           int
	Skipped           int
	Failed            int
	ValidationsQueued int
	Rows              []finding.BulkRowResult
	Task              *remediationdom.Task
}

// ErrMarkFixedUnavailable: the finding bulk path is not wired.
var ErrMarkFixedUnavailable = fmt.Errorf("%w: marking a task fixed is not available", shared.ErrValidation)

// MarkFixed claims the fix of every open finding of the task.
func (s *TaskService) MarkFixed(ctx context.Context, in MarkFixedInput, actx auditapp.AuditContext) (*MarkFixedResult, error) {
	if s.claimer == nil {
		return nil, ErrMarkFixedUnavailable
	}
	if in.Version <= 0 {
		return nil, ErrTaskVersionRequired
	}
	if !in.HasFixApplyPermission {
		return nil, finding.ErrFixApplyRequiresPermission
	}
	note := strings.TrimSpace(in.Note)
	if note == "" {
		return nil, finding.ErrNoteRequired
	}
	// Every finding of the task must be in the caller's scope: the claim is
	// for the whole task.
	t, err := s.writableTask(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, err
	}
	if t.State.IsTerminal() {
		return nil, remediationdom.ErrTaskTerminal
	}
	if t.Version != in.Version {
		return nil, remediationdom.ErrTaskVersionConflict
	}
	ids, err := s.repo.OpenPrimaryIDs(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, err
	}
	out := &MarkFixedResult{}
	if len(ids) > 0 {
		if s.guard != nil {
			if err := s.guard.CheckBulk(ctx, in.TenantID, len(ids), in.Approved); err != nil {
				return nil, err
			}
		}
		strs := make([]string, len(ids))
		for i, id := range ids {
			strs[i] = id.String()
		}
		actor := ""
		if in.ActorID != nil {
			actor = in.ActorID.String()
		}
		res, err := s.claimer.BulkUpdateFindingsStatus(ctx, in.TenantID.String(), finding.BulkUpdateStatusInput{
			FindingIDs: strs, Status: string(vulnerability.FindingStatusFixApplied), Resolution: note, ActorID: actor,
			HasFixApplyPermission: true, WalkToFixApplied: true,
		})
		if err != nil {
			return nil, err
		}
		out.Updated, out.Skipped, out.Failed, out.ValidationsQueued, out.Rows = res.Updated, res.Skipped, res.Failed, res.ValidationsQueued, res.Rows
	}
	if err := s.repo.RecordFixClaim(ctx, in.TenantID, in.TaskID, in.ActorID, map[string]any{
		"updated": out.Updated, "skipped": out.Skipped, "failed": out.Failed,
		"validations_queued": out.ValidationsQueued, "note": clipNote(note),
	}); err != nil {
		return nil, err
	}
	if out.Task, err = s.repo.GetTask(ctx, in.TenantID, in.TaskID); err != nil {
		return nil, err
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskFixClaimed, auditdom.ResourceTypeRemediationTask, t.ID.String()).
		WithResourceName(t.Title).
		WithMessage(fmt.Sprintf("Remediation task %q marked fixed: %d finding(s) claimed fixed, %d already claimed, %d refused, %d re-check(s) queued",
			t.Title, out.Updated, out.Skipped, out.Failed, out.ValidationsQueued)).
		WithMetadata("updated", out.Updated).WithMetadata("failed", out.Failed).WithMetadata("validations_queued", out.ValidationsQueued)
	if out.Failed > 0 {
		ev = ev.WithSeverity(auditdom.SeverityMedium)
	}
	s.logAudit(ctx, actx, ev)
	return out, nil
}

func clipNote(s string) string {
	if len(s) <= remediationdom.MaxStateNote {
		return s
	}
	n := remediationdom.MaxStateNote
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
