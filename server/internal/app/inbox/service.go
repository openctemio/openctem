// Package inbox counts the signed-in person's Inbox queues in one call
// (docs/architecture/my-work.md, "Inbox summary").
//
// It computes no predicate of its own: every queue is counted by the service
// behind the list it opens, with that list's own filter, so a count is the
// total of that list for the same caller (tenant, data scope, pentest
// visibility). A queue the caller has no permission or module for is left
// out, never reported as 0.
package inbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ErrNoPerson is returned for a caller with no user (an organization API key,
// a platform caller): the Inbox is a person's own.
var ErrNoPerson = fmt.Errorf("%w: the inbox needs a signed-in person", shared.ErrValidation)

// FindingCounter counts the finding, approval and closure queues
// (*finding.VulnerabilityService).
type FindingCounter interface {
	IncludeInformational(ctx context.Context, tenantID string, memberChoice *bool) bool
	CountQuickViewsOf(ctx context.Context, c finding.FilterCaller, includeInformational bool, keys []string) ([]finding.QuickViewCount, error)
	CountApprovalQueues(ctx context.Context, in finding.ApprovalQueueInput) (map[vulnerability.ApprovalQueue]int64, error)
	CountClosureProposals(ctx context.Context, tenantID string) (int, error)
}

// TaskCounter counts the remediation task list (*remediation.TaskService).
type TaskCounter interface {
	CountTasks(ctx context.Context, in remediationapp.ListTasksInput) (int64, error)
}

// ModuleReader says whether a module's data may be read for a tenant
// (*middleware.ModuleGate).
type ModuleReader interface {
	IsReadable(ctx context.Context, tenantID, moduleID string) bool
}

// Caller is the authenticated person the summary is for. Every field comes
// from the request's authenticated context, never from its query or body.
type Caller struct {
	TenantID string
	UserID   string
	IsAdmin  bool
	// APIKey: a delegated credential, read on its holder's own scope rows.
	APIKey bool
	// Has reports whether the caller holds a permission (administrators
	// hold every one).
	Has func(permission string) bool
	// InformationalChoice is the person's own findings work-view choice
	// (nil: the organization's default).
	InformationalChoice *bool
}

// Queues holds one count per queue; nil means the queue is not the caller's
// (no permission or module) and is left out of the response.
type Queues struct {
	Assigned     *int64
	Team         *int64
	DueSoon      *int64
	Review       *int64
	Requested    *int64
	Expiring     *int64
	Tasks        *int64
	ReadyToClose *int64
}

// Summary is the caller's Inbox: the queues and the Inbox total.
type Summary struct {
	Queues Queues
	// Total is assigned + review + requested + expiring + tasks +
	// ready_to_close, over the queues present. My team and Due soon are not
	// in it: My team is other people's work and Due soon is a part of
	// Assigned to me.
	Total int64
}

// Service builds the summary.
type Service struct {
	findings FindingCounter
	tasks    TaskCounter
	modules  ModuleReader
}

// NewService builds the service. tasks and modules may be nil: without a
// task counter the tasks queue is left out; without a module reader every
// module counts as on (the module gate is a product switch, not the
// authorization boundary).
func NewService(findings FindingCounter, tasks TaskCounter, modules ModuleReader) *Service {
	return &Service{findings: findings, tasks: tasks, modules: modules}
}

// The quick views behind the finding queues.
var findingQueueViews = []string{ //nolint:gochecknoglobals // fixed table
	vulnerability.QuickViewMyQueue, vulnerability.QuickViewMyTeam,
	vulnerability.QuickViewMyDueSoon, vulnerability.QuickViewMyAcceptedExpiring,
}

// Summary counts the caller's queues. Each queue needs what its list route
// needs, plus the permission to act on it where the queue is a decision:
//
//   - assigned, team, due_soon, expiring, requested: findings:read;
//   - review: findings:read and findings:approve;
//   - ready_to_close: findings:read and findings:verify;
//   - tasks: findings:remediation:read and the remediation module.
func (s *Service) Summary(ctx context.Context, c Caller) (*Summary, error) {
	if c.UserID == "" {
		return nil, ErrNoPerson
	}
	if _, err := shared.IDFromString(c.UserID); err != nil {
		return nil, ErrNoPerson
	}
	if _, err := shared.IDFromString(c.TenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	has := c.Has
	if has == nil {
		has = func(string) bool { return false }
	}
	var q Queues
	if has(permission.FindingsRead.String()) {
		if err := s.countFindingQueues(ctx, c, has, &q); err != nil {
			return nil, err
		}
	}
	if s.tasks != nil && has(permission.RemediationRead.String()) && s.moduleOn(ctx, c.TenantID, moduledom.ModuleRemediation) {
		tid, _ := shared.IDFromString(c.TenantID)
		uid, _ := shared.IDFromString(c.UserID)
		n, err := s.tasks.CountTasks(ctx, remediationapp.ListTasksInput{
			TenantID: tid, CallerID: &uid, Mine: true,
			Filter: remediationdom.TaskFilter{States: remediationdom.OpenTaskStates()},
		})
		if err != nil {
			return nil, fmt.Errorf("count tasks: %w", err)
		}
		q.Tasks = &n
	}
	sum := &Summary{Queues: q}
	for _, n := range []*int64{q.Assigned, q.Review, q.Requested, q.Expiring, q.Tasks, q.ReadyToClose} {
		if n != nil {
			sum.Total += *n
		}
	}
	return sum, nil
}

func (s *Service) countFindingQueues(ctx context.Context, c Caller, has func(string) bool, q *Queues) error {
	if s.findings == nil {
		return errors.New("inbox finding counter not configured")
	}
	include := s.findings.IncludeInformational(ctx, c.TenantID, c.InformationalChoice)
	views, err := s.findings.CountQuickViewsOf(ctx, finding.FilterCaller{
		TenantID: c.TenantID, UserID: c.UserID, IsAdmin: c.IsAdmin, APIKey: c.APIKey, Has: has,
	}, include, findingQueueViews)
	if err != nil {
		return fmt.Errorf("count finding queues: %w", err)
	}
	for _, v := range views {
		n := v.Count
		switch v.Key {
		case vulnerability.QuickViewMyQueue:
			q.Assigned = &n
		case vulnerability.QuickViewMyTeam:
			q.Team = &n
		case vulnerability.QuickViewMyDueSoon:
			q.DueSoon = &n
		case vulnerability.QuickViewMyAcceptedExpiring:
			q.Expiring = &n
		}
	}

	canApprove := has(permission.FindingsApprove.String())
	queues, err := s.findings.CountApprovalQueues(ctx, finding.ApprovalQueueInput{
		TenantID: c.TenantID, CallerID: c.UserID, CanApprove: canApprove,
	})
	if err != nil {
		return fmt.Errorf("count approval queues: %w", err)
	}
	requested := queues[vulnerability.ApprovalQueueRequested]
	q.Requested = &requested
	if canApprove {
		review := queues[vulnerability.ApprovalQueueReview]
		q.Review = &review
	}

	if has(permission.FindingsVerify.String()) {
		n, err := s.findings.CountClosureProposals(ctx, c.TenantID)
		if err != nil {
			return fmt.Errorf("count closure proposals: %w", err)
		}
		ready := int64(n)
		q.ReadyToClose = &ready
	}
	return nil
}

func (s *Service) moduleOn(ctx context.Context, tenantID, moduleID string) bool {
	if s.modules == nil {
		return true
	}
	return s.modules.IsReadable(ctx, tenantID, moduleID)
}
