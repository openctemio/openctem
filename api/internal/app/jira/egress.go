package jira

// The Jira side of the outbound gate (internal/app/ticketing/egress.go;
// docs/architecture/ticketing-integration.md, "Outbound gate").

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// SetEgressGate wires the outbound gate. Without one, pentest content is
// refused on every route.
func (s *SyncService) SetEgressGate(g *ticketing.EgressGate) { s.egress = g }

// CheckFindingEgress asks the gate whether the finding's content may go to a
// tracker on route (callers outside this package, such as the workflow
// update_ticket action, check before a push).
func (s *SyncService) CheckFindingEgress(ctx context.Context, tenantID, findingID shared.ID, route ticketing.Route) error {
	f, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("get finding: %w", err)
	}
	return s.egress.Check(ctx, tenantID, route, f)
}

// egressAllowed is the gate for a background push: a refusal is logged and
// skipped (ok false, nil error: retrying cannot change it), a read error is
// returned so the push is retried.
func (s *SyncService) egressAllowed(ctx context.Context, tenantID shared.ID, route ticketing.Route, findings ...*vulnerability.Finding) (bool, error) {
	err := s.egress.Check(ctx, tenantID, route, findings...)
	if err == nil {
		return true, nil
	}
	var refused *ticketing.EgressRefusedError
	if errors.As(err, &refused) {
		s.logger.Info("ticket push skipped by the outbound gate", "tenant_id", tenantID.String(), "route", string(route), "reason", string(refused.Reason))
		return false, nil
	}
	return false, err
}

// statusPushAllowed applies the gate to a finding's status push. A finding
// that cannot be read is left to the push itself to report.
func (s *SyncService) statusPushAllowed(ctx context.Context, tenantID, findingID shared.ID) (bool, error) {
	f, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return true, nil //nolint:nilerr // the push reads the finding again and reports the error
	}
	return s.egressAllowed(ctx, tenantID, ticketing.RouteStatusSync, f)
}

// taskEgressMembers loads every member of a task (primary and related, any
// status) for the gate: the issue carries the task, so every finding behind
// it counts.
func (s *SyncService) taskEgressMembers(ctx context.Context, tenantID, taskID shared.ID) ([]*vulnerability.Finding, error) {
	if s.taskReader == nil {
		return nil, nil
	}
	ids, err := s.taskReader.EgressMemberIDs(ctx, tenantID, taskID)
	if err != nil {
		return nil, fmt.Errorf("list the task's findings: %w", err)
	}
	out := make([]*vulnerability.Finding, 0, len(ids))
	for start := 0; start < len(ids); start += egressBatch {
		end := min(start+egressBatch, len(ids))
		fs, err := s.findingRepo.GetByIDs(ctx, tenantID, ids[start:end])
		if err != nil {
			return nil, fmt.Errorf("load the task's findings: %w", err)
		}
		out = append(out, fs...)
	}
	return out, nil
}

// egressBatch bounds one finding read of the task gate.
const egressBatch = 500
