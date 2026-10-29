package retest

// Retest of many findings at once, from a selection of vulnerabilities
// (docs/architecture/vulnerability-page.md, "Bulk actions"). Each finding
// goes through Request, the same path as "Retest now" on one finding: the
// strategy its provenance allows, the per-finding cooldown, the per-asset
// and per-organization in-flight caps and the request audit. The caller
// resolves the findings inside its own data scope; nothing here widens it.

import (
	"context"
	"errors"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxBulkRetest bounds the findings one bulk request tries (most urgent
// first); the organization's in-flight cap usually stops it earlier.
const MaxBulkRetest = 50

// Outcomes of one finding in a bulk retest.
const (
	BulkQueued      = "queued"
	BulkInFlight    = "in_flight"
	BulkRateLimited = "rate_limited"
	BulkNotEligible = "not_eligible"
	BulkNoSensor    = "no_sensor"
	BulkNotFound    = "not_found"
	BulkFailed      = "failed"
)

// BulkInput is a bulk retest request.
type BulkInput struct {
	TenantID    shared.ID
	FindingIDs  []shared.ID
	RequestedBy *shared.ID
	Audit       auditapp.AuditContext
}

// BulkItem is one finding's outcome.
type BulkItem struct {
	FindingID shared.ID
	Outcome   string
	RetestID  *shared.ID
}

// BulkResult counts the outcomes.
type BulkResult struct {
	Items  []BulkItem
	Counts map[string]int
}

// RequestMany queues a manual retest of each finding (at most MaxBulkRetest)
// and reports each outcome; one finding's refusal never stops the others.
func (s *Service) RequestMany(ctx context.Context, in BulkInput) BulkResult {
	ids := in.FindingIDs
	if len(ids) > MaxBulkRetest {
		ids = ids[:MaxBulkRetest]
	}
	res := BulkResult{Items: make([]BulkItem, 0, len(ids)), Counts: map[string]int{}}
	for _, id := range ids {
		item := BulkItem{FindingID: id}
		rt, err := s.Request(ctx, RequestInput{
			TenantID: in.TenantID, FindingID: id, Trigger: retestdom.TriggerManual,
			RequestedBy: in.RequestedBy, Audit: in.Audit,
		})
		item.Outcome = bulkOutcome(err)
		if rt != nil {
			rid := rt.ID
			item.RetestID = &rid
		}
		if item.Outcome == BulkFailed {
			s.logger.Warn("bulk retest of a finding failed", "finding_id", id.String(), "error", err)
		}
		res.Counts[item.Outcome]++
		res.Items = append(res.Items, item)
	}
	return res
}

// bulkOutcome classifies a Request error.
func bulkOutcome(err error) string {
	switch {
	case err == nil:
		return BulkQueued
	case errors.Is(err, retestdom.ErrInFlight):
		return BulkInFlight
	case errors.Is(err, retestdom.ErrRateLimited):
		return BulkRateLimited
	case errors.Is(err, retestdom.ErrNoSensor), errors.Is(err, retestdom.ErrNoCheckSensor):
		return BulkNoSensor
	case errors.Is(err, shared.ErrNotFound):
		return BulkNotFound
	case errors.Is(err, retestdom.ErrNotEligible), errors.Is(err, shared.ErrValidation):
		return BulkNotEligible
	default:
		return BulkFailed
	}
}
