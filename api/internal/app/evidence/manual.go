package evidence

import (
	"context"
	"errors"
	"fmt"

	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// legacyBatch is how many findings one legacy move transaction locks.
const legacyBatch = 50

// ErrDailyCapReached: the tenant stored its daily evidence budget.
var ErrDailyCapReached = fmt.Errorf("%w: the organization reached its daily evidence limit; try again later", shared.ErrValidation)

// StoreManual stores the request/responses a person recorded on a finding (a
// pentest write-up, an import, a drafted finding) as manual evidence: each
// entry is normalized, masked, and its secret values are encrypted apart
// from the item, exactly like tool evidence. Nothing of an entry is kept
// anywhere else. An entry already stored on the finding is skipped. Unlike
// scan evidence, a failure is returned: the person who sent it must know.
func (s *Service) StoreManual(ctx context.Context, tenantID, findingID shared.ID, entries []map[string]any, meta Meta) (int, error) {
	items, err := s.checkManual(ctx, tenantID, entries)
	if err != nil || len(items) == 0 {
		return 0, err
	}
	recs := s.prepare(ctx, tenantID, findingID, nil, evidencedom.OriginManual, items, meta)
	n, err := s.repo.InsertManual(ctx, tenantID, findingID, recs)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// CheckManual runs, without storing anything, the checks StoreManual does
// before it writes (entry count, masked placeholders sent back, the tenant's
// daily evidence budget). A caller that creates the finding first calls it
// before the create, so these refusals happen before the finding row exists
// and a retry cannot duplicate the finding.
func (s *Service) CheckManual(ctx context.Context, tenantID shared.ID, entries []map[string]any) error {
	_, err := s.checkManual(ctx, tenantID, entries)
	return err
}

// checkManual validates the entries and the budget and returns the items to store.
func (s *Service) checkManual(ctx context.Context, tenantID shared.ID, entries []map[string]any) ([]evidencedom.Item, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	if s == nil {
		// Never fall back to keeping the exchange in clear somewhere else.
		return nil, fmt.Errorf("%w: request/response evidence is not available", shared.ErrValidation)
	}
	if len(entries) > evidencedom.MaxManualPerFinding {
		return nil, evidencedom.ErrTooManyManual
	}
	items := make([]evidencedom.Item, 0, len(entries))
	for _, e := range entries {
		if evidencedom.ContainsPlaceholder(e) {
			return nil, evidencedom.ErrMaskedResent
		}
		if it, ok := evidencedom.FromRequestResponse(e); ok {
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		return nil, nil
	}
	budget, ok := s.dailyBudget(ctx, tenantID)
	if !ok {
		return nil, errors.New("evidence budget check failed")
	}
	if budget < len(items) {
		return nil, ErrDailyCapReached
	}
	return items, nil
}

// MoveLegacyRequestResponses moves the request/responses still kept in clear
// in findings.metadata (written before they went through this service) into
// masked, encrypted manual evidence, and removes them from the finding.
// Idempotent and batched (SKIP LOCKED): safe on every start, every
// maintenance tick and across replicas. One finding that cannot be moved is
// skipped and counted (logged without any of its values) and does not stop
// the rest. It returns how many findings it moved.
func (s *Service) MoveLegacyRequestResponses(ctx context.Context) (int, error) {
	moved, skipped := 0, 0
	after := "00000000-0000-0000-0000-000000000000"
	for {
		res, err := s.repo.MoveLegacyRequestResponses(ctx, legacyBatch, after, s.convertLegacy)
		moved += res.Moved
		skipped += res.Skipped
		if err != nil {
			return moved, err
		}
		if res.Moved+res.Skipped == 0 {
			break
		}
		after = res.Last
	}
	if skipped > 0 {
		s.log.Error("legacy request/response move skipped findings it could not move", "skipped", skipped, "moved", moved)
	}
	return moved, nil
}

// convertLegacy builds the masked records of one finding's legacy entries.
// An entry that holds nothing to show is dropped with the rest of the key.
// The per-finding cap of new writes does not apply: nothing already recorded
// is lost (a legacy finding may hold up to 500 entries).
func (s *Service) convertLegacy(ctx context.Context, tenantID, findingID shared.ID, entries []map[string]any) []evidencedom.NewRecord {
	items := make([]evidencedom.Item, 0, len(entries))
	for _, e := range entries {
		if it, ok := evidencedom.FromRequestResponse(e); ok {
			items = append(items, it)
		}
	}
	return s.prepare(ctx, tenantID, findingID, nil, evidencedom.OriginManual, items, Meta{})
}
