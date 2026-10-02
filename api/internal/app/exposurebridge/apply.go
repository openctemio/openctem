package exposurebridge

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/logger"
)

// upsertExposureEvent upserts a single prebuilt exposure event into the store,
// mirroring the credential-import dedupe/reactivate semantics: a re-scan finding
// the same exposure updates last_seen (reactivating a resolved one) instead of
// creating a duplicate. reactivateNote is recorded on the state-history entry
// when a resolved exposure is reactivated (e.g. "finding: <id>" or
// "asset: <id>") so the discovery channel that resurfaced it is auditable.
//
// Shared by every exposure projection (secret/misconfig finding bridge and the
// recon asset bridge) so the dedupe/reactivate rules live in exactly one place.
func upsertExposureEvent(
	ctx context.Context,
	repo exposure.Repository,
	historyRepo exposure.StateHistoryRepository,
	log *logger.Logger,
	event *exposure.ExposureEvent,
	reactivateNote string,
) error {
	existing, err := repo.GetByFingerprint(ctx, event.TenantID(), event.Fingerprint())
	if err != nil && !exposure.IsExposureEventNotFound(err) {
		return fmt.Errorf("failed to check existing exposure: %w", err)
	}

	if existing == nil {
		if err := repo.Create(ctx, event); err != nil {
			// A concurrent projection for the same exposure may have won the
			// race. Treat an existing fingerprint as success (idempotent).
			if exposure.IsExposureEventExists(err) {
				return nil
			}
			return fmt.Errorf("failed to create exposure event: %w", err)
		}
		return nil
	}

	return reconcileExistingEvent(ctx, repo, historyRepo, log, existing, reactivateNote)
}

// reconcileExistingEvent mirrors the credential-import handling of an
// already-known exposure: skip if the user marked it a false positive,
// reactivate + mark seen if it was resolved (the exposure is back), otherwise
// just bump last_seen.
func reconcileExistingEvent(
	ctx context.Context,
	repo exposure.Repository,
	historyRepo exposure.StateHistoryRepository,
	log *logger.Logger,
	existing *exposure.ExposureEvent,
	reactivateNote string,
) error {
	switch existing.State() {
	case exposure.StateFalsePositive:
		// Respect the user's decision — do not resurrect.
		return nil

	case exposure.StateResolved:
		previousState := existing.State()
		if err := existing.Reactivate(); err != nil {
			return fmt.Errorf("failed to reactivate exposure: %w", err)
		}
		existing.MarkSeen()
		if err := repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update exposure: %w", err)
		}
		if historyRepo != nil {
			history, herr := exposure.NewStateHistory(
				existing.ID(),
				previousState,
				exposure.StateActive,
				nil,
				fmt.Sprintf("Reactivated by re-scan (%s)", reactivateNote),
			)
			if herr == nil {
				_ = historyRepo.Create(ctx, history)
			}
		}
		return nil

	default: // active, accepted
		existing.MarkSeen()
		if err := repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update exposure: %w", err)
		}
		return nil
	}
}
