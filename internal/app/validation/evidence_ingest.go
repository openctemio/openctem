package validation

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// EvidenceIngestService records validation evidence submitted out-of-band — an
// agent that finished an async validation job, or a pentest retest reporting a
// result — and reconciles the finding status from the evidence outcome.
//
// This is the activation seam that makes CTEM Stage-4 (Validation) functional
// without a synchronous in-process dispatcher: agent executes the technique →
// POSTs Evidence to the ingest endpoint → this service persists it (redacted)
// and applies the outcome to the finding.
type EvidenceIngestService struct {
	store    *EvidenceStore
	finding  FindingMutator
	notifier RetestNotifier
	logger   *logger.Logger
}

// NewEvidenceIngestService wires the ingest service. notifier may be nil.
func NewEvidenceIngestService(store *EvidenceStore, finding FindingMutator, notifier RetestNotifier, log *logger.Logger) *EvidenceIngestService {
	return &EvidenceIngestService{
		store:    store,
		finding:  finding,
		notifier: notifier,
		logger:   log.With("service", "validation-ingest"),
	}
}

// ErrInvalidOutcome is returned when the evidence outcome is not a known value.
var ErrInvalidOutcome = fmt.Errorf("%w: invalid evidence outcome", shared.ErrValidation)

// IngestResult summarizes what an evidence ingestion did.
type IngestResult struct {
	Stored        StoredEvidence
	StatusChanged bool // the finding moved to resolved (the fix stood)
}

func validOutcome(o Outcome) bool {
	switch o {
	case OutcomeDetected, OutcomeNotDetected, OutcomeInconclusive, OutcomeError, OutcomeSkipped:
		return true
	}
	return false
}

// Ingest persists the evidence (after redaction) and applies its outcome to the
// finding. The evidence is the source of truth and is always recorded first; if
// the finding cannot legally transition from its current state (e.g. already
// closed) that is logged but NOT fatal — the recorded evidence still surfaces.
func (s *EvidenceIngestService) Ingest(
	ctx context.Context,
	tenantID, findingID shared.ID,
	simRunID *shared.ID,
	ev Evidence,
) (IngestResult, error) {
	if tenantID.IsZero() || findingID.IsZero() {
		return IngestResult{}, fmt.Errorf("%w: tenant and finding ids are required", shared.ErrValidation)
	}
	if !validOutcome(ev.Outcome) {
		return IngestResult{}, fmt.Errorf("%w: %q", ErrInvalidOutcome, ev.Outcome)
	}

	// Tenant guard: the finding must exist within the submitting agent's tenant.
	// Without this, a compromised agent could record evidence against another
	// tenant's finding id (the FK to findings(id) alone would not catch it).
	if _, err := s.finding.Get(ctx, tenantID, findingID); err != nil {
		return IngestResult{}, fmt.Errorf("finding lookup: %w", err)
	}

	stored, err := s.store.Record(ctx, tenantID, findingID, simRunID, ev)
	if err != nil {
		return IngestResult{}, err
	}

	stood, aerr := applyOutcomeToFinding(ctx, s.finding, s.notifier, tenantID, findingID, ev)
	if aerr != nil {
		s.logger.Warn("validation evidence recorded but finding status unchanged",
			"tenant_id", tenantID.String(), "finding_id", findingID.String(),
			"outcome", string(ev.Outcome), "error", aerr)
		return IngestResult{Stored: stored, StatusChanged: false}, nil
	}
	return IngestResult{Stored: stored, StatusChanged: stood}, nil
}

// ListForFinding returns the evidence recorded for a finding (UI detail page).
func (s *EvidenceIngestService) ListForFinding(ctx context.Context, tenantID, findingID shared.ID) ([]StoredEvidence, error) {
	return s.store.ListForFinding(ctx, tenantID, findingID)
}
