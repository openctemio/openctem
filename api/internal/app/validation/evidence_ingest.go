package validation

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EvidenceIngestService records validation evidence submitted out-of-band — an
// sensor that finished an async validation job, or a pentest retest reporting a
// result — and reconciles the finding status from the evidence outcome.
//
// This is the activation seam that makes CTEM Stage-4 (Validation) functional
// without a synchronous in-process dispatcher: sensor executes the technique →
// POSTs Evidence to the ingest endpoint → this service persists it (redacted)
// and applies the outcome to the finding.
type EvidenceIngestService struct {
	store    *EvidenceStore
	finding  FindingMutator
	notifier RetestNotifier
	recorder VerdictRecorder
	logger   *logger.Logger
}

// NewEvidenceIngestService wires the ingest service. notifier and recorder may
// be nil (recorder-nil skips the durable verdict stamp that feeds downgrade %).
func NewEvidenceIngestService(store *EvidenceStore, finding FindingMutator, notifier RetestNotifier, recorder VerdictRecorder, log *logger.Logger) *EvidenceIngestService {
	return &EvidenceIngestService{
		store:    store,
		finding:  finding,
		notifier: notifier,
		recorder: recorder,
		logger:   log.With("service", "validation-ingest"),
	}
}

// ErrInvalidOutcome is returned when the evidence outcome is not a known value.
var ErrInvalidOutcome = fmt.Errorf("%w: invalid evidence outcome", shared.ErrValidation)

// ErrEvidenceAssetMismatch is returned when evidence names an asset other
// than its finding's asset.
var ErrEvidenceAssetMismatch = fmt.Errorf("%w: evidence target asset is not the finding's asset", shared.ErrValidation)

// IngestResult summarizes what an evidence ingestion did.
type IngestResult struct {
	Stored        StoredEvidence
	StatusChanged bool // the finding moved to resolved (the fix stood)
	// Downgraded is true when a not_reproducible verdict downgraded a
	// still-open finding to validated_fixed (feeds the downgrade % metric).
	Downgraded bool
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
//
// Callers must only use Ingest for evidence that is AUTHORIZED to move the
// finding (a server-issued validate command, or a sensor proving it holds the
// validate command assigned to it for this finding). Unsolicited evidence goes
// through IngestAdvisory.
func (s *EvidenceIngestService) Ingest(
	ctx context.Context,
	tenantID, findingID shared.ID,
	simRunID *shared.ID,
	ev Evidence,
) (IngestResult, error) {
	stored, err := s.record(ctx, tenantID, findingID, simRunID, ev)
	if err != nil {
		return IngestResult{}, err
	}

	res, aerr := applyOutcomeToFinding(ctx, s.finding, s.notifier, s.recorder, tenantID, findingID, ev)
	if aerr != nil {
		s.logger.Warn("validation evidence recorded but finding status unchanged",
			"tenant_id", tenantID.String(), "finding_id", findingID.String(),
			"outcome", logger.SanitizeValue(string(ev.Outcome)), "error", aerr)
		return IngestResult{Stored: stored, StatusChanged: false}, nil
	}
	return IngestResult{Stored: stored, StatusChanged: res.Stood, Downgraded: res.Downgraded}, nil
}

// IngestAdvisory records the evidence (same validation, tenant guard and
// redaction as Ingest) WITHOUT applying its outcome to the finding. Used for
// evidence a sensor submits outside an assigned validate command: it stays
// visible on the finding for a human to weigh, but an arbitrary sensor key in
// the tenant can no longer resolve / downgrade / reopen any finding by id.
func (s *EvidenceIngestService) IngestAdvisory(
	ctx context.Context,
	tenantID, findingID shared.ID,
	simRunID *shared.ID,
	ev Evidence,
) (IngestResult, error) {
	stored, err := s.record(ctx, tenantID, findingID, simRunID, ev)
	if err != nil {
		return IngestResult{}, err
	}
	return IngestResult{Stored: stored}, nil
}

// record validates and persists the evidence after the tenant guard.
func (s *EvidenceIngestService) record(
	ctx context.Context,
	tenantID, findingID shared.ID,
	simRunID *shared.ID,
	ev Evidence,
) (StoredEvidence, error) {
	if tenantID.IsZero() || findingID.IsZero() {
		return StoredEvidence{}, fmt.Errorf("%w: tenant and finding ids are required", shared.ErrValidation)
	}
	if !validOutcome(ev.Outcome) {
		return StoredEvidence{}, fmt.Errorf("%w: %q", ErrInvalidOutcome, ev.Outcome)
	}

	// Tenant guard: the finding must exist within the submitting sensor's tenant.
	// Without this, a compromised sensor could record evidence against another
	// tenant's finding id (the FK to findings(id) alone would not catch it).
	f, err := s.finding.Get(ctx, tenantID, findingID)
	if err != nil {
		return StoredEvidence{}, fmt.Errorf("finding lookup: %w", err)
	}
	// Asset binding: evidence names the finding's own asset or none. A sensor
	// cannot attach evidence to another asset of the tenant through it.
	if !ev.Target.AssetID.IsZero() && !ev.Target.AssetID.Equals(f.AssetID()) {
		return StoredEvidence{}, ErrEvidenceAssetMismatch
	}

	return s.store.Record(ctx, tenantID, findingID, simRunID, ev)
}

// ListForFinding returns the evidence recorded for a finding (UI detail page).
func (s *EvidenceIngestService) ListForFinding(ctx context.Context, tenantID, findingID shared.ID) ([]StoredEvidence, error) {
	return s.store.ListForFinding(ctx, tenantID, findingID)
}
