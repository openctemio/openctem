package validation

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Evidence storage.
//
// Every executor produces Evidence; every Evidence row is persisted
// with tenant scope so the UI can show "what was checked, when, with
// what outcome" without re-running anything. This file defines the
// persistence contract and the redaction pass that MUST run before
// any provider-specific RawMeta hits the database.
//
// Redaction is defence-in-depth — providers should not capture
// secrets in the first place, but the Atomic Red Team executor's
// stdout CAN include environment variables that look like tokens,
// and that must not land in our DB verbatim.

// StoredEvidence is the persistence shape. Adds tenant_id + finding
// linkage to the in-memory Evidence struct. Persisted into the
// simulation_evidence table (migration lives in a companion PR).
type StoredEvidence struct {
	ID              shared.ID
	TenantID        shared.ID
	FindingID       shared.ID  // the finding this execution validated
	SimulationRunID *shared.ID // optional; populated when evidence is part of a scheduled simulation
	Evidence        Evidence
	CreatedAt       time.Time

	// DetectionStatus answers "did any control observe this?" — a
	// SEPARATE question from Evidence.Outcome ("is the exposure still
	// reachable?"). Defaults to DetectionNotEvaluated so a record never
	// implies a control failed just because correlation did not run.
	DetectionStatus DetectionStatus
	// DetectionDetail records how the verdict was reached (match mode,
	// window, pipeline liveness) so an operator can audit it.
	DetectionDetail map[string]any
}

// EvidenceRepository persists StoredEvidence. Implemented by a
// postgres-backed type; tests use an in-memory fake.
type EvidenceRepository interface {
	Create(ctx context.Context, ev StoredEvidence) error
	ListByFinding(ctx context.Context, tenantID, findingID shared.ID) ([]StoredEvidence, error)
}

// EvidenceStore is the app-layer facade. Calls redact → persist →
// returns the stored record so callers can surface it.
type EvidenceStore struct {
	repo       EvidenceRepository
	redactor   *Redactor
	now        func() time.Time
	detections *DetectionCorrelator // optional; nil → DetectionNotEvaluated
}

// NewEvidenceStore wires defaults. Detection correlation is off until
// SetDetectionCorrelator is called — until then every record is stored
// as DetectionNotEvaluated, never as a detection gap.
func NewEvidenceStore(repo EvidenceRepository) *EvidenceStore {
	return &EvidenceStore{
		repo:     repo,
		redactor: NewRedactor(),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// SetDetectionCorrelator enables "did our controls react?" evaluation.
// Called from services bootstrap after both the store and the telemetry
// probe exist — mirrors RuntimeTelemetryHandler.SetCorrelator and avoids
// a wiring-order cycle.
func (s *EvidenceStore) SetDetectionCorrelator(c *DetectionCorrelator) { s.detections = c }

// Record persists the evidence after redaction. Returns the stored
// envelope with ID populated. Errors from the repo are propagated.
func (s *EvidenceStore) Record(
	ctx context.Context,
	tenantID, findingID shared.ID,
	simulationRunID *shared.ID,
	ev Evidence,
) (StoredEvidence, error) {
	if tenantID.IsZero() || findingID.IsZero() {
		return StoredEvidence{}, fmt.Errorf("%w: tenant and finding ids are required", shared.ErrValidation)
	}
	redacted := s.redactor.Redact(ev)

	// Detection verdict — the "did our controls react?" half of Stage-4.
	// Correlation failures degrade to DetectionNotEvaluated inside
	// Evaluate; they never block persisting the evidence, and they never
	// produce a detection gap.
	verdict := DetectionVerdict{
		Status: DetectionNotEvaluated,
		Detail: map[string]any{"reason": "detection correlation not configured"},
	}
	if s.detections != nil {
		verdict = s.detections.Evaluate(ctx, tenantID, redacted, ev.CorrelationID)
	}

	stored := StoredEvidence{
		ID:              shared.NewID(),
		TenantID:        tenantID,
		FindingID:       findingID,
		SimulationRunID: simulationRunID,
		Evidence:        redacted,
		CreatedAt:       s.now(),
		DetectionStatus: verdict.Status,
		DetectionDetail: verdict.Detail,
	}
	if err := s.repo.Create(ctx, stored); err != nil {
		return StoredEvidence{}, fmt.Errorf("persist evidence: %w", err)
	}
	return stored, nil
}

// ListForFinding returns every evidence record attached to a finding
// in chronological order. The UI uses this on the finding detail
// page.
func (s *EvidenceStore) ListForFinding(
	ctx context.Context,
	tenantID, findingID shared.ID,
) ([]StoredEvidence, error) {
	return s.repo.ListByFinding(ctx, tenantID, findingID)
}

// Redactor scrubs common secret patterns from the evidence before
// it is persisted.
type Redactor struct {
	patterns []*regexp.Regexp
}

// NewRedactor returns a Redactor with the default pattern set.
// Patterns are conservative — we would rather redact too much than
// too little. Operators can extend via AddPattern.
func NewRedactor() *Redactor {
	return &Redactor{patterns: defaultRedactPatterns()}
}

// AddPattern registers an additional regex. Panics on a bad regex
// (programmer error — regex is a const at the call site).
func (r *Redactor) AddPattern(re string) {
	r.patterns = append(r.patterns, regexp.MustCompile(re))
}

// Redact returns a copy of the evidence with secrets replaced by
// "[REDACTED]". Fields scrubbed:
//   - Summary
//   - RawMeta["stdout"], RawMeta["stderr"] (common places ART puts output)
func (r *Redactor) Redact(ev Evidence) Evidence {
	out := ev
	out.Summary = r.redactString(out.Summary)
	if out.RawMeta != nil {
		cleaned := make(map[string]any, len(out.RawMeta))
		for k, v := range out.RawMeta {
			if s, ok := v.(string); ok {
				cleaned[k] = r.redactString(s)
			} else {
				cleaned[k] = v
			}
		}
		out.RawMeta = cleaned
	}
	return out
}

func (r *Redactor) redactString(in string) string {
	out := in
	for _, re := range r.patterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}

// defaultRedactPatterns is the initial pattern set. Each pattern
// targets a distinct class of secret. Order matters only for
// readability.
func defaultRedactPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// AWS access key IDs
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		// AWS secret access keys (40 chars of base64-ish material
		// after "aws_secret" prefix — rough match)
		regexp.MustCompile(`(?i)aws_secret[_a-z]*\s*[:=]\s*\S{20,}`),
		// Generic bearer tokens: "Bearer <token>"
		regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}`),
		// GitHub PAT (ghp_)
		regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),
		// OpenAI / Anthropic style sk- keys
		regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`),
		// Private-key headers
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		// Password=... / PASSWORD=... assignments
		regexp.MustCompile(`(?i)password\s*[:=]\s*\S+`),
	}
}
