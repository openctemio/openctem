package exposure

// Analyst severity override of an exposure
// (docs/architecture/exposure-taxonomy.md).
//
// severity stays the EFFECTIVE severity, so every reader (filters, stats,
// dashboards) keeps reading it. While an override stands the exposure keeps
// what the producer reported in sourceSeverity, and re-sightings update only
// that, so a scan never reverts the analyst. The four-eyes rule on accepting
// or dismissing an exposure reads the peak of the reported severity, which an
// override never lowers.

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxSeverityReasonLen bounds the reason of a severity change.
const MaxSeverityReasonLen = 1000

// ErrSeverityReasonRequired: a severity change always says why.
var ErrSeverityReasonRequired = fmt.Errorf("%w: a reason is required to change the severity", shared.ErrValidation)

// ErrNoSeverityOverride: there is no override to restore.
var ErrNoSeverityOverride = fmt.Errorf("%w: the severity is not overridden", shared.ErrValidation)

// SeverityProvenance is the stored provenance of the effective severity.
type SeverityProvenance struct {
	// Source is what the producer reported while an override stands; empty
	// when no override stands.
	Source         Severity
	OverrideReason string
	OverriddenBy   *shared.ID
	OverriddenAt   *time.Time
}

// SeverityProvenance returns the stored provenance (for persistence).
func (e *ExposureEvent) SeverityProvenance() SeverityProvenance { return e.provenance }

// RestoreSeverityProvenance sets the provenance read from storage.
func (e *ExposureEvent) RestoreSeverityProvenance(p SeverityProvenance) *ExposureEvent {
	e.provenance = p
	return e
}

// HasSeverityOverride reports whether an analyst's override stands.
func (e *ExposureEvent) HasSeverityOverride() bool { return e.provenance.OverriddenAt != nil }

// SourceSeverity is the severity the producer reported.
func (e *ExposureEvent) SourceSeverity() Severity {
	if e.HasSeverityOverride() && e.provenance.Source.IsValid() {
		return e.provenance.Source
	}
	return e.severity
}

// NormalizeSeverityReason trims a reason and checks it is present and
// bounded.
func NormalizeSeverityReason(reason string) (string, error) {
	r := strings.TrimSpace(reason)
	if r == "" {
		return "", ErrSeverityReasonRequired
	}
	if utf8.RuneCountInString(r) > MaxSeverityReasonLen {
		return "", fmt.Errorf("%w: the reason is longer than %d characters", shared.ErrValidation, MaxSeverityReasonLen)
	}
	return r, nil
}

// OverrideSeverity sets the effective severity as an analyst's decision. The
// reported severity is kept; the peak (read by the four-eyes rule) is not
// touched. Overriding to the reported severity is allowed and still records
// who decided it.
func (e *ExposureEvent) OverrideSeverity(severity Severity, reason string, by shared.ID, now time.Time) error {
	if !severity.IsValid() {
		return fmt.Errorf("%w: invalid severity", shared.ErrValidation)
	}
	r, err := NormalizeSeverityReason(reason)
	if err != nil {
		return err
	}
	if by.IsZero() {
		return fmt.Errorf("%w: the acting user is required", shared.ErrValidation)
	}
	source := e.SourceSeverity()
	// Pin the peak before the effective severity changes.
	e.peakSeverity = e.PeakSeverity()
	at := now.UTC()
	e.provenance = SeverityProvenance{Source: source, OverrideReason: r, OverriddenBy: &by, OverriddenAt: &at}
	e.severity = severity
	e.updatedAt = at
	return nil
}

// RestoreReportedSeverity removes the override: the effective severity is the
// reported one again.
func (e *ExposureEvent) RestoreReportedSeverity(reason string, now time.Time) error {
	if !e.HasSeverityOverride() {
		return ErrNoSeverityOverride
	}
	if _, err := NormalizeSeverityReason(reason); err != nil {
		return err
	}
	e.severity = e.SourceSeverity()
	e.provenance = SeverityProvenance{}
	e.updatedAt = now.UTC()
	return nil
}
