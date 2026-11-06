package postgres

// Severity provenance columns of the findings table
// (docs/architecture/finding-severity-override.md): severity is the
// effective value; source_severity is what the tools reported while an
// analyst override stands; the override's reason, author and time.

import (
	"database/sql"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// findingSeverityColumnsSQL lists the provenance columns of a SELECT; the
// order matches findingSeverityScan.dests.
const findingSeverityColumnsSQL = `source_severity, severity_override_reason, severity_overridden_by, severity_overridden_at`

// findingSeverityScan receives the provenance columns of a SELECT.
type findingSeverityScan struct {
	source       sql.NullString
	reason       sql.NullString
	overriddenBy sql.NullString
	overriddenAt sql.NullTime
}

func (s *findingSeverityScan) dests() []any {
	return []any{&s.source, &s.reason, &s.overriddenBy, &s.overriddenAt}
}

func (s *findingSeverityScan) provenance() vulnerability.SeverityProvenance {
	p := vulnerability.SeverityProvenance{
		Source:         vulnerability.Severity(s.source.String),
		OverrideReason: s.reason.String,
	}
	if s.overriddenBy.Valid {
		if id, err := shared.IDFromString(s.overriddenBy.String); err == nil {
			p.OverriddenBy = &id
		}
	}
	if s.overriddenAt.Valid {
		t := s.overriddenAt.Time
		p.OverriddenAt = &t
	}
	return p
}

// reportedSeveritySetSQL is the SET part of a write of a severity reported by
// a tool or a platform rule (not an analyst): it becomes the effective
// severity while no override stands, and the source severity otherwise, so
// an analyst's override always stands. ref qualifies the row's current
// columns ("" or "alias."); value is the SQL expression of the new severity.
func reportedSeveritySetSQL(ref, value string) string {
	return `severity = CASE WHEN ` + ref + `severity_overridden_at IS NULL THEN ` + value + ` ELSE ` + ref + `severity END,
			source_severity = CASE WHEN ` + ref + `severity_overridden_at IS NULL THEN ` + ref + `source_severity ELSE ` + value + ` END`
}

// reportedSeverityMaxSetSQL is reportedSeveritySetSQL with the re-sighting
// rule: the higher of the stored and the reported severity wins (ranked by
// severityRankSQL, the order of vulnerability.SeverityRank).
func reportedSeverityMaxSetSQL(ref, value string) string {
	stored := `COALESCE(` + ref + `source_severity, ` + ref + `severity)`
	return `severity = CASE WHEN ` + ref + `severity_overridden_at IS NOT NULL THEN ` + ref + `severity
				WHEN ` + severityRankSQL(value) + ` > ` + severityRankSQL(ref+`severity`) + ` THEN ` + value + `
				ELSE ` + ref + `severity END,
			source_severity = CASE WHEN ` + ref + `severity_overridden_at IS NULL THEN ` + ref + `source_severity
				WHEN ` + severityRankSQL(value) + ` > ` + severityRankSQL(stored) + ` THEN ` + value + `
				ELSE ` + stored + ` END`
}
