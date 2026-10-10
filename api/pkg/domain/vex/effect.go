package vex

import (
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingRef is what deciding a statement's effect needs to know about a
// finding.
type FindingRef struct {
	ID        shared.ID
	AssetID   shared.ID
	ProductID shared.ID
	// Version is the raw version of the finding's package version.
	Version string
	// VulnIDs are the finding's vulnerability ids, upper case: its CVE, CVEs,
	// rule id and typed ids.
	VulnIDs          []string
	Status           string
	Source           string
	ResolutionMethod string
	// StatementID is the statement the finding carries now (nil: none).
	StatementID *shared.ID
	// VEXAt is when the carried statement was last updated, as recorded.
	VEXAt *time.Time
}

// HasVuln reports whether id is one of the finding's vulnerability ids.
func (f *FindingRef) HasVuln(id string) bool {
	for _, v := range f.VulnIDs {
		if strings.EqualFold(v, id) {
			return true
		}
	}
	return false
}

// humanSources are never closed by a statement: a person found them.
var humanSources = map[string]bool{
	string(vulnerability.FindingSourcePentest):   true,
	string(vulnerability.FindingSourceManual):    true,
	string(vulnerability.FindingSourceBugBounty): true,
	string(vulnerability.FindingSourceRedTeam):   true,
}

// IsHumanSource reports whether a finding of this source is never closed by
// a statement.
func IsHumanSource(source string) bool { return humanSources[source] }

// closedByStatement reports whether the finding is closed because of the
// statement it carries.
func (f *FindingRef) closedByStatement() bool {
	if f.StatementID == nil {
		return false
	}
	switch f.ResolutionMethod {
	case ResolutionNotAffected:
		return f.Status == string(vulnerability.FindingStatusFalsePositive)
	case ResolutionFixed:
		return f.Status == string(vulnerability.FindingStatusResolved)
	}
	return false
}

// Effect is what to write on a finding.
type Effect struct {
	FindingID shared.ID
	// OldStatus guards the write: it applies only while the finding still
	// has this status.
	OldStatus string
	// Statement is the governing statement (nil: clear the carried one).
	Statement *Statement
	// NewStatus is set when the status changes. Resolution and
	// ResolutionMethod go with it ("" clears them on a reopen).
	NewStatus        string
	ResolutionMethod string
	Resolution       string
}

// Changes reports whether the effect moves the status.
func (e *Effect) Changes() bool { return e.NewStatus != "" && e.NewStatus != e.OldStatus }

// Decide returns what statement w (nil: none governs) does to finding f,
// or nil when nothing changes.
//
//   - No statement: a finding that carried one loses it; when that
//     statement had closed it, it reopens (false positive -> new, resolved ->
//     confirmed, the lifecycle's reopen edges).
//   - not_affected / fixed: an open, non-human finding is closed (false
//     positive with vex_not_affected, or resolved with vex_fixed). A finding
//     closed by another statement switches to this one's closure. A finding a
//     person closed, or a human-sourced finding, is annotated only.
//   - affected / under_investigation: annotate; a finding closed by a
//     statement reopens.
func Decide(f *FindingRef, w *Statement) *Effect {
	e := &Effect{FindingID: f.ID, OldStatus: f.Status, Statement: w}
	byStatement := f.closedByStatement()
	if w == nil {
		if f.StatementID == nil {
			return nil
		}
		if byStatement {
			e.NewStatus = reopenStatus(f.Status)
		}
		return e
	}
	if w.Status.Closes() && !IsHumanSource(f.Source) {
		target, method := closure(w.Status)
		switch {
		case canAutoClose(f.Status):
			e.NewStatus, e.ResolutionMethod, e.Resolution = target, method, ResolutionText(w)
		case byStatement && (f.Status != target || f.ResolutionMethod != method):
			e.NewStatus, e.ResolutionMethod, e.Resolution = target, method, ResolutionText(w)
		}
	} else if byStatement {
		e.NewStatus = reopenStatus(f.Status)
	}
	if !e.Changes() && f.StatementID != nil && *f.StatementID == w.ID &&
		f.VEXAt != nil && f.VEXAt.Equal(w.UpdatedAt) {
		return nil
	}
	return e
}

func closure(s Status) (status, method string) {
	if s == StatusFixed {
		return string(vulnerability.FindingStatusResolved), ResolutionFixed
	}
	return string(vulnerability.FindingStatusFalsePositive), ResolutionNotAffected
}

func canAutoClose(status string) bool {
	for _, s := range vulnerability.AutoCloseFromStatuses() {
		if string(s) == status {
			return true
		}
	}
	return false
}

func reopenStatus(status string) string {
	if status == string(vulnerability.FindingStatusResolved) {
		return string(vulnerability.FindingStatusConfirmed)
	}
	return string(vulnerability.FindingStatusNew)
}

// ResolutionText is the resolution note of a finding a statement closed.
func ResolutionText(s *Statement) string {
	reason := s.Justification
	if reason == "" {
		reason = "statement"
	}
	return "VEX " + string(s.Status) + ": " + reason + " (statement " + s.ID.String() + ")"
}
