package finding

import (
	"errors"
	"strings"
	"unicode/utf8"

	lc "github.com/openctemio/openctem/server/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// Refusal codes: why a verifier's decision on a claimed fix (verify or
// reject, by ids or by filter) left a finding alone. The list is closed: a
// client translates each code (web: findings.fixRefusal.<code>) and never
// sees the error text, which can name internal rules.
const (
	// RefusalNotFound: no such finding in the organization, or outside the
	// caller's data scope (the two read the same).
	RefusalNotFound = "not_found"
	// RefusalNotFixApplied: the finding no longer waits for verification.
	RefusalNotFixApplied = "not_fix_applied"
	// RefusalEvidenceRequired: a critical, P0 or known-exploited finding
	// closes only after a retest confirmed the fix, or with the verification
	// checklist completed by another person.
	RefusalEvidenceRequired = "evidence_required"
	// RefusalChecklistRequired: the verification checklist (complete) or a
	// confirmed retest is needed first.
	RefusalChecklistRequired = "checklist_required"
	// RefusalMissingPermission: the caller lacks a permission the move needs.
	RefusalMissingPermission = "missing_permission"
	// RefusalLifecycle: the organization's finding lifecycle does not allow
	// the move from an action (or needs fields an action does not take).
	RefusalLifecycle = "lifecycle_refused"
	// RefusalNoteRequired: the move needs a (longer) note.
	RefusalNoteRequired = "note_required"
	// RefusalApprovalRequired: the move is a request a second person approves.
	RefusalApprovalRequired = "approval_required"
	// RefusalChanged: the finding changed after it was read; reload and retry.
	RefusalChanged = "changed"
	// RefusalNotAllowed: any other refusal of the move.
	RefusalNotAllowed = "not_allowed"
	// RefusalUnavailable: the finding's evidence could not be read; retry.
	RefusalUnavailable = "unavailable"
)

// RefusalCodes is every refusal code, for clients and tests.
var RefusalCodes = []string{
	RefusalNotFound, RefusalNotFixApplied, RefusalEvidenceRequired, RefusalChecklistRequired,
	RefusalMissingPermission, RefusalLifecycle, RefusalNoteRequired, RefusalApprovalRequired,
	RefusalChanged, RefusalNotAllowed, RefusalUnavailable,
}

// ActionRefusal is a move an action route refused for one finding: the
// engine's error with its refusal code. It unwraps to the error, so callers
// that check the error kind (validation, forbidden, approval) are unchanged.
type ActionRefusal struct {
	Code string
	err  error
}

func (e *ActionRefusal) Error() string { return e.err.Error() }
func (e *ActionRefusal) Unwrap() error { return e.err }

// RefusalCodeOf returns the refusal code of an action error, or
// RefusalNotAllowed when it carries none.
func RefusalCodeOf(err error) string {
	var r *ActionRefusal
	if errors.As(err, &r) {
		return r.Code
	}
	return RefusalNotAllowed
}

// refusalCodeOf names the reason lifecycleError gave for d, in its order:
// the lifecycle's own blocks, then the platform's (approval, permission,
// evidence), then the note and the lifecycle's fields.
func refusalCodeOf(d lc.Decision, note string, err error) string {
	var approval *vulnerability.ApprovalRequiredError
	switch {
	case errors.Is(err, ErrLifecycleMove):
		return RefusalLifecycle
	case errors.As(err, &approval):
		return RefusalApprovalRequired
	case errors.Is(err, ErrResolveRequiresVerify), errors.Is(err, ErrFixApplyRequiresPermission),
		errors.Is(err, ErrRevokeRequiresApprove):
		return RefusalMissingPermission
	case errors.Is(err, ErrNoteRequired):
		return RefusalNoteRequired
	}
	for _, b := range d.Blocked {
		switch b.Code {
		case vulnerability.BlockEvidenceRequired:
			return RefusalEvidenceRequired
		case vulnerability.BlockChecklistRequired:
			return RefusalChecklistRequired
		case vulnerability.BlockMissingPermission:
			return RefusalMissingPermission
		case vulnerability.BlockNotInScope:
			return RefusalNotFound
		}
	}
	if len(d.Blocked) > 0 {
		return RefusalNotAllowed
	}
	if d.NoteMinLen > 0 && utf8.RuneCountInString(strings.TrimSpace(note)) < d.NoteMinLen {
		return RefusalNoteRequired
	}
	if len(d.Fields) > 0 {
		// Action routes take no lifecycle fields.
		return RefusalLifecycle
	}
	return RefusalNotAllowed
}
