package scope

// Why something is out of scope (research/320, RFC-054 §20). Every kind
// stops scanning the same way; the kind decides what else happens:
//
//   - do_not_scan: the organization's own, but must not be scanned (a
//     fragile system, a legal hold). Its findings stay open: the risk is
//     still the organization's.
//   - not_ours: someone else's (sold, third party, a typo in an import).
//   - retired: gone for good (decommissioned).
//
// A permanent (no end date) exclusion of a closing kind (not_ours,
// retired) that is in effect closes the open findings of the assets it
// matches as "out of scope"; taking it out of effect reopens them. A
// temporary exclusion never closes anything, whatever its kind.

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ExclusionKind is why something is out of scope.
type ExclusionKind string

// Exclusion kinds.
const (
	ExclusionKindDoNotScan ExclusionKind = "do_not_scan"
	ExclusionKindNotOurs   ExclusionKind = "not_ours"
	ExclusionKindRetired   ExclusionKind = "retired"
)

// ErrInvalidExclusionKind is a kind that is not one of the three.
var ErrInvalidExclusionKind = fmt.Errorf("%w: kind must be do_not_scan, not_ours or retired", shared.ErrValidation)

// ParseExclusionKind parses a kind; empty is do_not_scan (the meaning every
// exclusion had before kinds existed).
func ParseExclusionKind(s string) (ExclusionKind, error) {
	k := ExclusionKind(strings.ToLower(strings.TrimSpace(s)))
	if k == "" {
		return ExclusionKindDoNotScan, nil
	}
	if !k.Valid() {
		return "", ErrInvalidExclusionKind
	}
	return k, nil
}

// Valid reports whether k is a known kind.
func (k ExclusionKind) Valid() bool {
	switch k {
	case ExclusionKindDoNotScan, ExclusionKindNotOurs, ExclusionKindRetired:
		return true
	}
	return false
}

// ExclusionTypeNamesAssets reports whether an exclusion of type t names
// assets (a host, an address, a range, a URL, a repository), so it can say
// they are not the organization's. Path, finding type and scanner
// exclusions only shape scans: their kind is always do_not_scan.
func ExclusionTypeNamesAssets(t ExclusionType) bool {
	switch t {
	case ExclusionTypePath, ExclusionTypeFindingType, ExclusionTypeScanner:
		return false
	}
	return true
}

// ClosesFindings reports whether an exclusion of this kind closes the open
// findings of what it matches (when it is permanent and in effect).
func (k ExclusionKind) ClosesFindings() bool {
	return k == ExclusionKindNotOurs || k == ExclusionKindRetired
}

// String returns the kind's value.
func (k ExclusionKind) String() string { return string(k) }

// Kind is why the exclusion exists (do_not_scan when unknown).
func (e *Exclusion) Kind() ExclusionKind {
	if !e.kind.Valid() {
		return ExclusionKindDoNotScan
	}
	return e.kind
}

// SetKind records why the exclusion exists; an unknown value is ignored.
func (e *Exclusion) SetKind(k ExclusionKind) {
	if k.Valid() {
		e.kind = k
	}
}

// ClosesFindings reports whether this exclusion closes the open findings of
// what it matches: a closing kind, permanent (no end date) and in effect.
func (e *Exclusion) ClosesFindings() bool {
	return e.Kind().ClosesFindings() && e.expiresAt == nil && e.IsActive()
}

// ErrExclusionClosingKindNeedsApprover: in Strict, turning an approved
// exclusion into one that closes findings needs the exclusion approval
// permission (the approval it carries was given for a kind that closes
// nothing).
var ErrExclusionClosingKindNeedsApprover = fmt.Errorf(
	"%w: changing an approved scope exclusion to not ours or retired closes findings and needs the exclusion approval permission",
	shared.ErrForbidden)

// ErrExclusionSelfClosingKind: the requester of an approved exclusion cannot
// turn it into one that closes findings alone (separation of duties).
var ErrExclusionSelfClosingKind = fmt.Errorf(
	"%w: cannot change a scope exclusion you requested to not ours or retired; another approver must",
	shared.ErrForbidden)

// AuthorizeKindChange decides whether r may change the exclusion's kind to
// next. When exclusions need review (Strict), an approved exclusion was put
// into effect by two people for its current kind; changing it to a kind
// that closes findings (from one that does not) closes findings no second
// person agreed to, so it needs the approval permission and someone other
// than the requester. This holds whether or not it is in effect now: a
// deactivated one goes back into effect without a new approval. A pending
// exclusion is approved later with its new kind, and every other change
// closes nothing more.
func (e *Exclusion) AuthorizeKindChange(r Reviewer, next ExclusionKind, needsReview bool) error {
	if !needsReview || !e.IsApproved() || e.Kind().ClosesFindings() || !next.ClosesFindings() {
		return nil
	}
	if !r.CanApprove {
		return ErrExclusionClosingKindNeedsApprover
	}
	if r.UserID == "" {
		return fmt.Errorf("%w: reviewer is required", shared.ErrValidation)
	}
	if e.createdBy != "" && r.UserID == e.createdBy {
		return ErrExclusionSelfClosingKind
	}
	return nil
}
