package tag

import (
	"slices"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Change is an edit of an object's tags: the tags a person adds and the
// ones they remove. An edit is a change, never a new list: a tag the editor
// did not name stays, whoever set it (a rule, an import, a sensor, another
// person) and whenever (a list built from a copy loaded before that tag was
// set would drop it).
type Change struct {
	Add    []string
	Remove []string
}

// Empty reports whether the change adds and removes nothing.
func (c Change) Empty() bool { return len(c.Add) == 0 && len(c.Remove) == 0 }

// CodeTagChangeConflict is the code of a change that both adds and removes
// one tag.
const CodeTagChangeConflict = "TAG_CHANGE_CONFLICT"

// Check refuses a change that adds and removes the same tag: which one the
// person meant cannot be told.
func (c Change) Check() error {
	for _, a := range c.Add {
		n := Normalize(a)
		for _, r := range c.Remove {
			if r == a || Normalize(r) == n {
				return shared.NewDomainError(CodeTagChangeConflict,
					"a tag cannot be added and removed in the same change", shared.ErrValidation)
			}
		}
	}
	return nil
}

// Apply returns current with c applied: the removed tags left out (compared
// as stored, and in normalized form), the added ones appended in order,
// without duplicates. Every other tag of current stays, in its order. The
// added tags are not validated here (ValidateNew does that).
func Apply(current []string, c Change) []string {
	removed := func(t string) bool {
		n := Normalize(t)
		for _, r := range c.Remove {
			if r == t || Normalize(r) == n {
				return true
			}
		}
		return false
	}
	out := make([]string, 0, len(current)+len(c.Add))
	for _, t := range current {
		if !removed(t) && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	for _, t := range c.Add {
		if !slices.Contains(out, t) && !slices.Contains(out, Normalize(t)) {
			out = append(out, t)
		}
	}
	return out
}

// Diff returns the tags of next that current lacks, and the tags of current
// that next lacks.
func Diff(current, next []string) (added, removed []string) {
	for _, t := range next {
		if !slices.Contains(current, t) {
			added = append(added, t)
		}
	}
	for _, t := range current {
		if !slices.Contains(next, t) {
			removed = append(removed, t)
		}
	}
	return added, removed
}
