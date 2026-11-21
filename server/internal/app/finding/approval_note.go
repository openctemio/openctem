package finding

// When a false-positive or accepted-risk decision needs a note
// (research/533 D4, owner-approved 2026-11-19): the reason code is always
// required; the free-text note is optional only when the requester decides
// alone (applied now, never an automation's request) on a finding that is not
// serious. "Serious" is the classifier of the high_and_above level
// (approvalpolicy.MaterialForFalsePositive: critical or high, KEV, P0/P1, a
// validated exploit, a crown jewel or an internet-exposed asset). Whenever a
// second person approves (a pending request, every group) or the finding is
// serious, the note is required with the tier's minimum length (at least 1):
// the approver, and anyone reading the history later, needs the context.

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// noteRequired is the shortest note a decision needs; 0 means the note is
// optional. decidedAlone: the requester's decision is applied now, alone
// (tier single, not an automation). facts are the finding's policy facts and
// epss the organization's EPSS threshold; minNote is the tier's minimum.
func noteRequired(decidedAlone bool, facts approvalpolicy.Facts, epss float64, minNote int) int {
	if decidedAlone && !approvalpolicy.MaterialForFalsePositive(facts, epss) {
		return 0
	}
	return max(minNote, 1)
}

// noteLength is the length of a note as the rule counts it (trimmed runes).
func noteLength(note string) int {
	return utf8.RuneCountInString(strings.TrimSpace(note))
}

// errNoteRequired is the validation error of a missing or short note.
func errNoteRequired(minLen int, tier approvalpolicy.Tier) error {
	return fmt.Errorf("%w: this request needs a note of at least %d characters (%s tier)", shared.ErrValidation, minLen, tier)
}
