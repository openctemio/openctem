package retest

import "time"

// MinDenialGap is the least time between the two origin refusals that
// confirm an exposure fix: a transient rule, a deploy window or a burst of
// rate limiting does not last an hour.
const MinDenialGap = time.Hour

// MaxDenialAge is how old a prior origin refusal may be and still pair with a
// new one.
const MaxDenialAge = 14 * 24 * time.Hour

// Class is what the settlement needs to know about a finding beyond one
// attempt's evidence.
type Class struct {
	// Exposure: the platform template that matched is of the exposure class
	// (a page, panel, document, config or backup file, debug endpoint,
	// listing the server hands out), from the template's own tags recorded by
	// the scanner. It is never derived from the finding's editable tags.
	Exposure bool
	// PriorAccessDenied: the finding's previous completed retest, at least
	// MinDenialGap ago, was an origin refusal of the same check with no edge
	// marker. An edge-marked answer in between is not a refusal, so it
	// resets the count.
	PriorAccessDenied bool
}

func firstClass(c []Class) Class {
	if len(c) == 0 {
		return Class{}
	}
	return c[0]
}
