package safetext

import (
	"regexp"
	"slices"
	"strings"
)

// E-mail addresses are personal data the platform stores masked only
// (research/292, 446). MaskEmails replaces all but the first character of
// the local part of every address in a
// text with EmailMask and keeps the domain, which says whose address it was
// (the organization's, a provider's) without naming the person:
// "jane.doe@example.com" becomes "j***@example.com". A URL-encoded address
// ("jane%40example.com", a query value in a request line) is masked the same
// way. The mask contains no local-part character, so masking is idempotent.
// The owner rule (research/446): an address is kept, masked, not dropped; the
// first character stays so a person can tell addresses of one domain apart
// ("j***@example.com").

// EmailMask replaces the local part of an e-mail address.
const EmailMask = "***"

// emailDomain is a DNS name with at least two labels and an alphabetic top
// label, so version strings ("lib@1.2.3") and digests ("image@sha256:...")
// are not addresses.
const emailDomain = `((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})\b`

var (
	emailRE        = regexp.MustCompile(`[A-Za-z0-9._%+-]+@` + emailDomain)
	encodedEmailRE = regexp.MustCompile(`[A-Za-z0-9._+-]+%40` + emailDomain)
)

// MaskEmails returns s with the local part of every e-mail address replaced
// by EmailMask (see the file comment).
func MaskEmails(s string) string {
	return MaskEmailsMoving(s)
}

// MaskEmailsMoving is MaskEmails for a text that byte offsets point into
// (marked spans, match ranges): each offset is moved with the text it points
// at. An offset inside a masked local part moves to the start of its mask.
func MaskEmailsMoving(s string, offsets ...*int) string {
	locals := emailLocals(s)
	if len(locals) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, l := range locals {
		b.WriteString(s[prev:l[0]])
		b.WriteString(EmailMask)
		prev = l[1]
	}
	b.WriteString(s[prev:])
	for _, o := range offsets {
		if o != nil {
			*o = movedOffset(*o, locals)
		}
	}
	return b.String()
}

// movedOffset is where offset o of the original text sits after the local
// parts in locals are replaced by EmailMask.
func movedOffset(o int, locals [][2]int) int {
	delta := 0
	for _, l := range locals {
		switch {
		case o >= l[1]:
			delta += len(EmailMask) - (l[1] - l[0])
		case o > l[0]:
			return l[0] + delta
		default:
			return o + delta
		}
	}
	return o + delta
}

// emailLocals returns the byte ranges of the local parts of the addresses
// in s, sorted and not overlapping.
func emailLocals(s string) [][2]int {
	out := emailLocalsFull(s)
	for i := range out {
		// The first character stays: "jane.doe@example.com" becomes
		// "j***@example.com" (the replaced range starts one byte in; local
		// parts are ASCII).
		out[i][0]++
	}
	return out
}

// emailLocalsFull is emailLocals with each range starting at the first
// character of the local part.
func emailLocalsFull(s string) [][2]int {
	var out [][2]int
	if strings.Contains(s, "@") {
		for _, m := range emailRE.FindAllStringSubmatchIndex(s, -1) {
			// m[2] is the start of the domain, one past the "@".
			out = append(out, [2]int{m[0], m[2] - 1})
		}
	}
	if strings.Contains(s, "%40") {
		for _, m := range encodedEmailRE.FindAllStringSubmatchIndex(s, -1) {
			l := [2]int{m[0], m[2] - 3}
			overlaps := false
			for _, o := range out {
				if l[0] < o[1] && l[1] > o[0] {
					overlaps = true
					break
				}
			}
			if !overlaps {
				out = append(out, l)
			}
		}
		slices.SortFunc(out, func(a, b [2]int) int { return a[0] - b[0] })
	}
	return out
}

// ContainsEmail reports whether s holds an e-mail address MaskEmails would
// mask.
func ContainsEmail(s string) bool { return len(emailLocals(s)) > 0 }
