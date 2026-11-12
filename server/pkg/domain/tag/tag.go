// Package tag is the one validator for asset tags, used by every path that
// writes them: the create, update, bulk and import APIs and every import
// (CTIS ingest from sensors, connectors and importers). A tag is a free
// label or a `key:value` pair; this package decides which strings may be
// stored, never what they mean.
package tag

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/safetext"
)

// Limits. They are the ones the update API and the web have always
// enforced, so a tag any path accepts can always be saved from the console.
const (
	// MaxLength is the longest tag, in characters.
	MaxLength = 50
	// MaxPerObject is the most tags one object carries.
	MaxPerObject = 50
	// MaxPerImport is the most tags one import (a sensor report, a
	// connector sync) may set on one asset in one pass.
	MaxPerImport = 20
)

// Reason says why a tag was refused.
type Reason string

// Reasons a tag is refused.
const (
	ReasonEmpty    Reason = "empty"
	ReasonTooLong  Reason = "too_long"
	ReasonHidden   Reason = "hidden_chars"
	ReasonMarkup   Reason = "markup"
	ReasonFormula  Reason = "formula_prefix"
	ReasonReserved Reason = "reserved"
	// ReasonProtected: an import tried to set a tag that an access rule,
	// an approval rule, a scan window, an assignment rule or a routing
	// rule reads. Only a person with the permission of that rule sets it.
	ReasonProtected Reason = "protected"
	// ReasonOverCap: past the import cap per asset.
	ReasonOverCap Reason = "over_cap"
)

// reservedPrefixes are the namespaces only code writes (system tags derived
// from program links and the platform's own labels). They are compared
// case-insensitively; a bare label equal to one of them is reserved too.
var reservedPrefixes = []string{"sys:", "system:", "program:", "source:", "platform:"}

var reservedLabels = []string{"bug-bounty", "sys", "system", "dangling_cname"}

// Reserved reports whether t lives in a namespace only code writes.
func Reserved(t string) bool {
	l := strings.ToLower(strings.TrimSpace(t))
	if slices.Contains(reservedLabels, l) {
		return true
	}
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// Normalize trims t and puts it in Unicode form NFC. It does not change the
// case: values keep the spelling the writer chose.
func Normalize(t string) string {
	return norm.NFC.String(strings.TrimSpace(t))
}

// Check returns the normalized tag, or the reason it is refused. It is the
// grammar every writer shares: 1 to MaxLength characters; no control,
// bidirectional, zero-width or newline characters; no markup characters; no
// leading formula character (a CSV export would run it); not in a reserved
// namespace.
func Check(raw string) (string, Reason) {
	t := Normalize(raw)
	if t == "" {
		return "", ReasonEmpty
	}
	if utf8.RuneCountInString(t) > MaxLength {
		return "", ReasonTooLong
	}
	if !utf8.ValidString(t) || safetext.Clean(t) != t || strings.ContainsAny(t, "\r\n\t") {
		return "", ReasonHidden
	}
	if strings.ContainsAny(t, "<>") {
		return "", ReasonMarkup
	}
	switch t[0] {
	case '=', '+', '-', '@':
		return "", ReasonFormula
	}
	if Reserved(t) {
		return "", ReasonReserved
	}
	return t, ""
}

// ValidateNew checks the tags a person sets on an object that carries
// current. A tag already in current is kept as it is (a legacy tag must
// never make an object unsavable), so only added tags are checked. It
// returns the normalized list, without duplicates, or a validation error
// naming the first refused tag.
func ValidateNew(current, next []string) ([]string, error) {
	out := make([]string, 0, len(next))
	for _, raw := range next {
		if slices.Contains(current, raw) {
			if !slices.Contains(out, raw) {
				out = append(out, raw)
			}
			continue
		}
		t, why := Check(raw)
		if why != "" {
			return nil, &Error{Tag: raw, Reason: why}
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	if len(out) > MaxPerObject {
		return nil, &Error{Reason: ReasonOverCap}
	}
	return out, nil
}

// Error is a refused tag. It carries no tag text into messages beyond a
// short, escaped prefix.
type Error struct {
	Tag    string
	Reason Reason
}

func (e *Error) Error() string {
	switch e.Reason {
	case ReasonOverCap:
		return fmt.Sprintf("an object carries at most %d tags", MaxPerObject)
	case ReasonTooLong:
		return fmt.Sprintf("a tag is at most %d characters", MaxLength)
	case ReasonReserved:
		return fmt.Sprintf("tag %q is reserved for the platform", clip(e.Tag))
	case ReasonEmpty:
		return "a tag cannot be empty"
	default:
		return fmt.Sprintf("tag %q is not allowed (%s)", clip(e.Tag), e.Reason)
	}
}

// CodeInvalidTag is the code of a refused tag in an API answer.
const CodeInvalidTag = "INVALID_TAG"

// Refusal is the validation error an API answers for a refused tag: a
// fixed sentence that names the tag (clipped) and the reason, never a lower
// error's text.
func Refusal(err error) error {
	var te *Error
	if errors.As(err, &te) {
		return shared.NewDomainError(CodeInvalidTag, te.Error(), shared.ErrValidation)
	}
	return shared.NewDomainError(CodeInvalidTag, "a tag is not allowed", shared.ErrValidation)
}

func clip(s string) string {
	r := []rune(s)
	if len(r) > 20 {
		return string(r[:20]) + "..."
	}
	return s
}

// Dropped counts the tags an import dropped, by reason.
type Dropped map[Reason]int

// FilterImport returns the tags an import may set: valid, deduplicated, at
// most MaxPerImport, and for which allow (when not nil) is true. Everything
// else is dropped and counted by reason; nothing is stored in a modified
// form except normalization.
func FilterImport(raw []string, allow func(tag string) (Reason, bool)) ([]string, Dropped) {
	var dropped Dropped
	drop := func(r Reason) {
		if dropped == nil {
			dropped = Dropped{}
		}
		dropped[r]++
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		t, why := Check(r)
		if why != "" {
			drop(why)
			continue
		}
		if slices.Contains(out, t) {
			continue
		}
		if allow != nil {
			if why, ok := allow(t); !ok {
				drop(why)
				continue
			}
		}
		if len(out) >= MaxPerImport {
			drop(ReasonOverCap)
			continue
		}
		out = append(out, t)
	}
	return out, dropped
}
