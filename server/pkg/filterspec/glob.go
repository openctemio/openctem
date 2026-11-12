package filterspec

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// Name patterns ("*.example.com", "api-*", "db?.corp"): the glob syntax of
// the asset_name filter. A pattern is translated to an ILIKE pattern with
// every LIKE metacharacter of the input escaped, never to a regular
// expression, so a pattern cannot run away (no backtracking) and cannot
// inject a wildcard the person did not type.

// Glob limits.
const (
	// MaxGlobLen caps a pattern's length in bytes.
	MaxGlobLen = 200
	// MaxGlobWildcards caps the '*' and '?' of one pattern.
	MaxGlobWildcards = 3
	// minGlobLiteralRun is the shortest run of literal characters a pattern
	// must have, so the trigram index on the name can serve it.
	minGlobLiteralRun = 3
)

var (
	errGlobEmpty    = errors.New("pattern is empty")
	errGlobLong     = errors.New("pattern is longer than 200 characters")
	errGlobWild     = errors.New("pattern has more than 3 wildcards")
	errGlobLiteral  = errors.New("pattern needs at least 3 characters in a row that are not wildcards")
	errGlobBadBytes = errors.New("pattern has invalid characters")
)

// NormalizeGlob checks a name pattern and returns it trimmed and lower-cased
// (matching is case-insensitive). '*' is any run of characters, '?' exactly
// one; everything else is literal.
func NormalizeGlob(p string) (string, error) {
	p = strings.ToLower(strings.TrimSpace(p))
	switch {
	case p == "":
		return "", errGlobEmpty
	case len(p) > MaxGlobLen:
		return "", errGlobLong
	case !utf8.ValidString(p):
		return "", errGlobBadBytes
	}
	wild, run, best := 0, 0, 0
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", errGlobBadBytes
		}
		if r == '*' || r == '?' {
			wild++
			run = 0
			continue
		}
		run++
		best = max(best, run)
	}
	if wild > MaxGlobWildcards {
		return "", errGlobWild
	}
	if best < minGlobLiteralRun {
		return "", errGlobLiteral
	}
	return p, nil
}

// GlobToLike translates a pattern NormalizeGlob accepted into a LIKE
// pattern for the default escape character '\': literal '\', '%' and '_'
// are escaped, '*' becomes '%' and '?' becomes '_'.
func GlobToLike(p string) string {
	var b strings.Builder
	b.Grow(len(p) + 8)
	for _, r := range p {
		switch r {
		case '*':
			b.WriteByte('%')
		case '?':
			b.WriteByte('_')
		case '\\', '%', '_':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
