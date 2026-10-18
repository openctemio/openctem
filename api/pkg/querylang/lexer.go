// Package querylang is the custom query language: a small text language
// for questions over one entity ("findings where state = open | count by
// severity"), compiled to the filterspec AST plus an aggregation pipeline.
//
// Design, grammar, security model and limits:
// docs/architecture/query-language.md and docs/rfcs/RFC-115-custom-query-language.md.
//
// The package is backend-neutral. Parse turns text into a Query (with byte
// positions for the editor); Build checks it against an Entity for one
// Principal and returns a Plan. The Plan carries every rule the server
// injects (tenant, data scope, member visibility, mandatory exclusions,
// field permissions), so an Executor (the Postgres one renders SQL in
// pgsql) cannot run a query without them.
package querylang

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Input limits, checked before any parsing work.
const (
	// MaxQueryBytes bounds the query text.
	MaxQueryBytes = 4096
	// MaxTokens bounds the token count.
	MaxTokens = 512
	// MaxNesting bounds parentheses and "not" chains (the filter itself is
	// limited to filterspec.MaxDepth groups when it is built).
	MaxNesting = 16
	// maxNumberLen bounds a numeric literal.
	maxNumberLen = 24
	// maxRelativeDigits bounds the count of a relative time.
	maxRelativeDigits = 6
)

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokNumber
	tokRelative
	tokOp     // = != > >= < <= ~
	tokLParen // (
	tokRParen // )
	tokComma  // ,
	tokPipe   // |
	tokDot    // .
)

func (k tokKind) String() string {
	switch k {
	case tokEOF:
		return "end of query"
	case tokIdent:
		return "a name"
	case tokString:
		return "a string"
	case tokNumber:
		return "a number"
	case tokRelative:
		return "a relative time"
	case tokOp:
		return "an operator"
	case tokLParen:
		return `"("`
	case tokRParen:
		return `")"`
	case tokComma:
		return `","`
	case tokPipe:
		return `"|"`
	case tokDot:
		return `"."`
	}
	return "a token"
}

// Span is a byte range [Start, End) of the query text.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type token struct {
	kind tokKind
	// text is the token's source text, except for strings, where it is the
	// unescaped value.
	text string
	span Span
}

// lex splits the query into tokens. It never panics on any input and
// stops at the first error.
func lex(src string) ([]token, error) {
	if len(src) > MaxQueryBytes {
		return nil, newError(Span{0, len(src)}, fmt.Sprintf("the query is longer than %d bytes", MaxQueryBytes))
	}
	if !utf8.ValidString(src) {
		return nil, newError(Span{0, len(src)}, "the query is not valid UTF-8")
	}
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
			continue
		case c < 0x20 || c == 0x7f:
			return nil, newError(Span{i, i + 1}, "control characters are not allowed")
		}
		if len(out) >= MaxTokens {
			return nil, newError(Span{i, len(src)}, fmt.Sprintf("the query has more than %d tokens", MaxTokens))
		}
		start := i
		switch {
		case isIdentStart(c):
			for i < len(src) && isIdentPart(src[i]) {
				i++
			}
			out = append(out, token{tokIdent, src[start:i], Span{start, i}})
		case c == '"':
			s, n, err := lexString(src, i)
			if err != nil {
				return nil, err
			}
			i = n
			out = append(out, token{tokString, s, Span{start, i}})
		case isDigit(c):
			n, err := lexNumber(src, i)
			if err != nil {
				return nil, err
			}
			i = n
			out = append(out, token{tokNumber, src[start:i], Span{start, i}})
		case c == '-':
			t, n, err := lexMinus(src, i)
			if err != nil {
				return nil, err
			}
			i = n
			out = append(out, t)
		default:
			t, n, err := lexPunct(src, i)
			if err != nil {
				return nil, err
			}
			i = n
			out = append(out, t)
		}
	}
	out = append(out, token{tokEOF, "", Span{len(src), len(src)}})
	return out, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// lexString reads a double-quoted string starting at src[i] == '"'. The
// only escapes are \" and \\.
func lexString(src string, i int) (string, int, error) {
	start := i
	i++
	var b strings.Builder
	for i < len(src) {
		c := src[i]
		switch {
		case c == '"':
			return b.String(), i + 1, nil
		case c == '\\':
			if i+1 >= len(src) || (src[i+1] != '"' && src[i+1] != '\\') {
				return "", 0, newError(Span{i, min(i+2, len(src))}, `the only escapes in a string are \" and \\`)
			}
			b.WriteByte(src[i+1])
			i += 2
		case c < 0x20 || c == 0x7f:
			return "", 0, newError(Span{i, i + 1}, "control characters are not allowed in a string")
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", 0, newError(Span{start, len(src)}, "unterminated string")
}

// lexNumber reads digits with an optional fraction.
func lexNumber(src string, i int) (int, error) {
	start := i
	for i < len(src) && isDigit(src[i]) {
		i++
	}
	if i+1 < len(src) && src[i] == '.' && isDigit(src[i+1]) {
		i++
		for i < len(src) && isDigit(src[i]) {
			i++
		}
	}
	if i < len(src) && isIdentStart(src[i]) {
		return 0, newError(Span{start, i + 1}, "a number must not be followed by letters (quote dates and versions)")
	}
	if i-start > maxNumberLen {
		return 0, newError(Span{start, i}, "number too long")
	}
	return i, nil
}

// lexMinus reads a negative number ("-1.5") or a relative time ("-14d").
func lexMinus(src string, i int) (token, int, error) {
	start := i
	i++
	if i >= len(src) || !isDigit(src[i]) {
		return token{}, 0, newError(Span{start, i}, `"-" must start a number or a relative time such as -14d`)
	}
	ds := i
	for i < len(src) && isDigit(src[i]) {
		i++
	}
	if i < len(src) && isIdentStart(src[i]) {
		us := i
		for i < len(src) && isIdentPart(src[i]) {
			i++
		}
		if _, ok := relativeUnits[src[us:i]]; !ok {
			return token{}, 0, newError(Span{start, i}, "a relative time ends in h, d, w, mo or y")
		}
		if us-ds > maxRelativeDigits {
			return token{}, 0, newError(Span{start, i}, "relative time too long")
		}
		return token{tokRelative, src[start:i], Span{start, i}}, i, nil
	}
	n, err := lexNumber(src, ds)
	if err != nil {
		return token{}, 0, err
	}
	return token{tokNumber, src[start:n], Span{start, n}}, n, nil
}

// relativeUnits maps a relative-time unit to its ISO 8601 form: the
// designator and the multiplier of the count.
var relativeUnits = map[string]struct {
	time bool
	des  string
	mul  int
}{
	"h":  {true, "H", 1},
	"d":  {false, "D", 1},
	"w":  {false, "W", 1},
	"mo": {false, "D", 30},
	"y":  {false, "D", 365},
}

// punct maps one-character tokens to their kinds.
var punct = map[byte]tokKind{'=': tokOp, '~': tokOp, '(': tokLParen, ')': tokRParen, ',': tokComma, '|': tokPipe, '.': tokDot}

// lexPunct reads an operator or punctuation token at src[i].
func lexPunct(src string, i int) (token, int, error) {
	start, c := i, src[i]
	if c == '!' || c == '>' || c == '<' {
		i++
		if i < len(src) && src[i] == '=' {
			i++
		} else if c == '!' {
			return token{}, 0, newError(Span{start, i}, `"!" must be followed by "=" (use "not" to negate)`)
		}
		return token{tokOp, src[start:i], Span{start, i}}, i, nil
	}
	if k, ok := punct[c]; ok {
		return token{k, src[start : i+1], Span{start, i + 1}}, i + 1, nil
	}
	_, size := utf8.DecodeRuneInString(src[i:])
	return token{}, 0, newError(Span{i, i + size}, "unexpected character")
}
