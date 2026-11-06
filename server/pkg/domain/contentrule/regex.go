package contentrule

import (
	"fmt"
	"regexp"
	"regexp/syntax"
)

// Pattern bounds. Patterns use RE2 semantics (Go regexp): matching is
// linear in the input, there are no backreferences or lookaround, so
// catastrophic backtracking cannot happen. What remains is cost by size,
// which these bounds cap.
const (
	MaxPatternLen = 512
	// MaxProgramInsts bounds the compiled program, the per-byte work.
	MaxProgramInsts = 4000
	MaxGroups       = 8
	MaxRepeat       = 256
)

// Named groups a pattern may use.
const (
	GroupVersion = "version"
	GroupSecret  = "secret"
)

// CheckPattern reports why pattern cannot be used, or nil.
func CheckPattern(pattern string) error {
	if len(pattern) > MaxPatternLen {
		return fmt.Errorf("%w: pattern is longer than %d bytes", ErrInvalid, MaxPatternLen)
	}
	if !cleanString(pattern, MaxPatternLen) {
		return fmt.Errorf("%w: pattern has control characters", ErrInvalid)
	}
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return fmt.Errorf("%w: pattern is not RE2 syntax (%s)", ErrInvalid, syntaxCode(err))
	}
	if r := maxRepeat(re); r > MaxRepeat {
		return fmt.Errorf("%w: pattern repeats more than %d times", ErrInvalid, MaxRepeat)
	}
	if re.MaxCap() > MaxGroups {
		return fmt.Errorf("%w: pattern has more than %d groups", ErrInvalid, MaxGroups)
	}
	for _, n := range re.CapNames() {
		if n != "" && n != GroupVersion && n != GroupSecret {
			return fmt.Errorf("%w: named groups are %q or %q only", ErrInvalid, GroupVersion, GroupSecret)
		}
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return fmt.Errorf("%w: pattern does not compile", ErrInvalid)
	}
	if len(prog.Inst) > MaxProgramInsts {
		return fmt.Errorf("%w: pattern is too complex (%d steps, at most %d)", ErrInvalid, len(prog.Inst), MaxProgramInsts)
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("%w: pattern does not compile", ErrInvalid)
	}
	if compiled.MatchString("") {
		return fmt.Errorf("%w: pattern matches empty text; it must require at least one character", ErrInvalid)
	}
	return nil
}

// maxRepeat is the largest repeat bound in re ({n,m}: max(n,m)).
func maxRepeat(re *syntax.Regexp) int {
	m := 0
	if re.Op == syntax.OpRepeat {
		m = max(re.Min, re.Max)
	}
	for _, s := range re.Sub {
		m = max(m, maxRepeat(s))
	}
	return m
}

// syntaxCode is the parser's error code, without the pattern text.
func syntaxCode(err error) string {
	if se, ok := err.(*syntax.Error); ok { //nolint:errorlint // syntax.Parse returns *syntax.Error unwrapped
		return string(se.Code)
	}
	return "invalid"
}
