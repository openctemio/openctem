package template

import (
	"fmt"
	"regexp/syntax"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Opengrep evaluates rule regexes with a backtracking (PCRE-style) engine,
// so a pattern that Go's linear engine runs safely can still pin a sensor
// core. checkBacktrackingRegex is a small static analyser over the parse
// tree. It rejects:
//   - backreferences,
//   - an unbounded quantifier at the edge of a repeated body that can also
//     match what the previous iteration ended with (or starts with), such
//     as (a+)+ or (.*a){10},
//   - overlapping alternation under a repeat, such as (a|a)* or (a|ab)+,
//   - patterns longer than maxOpengrepRegexLen.
//
// Delimited repeats such as (\w+,)* or (\d{1,3}\.){3} are accepted.

const maxOpengrepRegexLen = 1000

// unboundedMin is the inner repeat maximum from which a bounded repeat is
// treated like an unbounded one.
const unboundedMin = 10

type runeSet [][2]rune

func (s runeSet) overlaps(o runeSet) bool {
	for _, a := range s {
		for _, b := range o {
			if a[0] <= b[1] && b[0] <= a[1] {
				return true
			}
		}
	}
	return false
}

func anyOverlap(sets []runeSet, o runeSet) bool {
	for _, s := range sets {
		if s.overlaps(o) {
			return true
		}
	}
	return false
}

func unionSets(sets []runeSet) runeSet {
	var u runeSet
	for _, s := range sets {
		u = append(u, s...)
	}
	return u
}

// normalizePCRE rewrites PCRE-only syntax that cannot change the matching
// cost class into Go syntax so the pattern can be parsed. It reports whether
// the pattern uses a backreference.
func normalizePCRE(p string) (string, bool) {
	var b strings.Builder
	inClass := false
	prevQuant := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			n := p[i+1]
			switch {
			case n >= '1' && n <= '9':
				return "", true
			case n == 'g' || n == 'k':
				if !inClass {
					return "", true
				}
			}
			if !inClass {
				switch n {
				case 'h':
					b.WriteString(`[ \t]`)
					i++
					prevQuant = false
					continue
				case 'K', 'G':
					i++
					continue
				case 'R':
					b.WriteString(`\n`)
					i++
					prevQuant = false
					continue
				case 'Z':
					b.WriteString(`\z`)
					i++
					prevQuant = false
					continue
				}
			}
			b.WriteByte(c)
			b.WriteByte(n)
			i++
			prevQuant = false
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '[':
			inClass = true
			b.WriteByte(c)
			// a leading ] or ^] is a literal
			if i+1 < len(p) && p[i+1] == '^' {
				b.WriteByte('^')
				i++
			}
			if i+1 < len(p) && p[i+1] == ']' {
				b.WriteString(`\]`)
				i++
			}
			prevQuant = false
		case '(':
			rest := p[i:]
			switch {
			case strings.HasPrefix(rest, "(?P="):
				return "", true
			case strings.HasPrefix(rest, "(?<=") || strings.HasPrefix(rest, "(?<!"):
				b.WriteString("(?:")
				i += 3
			case strings.HasPrefix(rest, "(?=") || strings.HasPrefix(rest, "(?!") || strings.HasPrefix(rest, "(?>"):
				b.WriteString("(?:")
				i += 2
			default:
				b.WriteByte(c)
			}
			prevQuant = false
		case '*', '+', '?', '}':
			if c == '+' && prevQuant {
				// possessive quantifier: never backtracks, same match set
				prevQuant = false
				continue
			}
			b.WriteByte(c)
			prevQuant = true
		default:
			b.WriteByte(c)
			prevQuant = false
		}
	}
	return b.String(), false
}

func nodeSet(n *syntax.Regexp) runeSet {
	switch n.Op {
	case syntax.OpLiteral:
		if len(n.Rune) == 0 {
			return nil
		}
		var s runeSet
		r := n.Rune[0]
		s = append(s, [2]rune{r, r})
		if n.Flags&syntax.FoldCase != 0 {
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				s = append(s, [2]rune{f, f})
			}
		}
		return s
	case syntax.OpCharClass:
		var s runeSet
		for i := 0; i+1 < len(n.Rune); i += 2 {
			s = append(s, [2]rune{n.Rune[i], n.Rune[i+1]})
		}
		return s
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return runeSet{{0, unicode.MaxRune}}
	}
	return nil
}

func nullable(n *syntax.Regexp) bool {
	switch n.Op {
	case syntax.OpEmptyMatch, syntax.OpStar, syntax.OpQuest,
		syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	case syntax.OpRepeat:
		return n.Min == 0 || nullable(n.Sub[0])
	case syntax.OpPlus, syntax.OpCapture:
		return nullable(n.Sub[0])
	case syntax.OpConcat:
		for _, s := range n.Sub {
			if !nullable(s) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, s := range n.Sub {
			if nullable(s) {
				return true
			}
		}
		return false
	}
	return false
}

// edgeSet returns the characters that can appear first (or last) in n.
func edgeSet(n *syntax.Regexp, first bool) runeSet {
	switch n.Op {
	case syntax.OpLiteral:
		if len(n.Rune) == 0 {
			return nil
		}
		lit := *n
		if first {
			lit.Rune = n.Rune[:1]
		} else {
			lit.Rune = n.Rune[len(n.Rune)-1:]
		}
		return nodeSet(&lit)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return nodeSet(n)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat, syntax.OpCapture:
		return edgeSet(n.Sub[0], first)
	case syntax.OpAlternate:
		var all []runeSet
		for _, s := range n.Sub {
			all = append(all, edgeSet(s, first))
		}
		return unionSets(all)
	case syntax.OpConcat:
		var all []runeSet
		idx := func(i int) int {
			if first {
				return i
			}
			return len(n.Sub) - 1 - i
		}
		for i := range n.Sub {
			c := n.Sub[idx(i)]
			all = append(all, edgeSet(c, first))
			if !nullable(c) {
				break
			}
		}
		return unionSets(all)
	}
	return nil
}

func isUnboundedRep(n *syntax.Regexp) bool {
	switch n.Op {
	case syntax.OpStar, syntax.OpPlus:
		return true
	case syntax.OpRepeat:
		return n.Max < 0 || n.Max >= unboundedMin
	}
	return false
}

// edgeRepeats collects the character sets of unbounded repeats found at the
// start (or end) of n, looking through nullable neighbours.
func edgeRepeats(n *syntax.Regexp, first bool) []runeSet {
	switch n.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		var out []runeSet
		if isUnboundedRep(n) {
			out = append(out, edgeSet(n.Sub[0], true), edgeSet(n.Sub[0], false))
		}
		return append(out, edgeRepeats(n.Sub[0], first)...)
	case syntax.OpQuest, syntax.OpCapture:
		return edgeRepeats(n.Sub[0], first)
	case syntax.OpAlternate:
		var out []runeSet
		for _, s := range n.Sub {
			out = append(out, edgeRepeats(s, first)...)
		}
		return out
	case syntax.OpConcat:
		var out []runeSet
		for i := range n.Sub {
			c := n.Sub[i]
			if !first {
				c = n.Sub[len(n.Sub)-1-i]
			}
			out = append(out, edgeRepeats(c, first)...)
			if !nullable(c) {
				break
			}
		}
		return out
	}
	return nil
}

func repeatsManyTimes(n *syntax.Regexp) bool {
	switch n.Op {
	case syntax.OpStar, syntax.OpPlus:
		return true
	case syntax.OpRepeat:
		return n.Max < 0 || n.Max > 1
	}
	return false
}

func walkBacktracking(n *syntax.Regexp) string {
	if repeatsManyTimes(n) {
		body := n.Sub[0]
		first, last := edgeSet(body, true), edgeSet(body, false)
		// An unbounded repeat at the start of the body can re-split text that
		// the previous iteration's tail also matches (and the reverse).
		if anyOverlap(edgeRepeats(body, true), last) || anyOverlap(edgeRepeats(body, false), first) {
			return "nested quantifiers that can match the same text (catastrophic backtracking)"
		}
		if body.Op == syntax.OpStar || body.Op == syntax.OpPlus ||
			(body.Op == syntax.OpRepeat && isUnboundedRep(body)) {
			return "nested quantifiers (catastrophic backtracking)"
		}
	}
	for _, s := range n.Sub {
		if why := walkBacktracking(s); why != "" {
			return why
		}
	}
	return ""
}

// altUnderRepeat finds quantified groups whose alternatives can start with
// the same character. Go's parser factors common prefixes out of an
// alternation, so this reads the pattern text instead of the tree.
func altUnderRepeat(p string) string {
	type frame struct {
		start int
		alts  []int
		skip  bool
	}
	var stack []frame
	inClass := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' {
			i++
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			continue
		}
		switch c {
		case '[':
			inClass = true
			if i+1 < len(p) && p[i+1] == '^' {
				i++
			}
			if i+1 < len(p) && p[i+1] == ']' {
				i++
			}
		case '(':
			rest := p[i:]
			skip := strings.HasPrefix(rest, "(?=") || strings.HasPrefix(rest, "(?!") ||
				strings.HasPrefix(rest, "(?<=") || strings.HasPrefix(rest, "(?<!")
			stack = append(stack, frame{start: i, skip: skip})
		case '|':
			if len(stack) > 0 {
				stack[len(stack)-1].alts = append(stack[len(stack)-1].alts, i)
			}
		case ')':
			if len(stack) == 0 {
				continue
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if f.skip || len(f.alts) == 0 || !quantifiedMany(p[i+1:]) {
				continue
			}
			if why := overlappingBranches(p, f.start, i, f.alts); why != "" {
				return why
			}
		}
	}
	return ""
}

func quantifiedMany(rest string) bool {
	if rest == "" {
		return false
	}
	switch rest[0] {
	case '*', '+':
		return true
	case '{':
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return false
		}
		body := rest[1:end]
		if !strings.Contains(body, ",") {
			return body != "0" && body != "1" && body != ""
		}
		return !strings.HasSuffix(body, ",0") && !strings.HasSuffix(body, ",1")
	}
	return false
}

func overlappingBranches(p string, start, end int, alts []int) string {
	// body starts after the group opener, which may be (?:, (?<n>, (?P<n>
	bodyStart := start + 1
	if strings.HasPrefix(p[start:], "(?") {
		if j := strings.IndexAny(p[start:], ":>"); j > 0 && j < 40 {
			bodyStart = start + j + 1
		}
	}
	bounds := append([]int{bodyStart - 1}, alts...)
	bounds = append(bounds, end)
	var sets []runeSet
	var lits []string // literal text of each branch, "" when not a pure literal
	for k := 0; k+1 < len(bounds); k++ {
		lo, hi := bounds[k]+1, bounds[k+1]
		if lo < bodyStart {
			lo = bodyStart
		}
		if lo >= hi {
			continue
		}
		norm, backref := normalizePCRE(p[lo:hi])
		if backref {
			continue
		}
		re, err := syntax.Parse(norm, syntax.Perl)
		if err != nil || nullable(re) {
			continue
		}
		sets = append(sets, edgeSet(re, true))
		lit := ""
		if re.Op == syntax.OpLiteral && re.Flags&syntax.FoldCase == 0 {
			lit = string(re.Rune)
		}
		lits = append(lits, lit)
	}
	for i := range sets {
		for j := i + 1; j < len(sets); j++ {
			if lits[i] != "" && lits[j] != "" {
				// distinct words sharing a first letter (foo|far) do not
				// backtrack; only one being a prefix of the other does
				if strings.HasPrefix(lits[i], lits[j]) || strings.HasPrefix(lits[j], lits[i]) {
					return "alternatives that can match the same text under a repeat (catastrophic backtracking)"
				}
				continue
			}
			if sets[i].overlaps(sets[j]) {
				return "alternatives that can match the same text under a repeat (catastrophic backtracking)"
			}
		}
	}
	return ""
}

// checkBacktrackingRegex reports why a regex is unsafe for a backtracking
// engine, or "" when it is acceptable.
func checkBacktrackingRegex(p string) string {
	if len(p) > maxOpengrepRegexLen {
		return fmt.Sprintf("pattern too long (%d > %d)", len(p), maxOpengrepRegexLen)
	}
	norm, backref := normalizePCRE(p)
	if backref {
		return "backreferences are not allowed (catastrophic backtracking)"
	}
	re, err := syntax.Parse(norm, syntax.Perl)
	if err != nil {
		return fmt.Sprintf("regex could not be analysed: %v", err)
	}
	if why := walkBacktracking(re); why != "" {
		return why
	}
	return altUnderRepeat(p)
}

// opengrepRegexKeys are the rule keys whose value is a regex string, and the
// keys whose mapping holds one in its "regex" field.
var opengrepRegexKeys = map[string]bool{"pattern-regex": true, "pattern-not-regex": true}
var opengrepRegexMapKeys = map[string]bool{"metavariable-regex": true, "fix-regex": true}

// validateOpengrepRegexes walks the rule YAML for every regex field and
// reports unsafe ones with the field path and line.
func validateOpengrepRegexes(content []byte, result *ValidationResult) {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil || len(doc.Content) == 0 {
		return
	}
	var walk func(n *yaml.Node, path string)
	check := func(v *yaml.Node, path string) {
		if v.Kind != yaml.ScalarNode {
			return
		}
		if why := checkBacktrackingRegex(v.Value); why != "" {
			result.AddError(path, fmt.Sprintf("unsafe regex at line %d: %s", v.Line, why), "UNSAFE_REGEX")
		}
	}
	walk = func(n *yaml.Node, path string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, path)
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				walk(c, fmt.Sprintf("%s[%d]", path, i))
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i].Value, n.Content[i+1]
				sub := path + "." + k
				if path == "" {
					sub = k
				}
				switch {
				case opengrepRegexKeys[k]:
					check(v, sub)
				case opengrepRegexMapKeys[k] && v.Kind == yaml.MappingNode:
					for j := 0; j+1 < len(v.Content); j += 2 {
						if v.Content[j].Value == "regex" {
							check(v.Content[j+1], sub+".regex")
						}
					}
				default:
					walk(v, sub)
				}
			}
		}
	}
	walk(&doc, "")
}
