package notifymsg

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Var is a template variable. The set is closed: a template naming anything
// else is refused on save, and a stored one that no longer validates is not
// used (the default layout is), so a message never shows raw braces.
type Var string

// The template variables. The severity marker (emoji, color) and the link
// are rendered by the channel, never by a template.
const (
	VarTitle        Var = "title"
	VarSeverity     Var = "severity"
	VarAsset        Var = "asset"
	VarAssetType    Var = "asset_type"
	VarWhat         Var = "what"
	VarWhy          Var = "why"
	VarNextStep     Var = "next_step"
	VarOrganization Var = "organization"
	VarCount        Var = "count"
	VarDescription  Var = "description"
)

// Vars lists the template variables in display order.
func Vars() []Var {
	return []Var{VarTitle, VarSeverity, VarAsset, VarAssetType, VarWhat, VarWhy, VarNextStep,
		VarOrganization, VarCount, VarDescription}
}

func knownVar(name string) bool {
	for _, v := range Vars() {
		if string(v) == name {
			return true
		}
	}
	return false
}

// Template limits.
const (
	MaxTemplateRunes = 2000
	MaxTemplateLines = 20
	maxVarNameRunes  = 40
)

// Template errors. Every validation error wraps ErrInvalidTemplate.
var (
	ErrInvalidTemplate = errors.New("invalid message template")
)

// UnknownVariablesError names the variables a template uses that are not in
// the closed set.
type UnknownVariablesError struct{ Names []string }

func (e *UnknownVariablesError) Error() string {
	return "unknown template variable: " + strings.Join(e.Names, ", ")
}

// Unwrap makes the error an ErrInvalidTemplate.
func (e *UnknownVariablesError) Unwrap() error { return ErrInvalidTemplate }

// Template is a parsed message template: lines of literal text and
// variables.
type Template struct {
	lines [][]segment
}

type segment struct {
	text string
	v    Var // non-empty: a variable
}

// ParseTemplate parses and validates src. `{name}` is a variable, `{{` and
// `}}` are literal braces; anything else with a brace is an error.
func ParseTemplate(src string) (*Template, error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	if !utf8.ValidString(src) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrInvalidTemplate)
	}
	if n := utf8.RuneCountInString(src); n > MaxTemplateRunes {
		return nil, fmt.Errorf("%w: %d characters, at most %d", ErrInvalidTemplate, n, MaxTemplateRunes)
	}
	rawLines := strings.Split(src, "\n")
	if len(rawLines) > MaxTemplateLines {
		return nil, fmt.Errorf("%w: %d lines, at most %d", ErrInvalidTemplate, len(rawLines), MaxTemplateLines)
	}
	unknown := map[string]bool{}
	t := &Template{}
	for _, raw := range rawLines {
		line, err := parseLine(raw, unknown)
		if err != nil {
			return nil, err
		}
		t.lines = append(t.lines, line)
	}
	if len(unknown) > 0 {
		names := make([]string, 0, len(unknown))
		for n := range unknown {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, &UnknownVariablesError{Names: names}
	}
	return t, nil
}

func parseLine(raw string, unknown map[string]bool) ([]segment, error) {
	var segs []segment
	var lit strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '{' && i+1 < len(raw) && raw[i+1] == '{':
			lit.WriteByte('{')
			i++
		case c == '}' && i+1 < len(raw) && raw[i+1] == '}':
			lit.WriteByte('}')
			i++
		case c == '}':
			return nil, fmt.Errorf("%w: unmatched }", ErrInvalidTemplate)
		case c == '{':
			end := strings.IndexByte(raw[i+1:], '}')
			if end < 0 {
				return nil, fmt.Errorf("%w: unclosed {", ErrInvalidTemplate)
			}
			name := raw[i+1 : i+1+end]
			if !validVarName(name) {
				return nil, fmt.Errorf("%w: %q is not a variable name (write {{ for a brace)", ErrInvalidTemplate, "{"+safeName(name)+"}")
			}
			if !knownVar(name) {
				unknown[name] = true
			}
			if lit.Len() > 0 {
				segs = append(segs, segment{text: lit.String()})
				lit.Reset()
			}
			segs = append(segs, segment{v: Var(name)})
			i += end + 1
		default:
			lit.WriteByte(c)
		}
	}
	if lit.Len() > 0 {
		segs = append(segs, segment{text: lit.String()})
	}
	return segs, nil
}

func validVarName(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > maxVarNameRunes {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func safeName(s string) string {
	if utf8.RuneCountInString(s) > maxVarNameRunes {
		r := []rune(s)
		return string(r[:maxVarNameRunes]) + "..."
	}
	return s
}

// ValidateTemplate reports why src cannot be saved (nil: it can). An empty
// template is valid: it means the default layout.
func ValidateTemplate(src string) error {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	_, err := ParseTemplate(src)
	return err
}

// Render fills the variables from vars and returns the lines. A line whose
// variables all rendered empty is dropped (a "Asset: {asset}" line on a
// minimal channel disappears), runs of blank lines collapse to one, and
// blank lines at either end are removed.
func (t *Template) Render(vars map[Var]string) []string {
	out := make([]string, 0, len(t.lines))
	for _, segs := range t.lines {
		var b strings.Builder
		hasVar, anyValue := false, false
		for _, s := range segs {
			if s.v == "" {
				b.WriteString(s.text)
				continue
			}
			hasVar = true
			if v := vars[s.v]; v != "" {
				anyValue = true
				b.WriteString(v)
			}
		}
		if hasVar && !anyValue {
			continue
		}
		line := strings.TrimRight(b.String(), " \t")
		if line == "" && (len(out) == 0 || out[len(out)-1] == "") {
			continue
		}
		out = append(out, line)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// VarsOf is the value of every variable for card c. Values above the
// channel's level are already absent from the card, so a template cannot
// reach them.
func VarsOf(c Card, count int) map[Var]string {
	if count < 1 {
		count = 1
	}
	return map[Var]string{
		VarTitle:        c.Headline,
		VarSeverity:     c.SeverityText(),
		VarAsset:        c.Subject.Name,
		VarAssetType:    strings.ReplaceAll(c.Subject.Type, "_", " "),
		VarWhat:         c.What,
		VarWhy:          c.Why,
		VarNextStep:     c.NextStep,
		VarOrganization: c.Organization,
		VarCount:        fmt.Sprintf("%d", count),
		VarDescription:  c.Description,
	}
}

// ApplyTemplate lays c out with src. An empty template keeps the default
// layout; one that does not validate (stored before the variable set was
// closed) also keeps it, and ok is false so the caller can log it.
func ApplyTemplate(c Card, src string) (Card, bool) {
	if strings.TrimSpace(src) == "" {
		return c, true
	}
	t, err := ParseTemplate(src)
	if err != nil {
		return c, false
	}
	lines := t.Render(VarsOf(c, 1))
	if len(lines) == 0 {
		return c, true
	}
	c.Custom = lines
	return c, true
}
