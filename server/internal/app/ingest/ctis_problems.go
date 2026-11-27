package ingest

// The item errors of a segment the CTIS module's validator refused
// (ctis.Report.Validate). Its message lists every problem as
// "<location>: <what is wrong>" ("assets[29]: identity needs
// technical.identity.kind", "tool.techniques[0] \"x\" is invalid") and can
// quote the document, so it never reaches the sensor. What the sensor gets
// per problem is derived from the message's structure only: a JSON pointer
// built from the location (field names and indices, nothing else) and a code
// with its fixed detail. A location that is not a plain path (it quotes a
// value) gives an empty pointer; the cause stays in the server log.

import (
	"regexp"
	"strings"

	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
)

// ctisProblemPrefix starts every message of ctis.Report.Validate.
const ctisProblemPrefix = "invalid CTIS report: "

// maxProblemPointer bounds a derived pointer.
const maxProblemPointer = 256

// ctisPathRe is a location in the validator's notation: lowercase field
// names joined by dots, each with optional [index] suffixes.
var ctisPathRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\[[0-9]+\])*(\.[a-z_][a-z0-9_]*(\[[0-9]+\])*)*$`)

// fieldVerbs follow a field name the validator reports on ("value is
// required", "owners has 3 entries", "ref longer than 64", "asset_ref names
// no asset").
var fieldVerbs = map[string]bool{"is": true, "has": true, "longer": true, "names": true, "must": true, "does": true}

// ctisProblemItems turns the validator's error into item errors: one per
// problem, capped at protov2.MaxItemErrors; an error of another shape gives
// one item with no pointer.
func ctisProblemItems(err error) []protov2.ItemError {
	fallback := []protov2.ItemError{item("", protov2.CodeInvalidValue, protov2.DetailInvalidValue)}
	if err == nil {
		return nil
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, ctisProblemPrefix) {
		return fallback
	}
	var out []protov2.ItemError
	seen := map[string]bool{}
	for _, p := range strings.Split(strings.TrimPrefix(msg, ctisProblemPrefix), "; ") {
		it := ctisProblemItem(p)
		key := it.Pointer + "\x00" + it.Code
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, it)
		if len(out) >= protov2.MaxItemErrors {
			break
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

// ctisProblemItem is the item error of one problem of the message.
func ctisProblemItem(problem string) protov2.ItemError {
	code, detail := ctisProblemCode(problem)
	return item(ctisProblemPointer(problem), code, detail)
}

// ctisProblemCode classifies a problem by the validator's fixed wording.
func ctisProblemCode(problem string) (string, string) {
	switch {
	case strings.Contains(problem, " is required"), strings.Contains(problem, " needs "):
		return protov2.CodeRequired, protov2.DetailRequired
	case strings.Contains(problem, " entries, at most "):
		return protov2.CodeTooMany, protov2.DetailTooManyEntries
	case strings.Contains(problem, " longer than "), strings.Contains(problem, " bytes, at most "):
		return protov2.CodeInvalidValue, protov2.DetailTooLong
	}
	return protov2.CodeInvalidValue, protov2.DetailInvalidValue
}

// ctisProblemPointer is the JSON pointer of a problem's location, refined by
// the field the problem names after a "<location>: " prefix; "" when the
// location is not a plain path.
func ctisProblemPointer(problem string) string {
	loc, rest, colon := cutLocation(problem)
	if !ctisPathRe.MatchString(loc) {
		return ""
	}
	path := loc
	if colon {
		if sub := namedField(rest); sub != "" {
			path += "." + sub
		}
	}
	ptr := ctisPathPointer(path)
	if len(ptr) > maxProblemPointer {
		return ""
	}
	return ptr
}

// cutLocation splits a problem into its leading location and the rest;
// colon reports whether the location ended with ": ".
func cutLocation(problem string) (loc, rest string, colon bool) {
	end := strings.IndexAny(problem, ": ")
	if end < 0 {
		return problem, "", false
	}
	if problem[end] == ':' {
		return problem[:end], strings.TrimPrefix(problem[end+1:], " "), true
	}
	return problem[:end], problem[end+1:], false
}

// namedField is the field the text after a location names, when it names
// one: "<field> is ...", "<field> <value> is ...", "invalid <field> ...", "duplicate id ...",
// "<word> needs <dotted.path>" (and nothing after it).
func namedField(rest string) string {
	words := strings.Fields(rest)
	if len(words) < 2 {
		return ""
	}
	switch {
	case words[0] == "invalid" || words[0] == "duplicate":
		if ctisPathRe.MatchString(words[1]) {
			return words[1]
		}
	case fieldVerbs[words[1]] || quotesValue(words[1]):
		if ctisPathRe.MatchString(words[0]) {
			return words[0]
		}
	case len(words) == 3 && words[1] == "needs" && strings.Contains(words[2], ".") && ctisPathRe.MatchString(words[2]):
		return words[2]
	}
	// "owners[0]: invalid kind" and similar nest one level deeper.
	if loc, more, colon := cutLocation(rest); colon && ctisPathRe.MatchString(loc) {
		if sub := namedField(more); sub != "" {
			return loc + "." + sub
		}
		return loc
	}
	return ""
}

// quotesValue reports whether a word is a value the validator quotes after
// a field name (`asset_ref "b" names ...`, `confidence 120 is ...`).
func quotesValue(w string) bool {
	return w != "" && (w[0] == '"' || w[0] == '-' || (w[0] >= '0' && w[0] <= '9'))
}

// ctisPathPointer converts "assets[29].owners[0].ref" to
// "/assets/29/owners/0/ref". The path matched ctisPathRe, so nothing needs
// escaping.
func ctisPathPointer(path string) string {
	var b strings.Builder
	for _, seg := range strings.Split(path, ".") {
		name, idx, _ := strings.Cut(seg, "[")
		b.WriteString("/" + name)
		if idx == "" {
			continue
		}
		for _, n := range strings.Split(strings.TrimSuffix(idx, "]"), "][") {
			b.WriteString("/" + n)
		}
	}
	return b.String()
}
