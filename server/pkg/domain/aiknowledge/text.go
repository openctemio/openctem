package aiknowledge

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits.
const (
	// MaxDocumentBytes bounds one document version.
	MaxDocumentBytes = 256 * 1024
	// MaxChunks bounds the chunks of one document version.
	MaxChunks = 400
	// ChunkTarget is the size a chunk is filled to, in runes.
	ChunkTarget = 1200
	// maxChunkRunes is the hard cap of one chunk body.
	maxChunkRunes = 1500
	// MaxTerms bounds the terms of a search query.
	MaxTerms      = 16
	maxTermRunes  = 64
	maxTitleRunes = 300
)

// Terms splits a query into at most MaxTerms distinct lower-case terms of
// letters and digits (inner '-', '.', '_' kept, so a CVE id or a host pattern
// stays one term). Leading signs and quotes are dropped, so a term is never a
// negation or a phrase, and the word "or" is dropped, so a term is never an
// operator.
func Terms(query string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, MaxTerms)
	for _, f := range strings.FieldsFunc(query, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '_')
	}) {
		t := strings.ToLower(strings.Trim(f, "-._"))
		if utf8.RuneCountInString(t) < 2 || t == "or" || seen[t] {
			continue
		}
		if utf8.RuneCountInString(t) > maxTermRunes {
			t = string([]rune(t)[:maxTermRunes])
		}
		seen[t] = true
		out = append(out, t)
		if len(out) == MaxTerms {
			break
		}
	}
	return out
}

// Normalize makes stored text safe and stable: valid UTF-8, no control
// characters except newlines and tabs, Windows line ends unified, runs of
// blank lines collapsed, trimmed.
func Normalize(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var b strings.Builder
	b.Grow(len(s))
	newlines := 0
	for _, r := range s {
		switch {
		case r == '\n':
			newlines++
			if newlines <= 2 {
				b.WriteRune(r)
			}
			continue
		case r == '\t':
		case unicode.IsControl(r), r == '\u2028', r == '\u2029', r == '\ufeff':
			continue
		case unicode.Is(unicode.Cf, r):
			// Format characters (zero-width, bidi overrides) can hide text
			// from a reviewer while a model still reads it.
			continue
		}
		newlines = 0
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// Split cuts normalized Markdown or plain text into chunks: a new chunk at
// every heading (the heading path is the chunk title), filled with whole
// paragraphs up to ChunkTarget runes; a longer paragraph is cut at a space.
// It returns at most MaxChunks chunks and false when the text needs more.
func Split(text string) ([]Chunk, bool) {
	var out []Chunk
	var path []string
	var cur strings.Builder
	title := func() string {
		t := strings.Join(path, " > ")
		if utf8.RuneCountInString(t) > maxTitleRunes {
			t = string([]rune(t)[:maxTitleRunes])
		}
		return t
	}
	flush := func() {
		body := strings.TrimSpace(cur.String())
		cur.Reset()
		if body != "" {
			out = append(out, Chunk{Ordinal: len(out), Title: title(), Body: body})
		}
	}
	add := func(p string) {
		for utf8.RuneCountInString(p) > maxChunkRunes {
			head, rest := cutAtSpace(p, ChunkTarget)
			flush()
			cur.WriteString(head)
			flush()
			p = rest
		}
		if cur.Len() > 0 && utf8.RuneCountInString(cur.String())+utf8.RuneCountInString(p) > ChunkTarget {
			flush()
		}
		if cur.Len() > 0 {
			cur.WriteString("\n\n")
		}
		cur.WriteString(p)
	}
	for _, para := range strings.Split(text, "\n\n") {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}
		// A heading line starts a section; text under it in the same
		// paragraph stays with it.
		if level, h, rest, ok := heading(para); ok {
			flush()
			if level <= len(path) {
				path = path[:level-1]
			}
			for len(path) < level-1 {
				path = append(path, "")
			}
			path = append(path, h)
			if rest == "" {
				continue
			}
			para = rest
		}
		add(para)
		if len(out) > MaxChunks {
			return out[:MaxChunks], false
		}
	}
	flush()
	if len(out) > MaxChunks {
		return out[:MaxChunks], false
	}
	return out, true
}

func heading(para string) (int, string, string, bool) {
	line, rest, _ := strings.Cut(para, "\n")
	level := 0
	for level < len(line) && level < 6 && line[level] == '#' {
		level++
	}
	if level == 0 || level >= len(line) || line[level] != ' ' {
		return 0, "", "", false
	}
	h := strings.TrimSpace(strings.Trim(strings.TrimSpace(line[level:]), "#"))
	if h == "" {
		return 0, "", "", false
	}
	return level, h, strings.TrimSpace(rest), true
}

// cutAtSpace cuts s after about n runes, at the last space before it when
// there is one in the second half.
func cutAtSpace(s string, n int) (string, string) {
	r := []rune(s)
	if len(r) <= n {
		return s, ""
	}
	cut := n
	for i := n; i > n/2; i-- {
		if unicode.IsSpace(r[i]) {
			cut = i
			break
		}
	}
	return strings.TrimSpace(string(r[:cut])), strings.TrimSpace(string(r[cut:]))
}
