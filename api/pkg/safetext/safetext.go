// Package safetext encodes untrusted text (finding titles and descriptions,
// file paths, hostnames: anything a scan target or a sensor can influence)
// for the places the platform writes it outside its own console: Jira wiki
// markup, GitHub-flavored markdown and plain-text ticket titles.
//
// Each format gets its own encoder, because each has its own control syntax:
// a value safe in markdown can still inject a link or a macro into Jira wiki
// markup. Every encoder first runs Clean, which removes the characters that
// make text display differently from what it is (Trojan Source), so an
// analyst reading the ticket sees the bytes the scanner sent.
//
// Design: RFC-040 (platform/sensor mutual distrust), section 5.4.
package safetext

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Length caps for ticket fields. Jira caps a summary at 255 characters and a
// description at 32,767; GitHub caps a title at 256 and a body at 65,536.
const (
	MaxTitleRunes       = 240
	MaxInlineRunes      = 1024
	MaxDescriptionRunes = 16000
)

// ellipsis marks text cut by a length cap.
const ellipsis = "…"

// isInvisibleControl reports runes that are removed from untrusted text:
// C0 controls except tab and newline, DEL and C1 controls, bidirectional
// embedding/override/isolate controls and marks (Trojan Source), and
// zero-width characters that hide content. ZWJ/ZWNJ are kept: scripts and
// emoji need them.
func isInvisibleControl(r rune) bool {
	switch {
	case r == '\t' || r == '\n':
		return false
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, // LRE RLE PDF LRO RLO
		r >= 0x2066 && r <= 0x2069,            // LRI RLI FSI PDI
		r == 0x200e, r == 0x200f, r == 0x061c, // LRM RLM ALM
		r == 0x200b, r == 0x2060, r == 0xfeff: // ZWSP, word joiner, BOM
		return true
	}
	return false
}

// Clean returns s as valid UTF-8 without NUL, control, bidi-control or
// zero-width characters. CR and CRLF become LF.
func Clean(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.Map(func(r rune) rune {
		if isInvisibleControl(r) {
			return -1
		}
		return r
	}, s)
}

// Truncate cuts s to at most maxRunes runes, ending in "…" when it cut.
func Truncate(s string, maxRunes int) string {
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes-1]) + ellipsis
}

// SingleLine cleans s, folds every run of whitespace (including newlines) into
// one space and caps the length. Use it for titles and other one-line fields
// that the receiving system shows as plain text (Jira summary, GitHub title).
func SingleLine(s string, maxRunes int) string {
	return Truncate(strings.Join(strings.Fields(Clean(s)), " "), maxRunes)
}

// urlSchemeRE matches the scheme separator of an absolute URL.
var urlSchemeRE = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*)://`)

// mailtoRE matches mailto:, which Jira and GitHub both turn into links.
var mailtoRE = regexp.MustCompile(`(?i)\bmailto:`)

// Defang makes URLs in s non-clickable while keeping them readable:
// "https://evil.test/x" becomes "https[:]//evil.test/x". Ticketing systems
// auto-link bare URLs; a URL that came from a scan target must not become a
// link an engineer clicks from their tracker.
func Defang(s string) string {
	s = urlSchemeRE.ReplaceAllString(s, "${1}[:]//")
	return mailtoRE.ReplaceAllString(s, "mailto[:]")
}

// jiraWikiEscaper backslash-escapes the characters Jira wiki markup gives a
// meaning: macros {…}, links and mentions […|…] / [~user], tables |, images
// !…!, text effects * _ ^ ~ + - ?? and lists/headings # at line start.
var jiraWikiEscaper = strings.NewReplacer(
	`\`, `\\`,
	`{`, `\{`, `}`, `\}`,
	`[`, `\[`, `]`, `\]`,
	`|`, `\|`,
	`!`, `\!`,
	`*`, `\*`,
	`_`, `\_`,
	`^`, `\^`,
	`~`, `\~`,
	`+`, `\+`,
	`-`, `\-`,
	`?`, `\?`,
	`#`, `\#`,
)

// JiraWikiInline encodes s for one line of Jira wiki markup (API v2
// descriptions and comments): cleaned, folded to one line, URLs defanged,
// every markup character escaped, capped at maxRunes.
func JiraWikiInline(s string, maxRunes int) string {
	return jiraWikiEscaper.Replace(Defang(SingleLine(s, maxRunes)))
}

// noformatTagRE matches a {noformat} tag in any case, so untrusted text
// cannot close the block it is placed in.
var noformatTagRE = regexp.MustCompile(`(?i)\{\s*noformat`)

// JiraWikiBlock encodes multi-line untrusted text for Jira wiki markup as a
// {noformat} block, inside which Jira renders no markup, macros or links.
// The text is cleaned and capped, any {noformat} inside it is broken, and
// URLs are defanged in case a renderer auto-links inside the block.
func JiraWikiBlock(s string, maxRunes int) string {
	body := Truncate(strings.TrimSpace(Clean(s)), maxRunes)
	body = noformatTagRE.ReplaceAllString(body, "(noformat")
	body = Defang(body)
	return "{noformat}\n" + body + "\n{noformat}"
}

// longestBacktickRun returns the length of the longest run of '`' in s.
func longestBacktickRun(s string) int {
	longest, cur := 0, 0
	for _, r := range s {
		if r == '`' {
			cur++
			if cur > longest {
				longest = cur
			}
			continue
		}
		cur = 0
	}
	return longest
}

// MarkdownInline encodes s as a markdown code span. Inside a code span
// GitHub/GitLab render no emphasis, links, images, HTML, @mentions or #refs.
// The fence is longer than any backtick run in s, so s cannot close it.
func MarkdownInline(s string, maxRunes int) string {
	text := SingleLine(s, maxRunes)
	if text == "" {
		return ""
	}
	fence := strings.Repeat("`", longestBacktickRun(text)+1)
	return fence + " " + text + " " + fence
}

// MarkdownBlock encodes multi-line untrusted text as a fenced markdown code
// block: no markup, links, images, HTML or mentions are rendered inside it.
// The fence is longer than any backtick run in the text (at least three), so
// the text cannot close the block early.
func MarkdownBlock(s string, maxRunes int) string {
	body := Truncate(strings.TrimSpace(Clean(s)), maxRunes)
	n := longestBacktickRun(body) + 1
	if n < 3 {
		n = 3
	}
	fence := strings.Repeat("`", n)
	return fence + "text\n" + body + "\n" + fence
}
