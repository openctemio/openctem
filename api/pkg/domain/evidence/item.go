// Package evidence is the typed proof attached to a finding: what a tool sent
// and received when it detected (or re-checked) an issue. Design:
// docs/architecture/finding-evidence.md.
//
// An Item is tool-agnostic. Known kinds (http_exchange, raw_text, screenshot,
// file_excerpt, command_output, curl) have a typed body; any other kind is
// kept as generic text, never rejected. Every item is normalized (caps,
// valid UTF-8, no control characters that matter for display) and masked
// (Mask) before it is stored: secret values move to a separate, encrypted
// store and are replaced by placeholders such as «secret:authorization#1».
package evidence

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Known evidence kinds.
const (
	KindHTTPExchange  = "http_exchange"
	KindRawText       = "raw_text"
	KindScreenshot    = "screenshot"
	KindFileExcerpt   = "file_excerpt"
	KindCommandOutput = "command_output"
	KindCurl          = "curl"
)

// Caps. They are enforced on every item the platform stores, whatever the
// tool claims to have enforced.
const (
	MaxBodyBytes      = 64 << 10 // one request or response body
	MaxTextBytes      = 64 << 10 // text / snippet
	MaxHeaders        = 100
	MaxHeaderValue    = 8 << 10
	MaxHeaderName     = 256
	MaxHeaderBytes    = 32 << 10 // all header values of one message
	MaxURLBytes       = 8 << 10
	MaxLabel          = 200
	MaxExtracted      = 20
	MaxExtractedBytes = 1 << 10
	MaxMatches        = 20
	MaxSensitive      = 200
	MaxItemsPerReport = 20 // per finding, per report
	MaxItemsPerRetest = 5  // per retest attempt
	// MaxItemBytes bounds one normalized item serialized (the DB CHECK is a
	// little higher to leave room for JSON escaping differences).
	MaxItemBytes = 256 << 10
	// matchWindowBefore is how much of a too-long body is kept before the
	// first match; the rest of the budget goes after it.
	matchWindowBefore = 16 << 10
	truncMarker       = "\n…[truncated]"
)

// Match locations, parts and the binary body encoding.
const (
	locRequest  = "request"
	locResponse = "response"
	partBody    = "body"
	encBase64   = "base64"
)

var kindPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Header is one HTTP header, in order.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HTTPRequest is the request half of an exchange.
type HTTPRequest struct {
	Method        string   `json:"method,omitempty"`
	URL           string   `json:"url,omitempty"`
	HTTPVersion   string   `json:"http_version,omitempty"`
	Headers       []Header `json:"headers,omitempty"`
	Body          string   `json:"body,omitempty"`
	BodyEncoding  string   `json:"body_encoding,omitempty"` // text (default) | base64
	BodyTruncated bool     `json:"body_truncated,omitempty"`
	BodySize      int      `json:"body_size,omitempty"`
}

// HTTPResponse is the response half of an exchange.
type HTTPResponse struct {
	Status        int      `json:"status,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	HTTPVersion   string   `json:"http_version,omitempty"`
	Headers       []Header `json:"headers,omitempty"`
	Body          string   `json:"body,omitempty"`
	BodyEncoding  string   `json:"body_encoding,omitempty"`
	BodyTruncated bool     `json:"body_truncated,omitempty"`
	BodySize      int      `json:"body_size,omitempty"`
	TimeMS        int      `json:"time_ms,omitempty"`
}

// HTTP is an http_exchange body.
type HTTP struct {
	Request  *HTTPRequest  `json:"request,omitempty"`
	Response *HTTPResponse `json:"response,omitempty"`
}

// Match says where the check matched: a byte range of one part of the
// request or response body (Start/End index the stored body), or a whole
// part (status, a header) when no range is given.
type Match struct {
	Location string `json:"location"`        // request | response
	Part     string `json:"part"`            // status | header | body | url
	Start    *int   `json:"start,omitempty"` // byte offset into the stored body
	End      *int   `json:"end,omitempty"`
	Matcher  string `json:"matcher,omitempty"`
}

// Sensitive is a span a tool marked as sensitive: Pointer is a JSON pointer
// into the item (e.g. /http/request/headers/3/value), Start/End an optional
// byte range inside that string.
type Sensitive struct {
	Pointer string `json:"pointer"`
	Start   *int   `json:"start,omitempty"`
	End     *int   `json:"end,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// File is a file_excerpt body.
type File struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// Artifact is a screenshot (or other binary) reference.
type Artifact struct {
	MediaType string `json:"media_type,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Ref       string `json:"ref,omitempty"`
}

// Item is one piece of evidence (CTIS 1.6 evidence_items[] shape).
type Item struct {
	Kind          string      `json:"kind"`
	Version       int         `json:"version,omitempty"`
	Label         string      `json:"label,omitempty"`
	CapturedAt    *time.Time  `json:"captured_at,omitempty"`
	ContentSHA256 string      `json:"content_sha256,omitempty"`
	HTTP          *HTTP       `json:"http,omitempty"`
	Match         []Match     `json:"match,omitempty"`
	Extracted     []string    `json:"extracted,omitempty"`
	Text          string      `json:"text,omitempty"`
	Protocol      string      `json:"protocol,omitempty"`
	Command       string      `json:"command,omitempty"`
	ExitCode      *int        `json:"exit_code,omitempty"`
	File          *File       `json:"file,omitempty"`
	Artifact      *Artifact   `json:"artifact,omitempty"`
	Sensitive     []Sensitive `json:"sensitive,omitempty"`
	// Truncated is set by the platform when it cut anything.
	Truncated bool `json:"truncated,omitempty"`
}

// IsKnownKind reports whether the platform has a typed viewer for kind.
func IsKnownKind(kind string) bool {
	switch kind {
	case KindHTTPExchange, KindRawText, KindScreenshot, KindFileExcerpt, KindCommandOutput, KindCurl:
		return true
	}
	return false
}

// Decode reads one item as a tool sent it. A kind outside the pattern is
// refused; an unknown kind is kept: its whole JSON becomes the item's text
// (shown as text), so a newer tool never loses evidence on an older platform.
func Decode(raw json.RawMessage) (Item, bool) {
	if len(raw) == 0 || len(raw) > 4*MaxItemBytes {
		return Item{}, false
	}
	var it Item
	if err := json.Unmarshal(raw, &it); err != nil {
		return Item{}, false
	}
	it.Kind = strings.ToLower(strings.TrimSpace(it.Kind))
	if !kindPattern.MatchString(it.Kind) {
		return Item{}, false
	}
	if !IsKnownKind(it.Kind) {
		var generic map[string]any
		if json.Unmarshal(raw, &generic) == nil {
			delete(generic, "kind")
			delete(generic, "sensitive")
			if b, err := json.MarshalIndent(generic, "", "  "); err == nil {
				it.Text = string(b)
			}
		}
		it.HTTP, it.File, it.Artifact = nil, nil, nil
	}
	return it, true
}

// DecodeList reads up to limit items from a JSON array, skipping the ones
// Decode refuses.
func DecodeList(raw json.RawMessage, limit int) []Item {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return nil
	}
	out := make([]Item, 0, min(len(arr), limit))
	for _, r := range arr {
		if len(out) >= limit {
			break
		}
		if it, ok := Decode(r); ok {
			out = append(out, it)
		}
	}
	return out
}

// Normalize applies the caps and cleans every string. It returns false when
// nothing worth showing is left. Match ranges outside a stored body are
// dropped; a too-long body keeps the window around its first match.
func Normalize(it Item) (Item, bool) {
	it.Version = 1
	it.Label = cleanLine(it.Label, MaxLabel)
	it.Protocol = cleanLine(it.Protocol, 32)
	it.ContentSHA256 = cleanDigest(it.ContentSHA256)
	it.Command = capText(cleanText(it.Command), 4<<10, &it.Truncated)
	it.Text = capText(cleanText(it.Text), MaxTextBytes, &it.Truncated)
	if len(it.Extracted) > MaxExtracted {
		it.Extracted, it.Truncated = it.Extracted[:MaxExtracted], true
	}
	for i := range it.Extracted {
		it.Extracted[i] = capText(cleanText(it.Extracted[i]), MaxExtractedBytes, &it.Truncated)
	}
	if len(it.Sensitive) > MaxSensitive {
		it.Sensitive = it.Sensitive[:MaxSensitive]
	}
	if it.HTTP != nil {
		normalizeHTTP(&it)
	}
	if it.File != nil {
		it.File.Path = cleanLine(it.File.Path, 1024)
		it.File.Snippet = capText(cleanText(it.File.Snippet), MaxTextBytes, &it.Truncated)
		if it.File.StartLine < 0 {
			it.File.StartLine = 0
		}
		if it.File.EndLine < it.File.StartLine {
			it.File.EndLine = it.File.StartLine
		}
	}
	if it.Artifact != nil {
		it.Artifact.MediaType = cleanLine(it.Artifact.MediaType, 100)
		it.Artifact.SHA256 = cleanDigest(it.Artifact.SHA256)
		it.Artifact.Ref = cleanLine(it.Artifact.Ref, 512)
		if it.Artifact.Size < 0 {
			it.Artifact.Size = 0
		}
	}
	if len(it.Match) > MaxMatches {
		it.Match = it.Match[:MaxMatches]
	}
	it.Match = validMatches(it)
	fitItem(&it)
	return it, !it.isEmpty()
}

// fitItem shrinks the largest free parts until the serialized item fits
// MaxItemBytes (the caps per part can add up to more).
func fitItem(it *Item) {
	for range 8 {
		b, err := json.Marshal(it)
		if err != nil || len(b) <= MaxItemBytes {
			return
		}
		it.Truncated = true
		parts := []*string{&it.Text}
		if it.File != nil {
			parts = append(parts, &it.File.Snippet)
		}
		if it.HTTP != nil && it.HTTP.Response != nil {
			parts = append(parts, &it.HTTP.Response.Body)
		}
		if it.HTTP != nil && it.HTTP.Request != nil {
			parts = append(parts, &it.HTTP.Request.Body)
		}
		biggest := parts[0]
		for _, p := range parts[1:] {
			if len(*p) > len(*biggest) {
				biggest = p
			}
		}
		if len(*biggest) < 1024 {
			return
		}
		*biggest = safeCut(*biggest, len(*biggest)/2) + truncMarker
		if it.HTTP != nil && it.HTTP.Response != nil && biggest == &it.HTTP.Response.Body {
			it.HTTP.Response.BodyTruncated = true
		}
		if it.HTTP != nil && it.HTTP.Request != nil && biggest == &it.HTTP.Request.Body {
			it.HTTP.Request.BodyTruncated = true
		}
		it.Match = validMatches(*it)
	}
}

func (it Item) isEmpty() bool {
	return it.HTTP == nil && it.Text == "" && it.File == nil && it.Artifact == nil &&
		len(it.Extracted) == 0 && it.Command == ""
}

func normalizeHTTP(it *Item) {
	if q := it.HTTP.Request; q != nil {
		q.Method = cleanLine(strings.ToUpper(q.Method), 16)
		q.URL = cleanLine(q.URL, MaxURLBytes)
		q.HTTPVersion = cleanLine(q.HTTPVersion, 16)
		q.Headers = capHeaders(q.Headers, &it.Truncated)
		q.BodyEncoding = bodyEncoding(q.BodyEncoding)
		if q.BodySize < len(q.Body) {
			q.BodySize = len(q.Body)
		}
		var cut bool
		q.Body, cut = windowBody(cleanBody(q.Body, q.BodyEncoding), -1)
		q.BodyTruncated = q.BodyTruncated || cut
		it.Truncated = it.Truncated || cut
	}
	if s := it.HTTP.Response; s != nil {
		if s.Status < 0 || s.Status > 999 {
			s.Status = 0
		}
		s.Reason = cleanLine(s.Reason, 128)
		s.HTTPVersion = cleanLine(s.HTTPVersion, 16)
		s.Headers = capHeaders(s.Headers, &it.Truncated)
		s.BodyEncoding = bodyEncoding(s.BodyEncoding)
		if s.TimeMS < 0 {
			s.TimeMS = 0
		}
		if s.BodySize < len(s.Body) {
			s.BodySize = len(s.Body)
		}
		anchor := firstBodyMatch(it.Match, locResponse)
		var cut bool
		var shift int
		s.Body, cut, shift = windowBodyShift(cleanBody(s.Body, s.BodyEncoding), anchor)
		if cut {
			shiftMatches(it.Match, locResponse, shift)
		}
		s.BodyTruncated = s.BodyTruncated || cut
		it.Truncated = it.Truncated || cut
	}
}

func bodyEncoding(e string) string {
	if strings.EqualFold(strings.TrimSpace(e), "base64") {
		return encBase64
	}
	return ""
}

// cleanBody keeps a text body as valid UTF-8 without NUL bytes; base64 is
// kept as is (it is validated by the viewer, never decoded server-side).
func cleanBody(b, enc string) string {
	if enc == encBase64 {
		return strings.Map(func(r rune) rune {
			if r < 0x80 && (r == '+' || r == '/' || r == '=' || r == '-' || r == '_' ||
				(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return r
			}
			return -1
		}, b)
	}
	return cleanText(b)
}

func windowBody(b string, anchor int) (string, bool) {
	out, cut, _ := windowBodyShift(b, anchor)
	return out, cut
}

// windowBodyShift caps b at MaxBodyBytes. Without an anchor it keeps the
// head; with one it keeps matchWindowBefore bytes before the anchor and the
// rest after it. shift is how many bytes were removed before the anchor.
func windowBodyShift(b string, anchor int) (string, bool, int) {
	if len(b) <= MaxBodyBytes {
		return b, false, 0
	}
	if anchor < 0 || anchor >= len(b) || anchor < matchWindowBefore {
		return safeCut(b, MaxBodyBytes) + truncMarker, true, 0
	}
	start := anchor - matchWindowBefore
	for start > 0 && !utf8.RuneStart(b[start]) {
		start++
	}
	rest := b[start:]
	return "…[truncated]\n" + safeCut(rest, MaxBodyBytes) + truncMarker, true, start - len("…[truncated]\n")
}

func firstBodyMatch(ms []Match, loc string) int {
	best := -1
	for _, m := range ms {
		if m.Location == loc && m.Part == partBody && m.Start != nil && (best < 0 || *m.Start < best) {
			best = *m.Start
		}
	}
	return best
}

func shiftMatches(ms []Match, loc string, shift int) {
	for i := range ms {
		if ms[i].Location != loc || ms[i].Part != partBody || ms[i].Start == nil || ms[i].End == nil {
			continue
		}
		s, e := *ms[i].Start-shift, *ms[i].End-shift
		ms[i].Start, ms[i].End = &s, &e
	}
}

// validMatches keeps the matches that point at something stored.
func validMatches(it Item) []Match {
	out := it.Match[:0]
	for _, m := range it.Match {
		m.Location = strings.ToLower(m.Location)
		m.Part = strings.ToLower(m.Part)
		m.Matcher = cleanLine(m.Matcher, 128)
		if m.Location != locRequest && m.Location != locResponse {
			continue
		}
		switch m.Part {
		case "status", "header", "url":
			m.Start, m.End = nil, nil
		case partBody:
			body := bodyOf(it, m.Location)
			if m.Start != nil || m.End != nil {
				if m.Start == nil || m.End == nil || *m.Start < 0 || *m.End <= *m.Start || *m.End > len(body) {
					continue
				}
			}
		default:
			continue
		}
		out = append(out, m)
	}
	return out
}

func bodyOf(it Item, loc string) string {
	if it.HTTP == nil {
		return ""
	}
	if loc == locRequest && it.HTTP.Request != nil {
		return it.HTTP.Request.Body
	}
	if loc == locResponse && it.HTTP.Response != nil {
		return it.HTTP.Response.Body
	}
	return ""
}

func capHeaders(hs []Header, truncated *bool) []Header {
	if len(hs) > MaxHeaders {
		hs, *truncated = hs[:MaxHeaders], true
	}
	out := hs[:0]
	budget := MaxHeaderBytes
	for _, h := range hs {
		h.Name = cleanLine(h.Name, MaxHeaderName)
		if h.Name == "" {
			continue
		}
		h.Value = capText(cleanLine(h.Value, 1<<20), min(MaxHeaderValue, max(budget, 0)), truncated)
		budget -= len(h.Name) + len(h.Value)
		out = append(out, h)
	}
	return out
}

// cleanText keeps valid UTF-8 and drops NUL; newlines and tabs stay.
func cleanText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// cleanLine is cleanText on one line, capped.
func cleanLine(s string, maxBytes int) string {
	s = cleanText(s)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return safeCut(strings.TrimSpace(s), maxBytes)
}

func capText(s string, maxBytes int, truncated *bool) string {
	if len(s) <= maxBytes {
		return s
	}
	*truncated = true
	return safeCut(s, maxBytes) + truncMarker
}

// safeCut cuts s at most maxBytes without splitting a rune.
func safeCut(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func cleanDigest(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if digestPattern.MatchString(d) {
		return d
	}
	return ""
}
