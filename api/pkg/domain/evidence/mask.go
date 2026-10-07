package evidence

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Secret is one value Mask took out of an item. Placeholder is what replaced
// it everywhere in the item; Value is the plaintext the platform encrypts and
// stores apart from the item.
type Secret struct {
	Placeholder string
	Kind        string
	Value       string
}

// MaxSecretsPerItem bounds what one item can put into the encrypted store. A
// value beyond the bound is still masked, but its plaintext is not kept.
const MaxSecretsPerItem = 100

// minSecretLen: shorter values are masked where they were found by name but
// not searched for elsewhere in the item (too many false hits).
const minSecretLen = 4

// placeholderPrefix opens every placeholder; the web viewer finds them by it.
const placeholderPrefix = "«secret:"

var placeholderPattern = regexp.MustCompile(`«secret:[a-z_]{1,32}#[0-9]{1,4}»`)

// RedactText masks the secrets in a free text (a reason, a summary) without
// keeping them: for text that leaves the platform's evidence store.
func RedactText(s string) string {
	masked, _ := Mask(Item{Kind: KindRawText, Text: s})
	return masked.Text
}

// Placeholders returns the distinct placeholders present in s.
func Placeholders(s string) []string {
	return placeholderPattern.FindAllString(s, -1)
}

// IsPlaceholder reports whether p is a well-formed placeholder.
func IsPlaceholder(p string) bool {
	return placeholderPattern.MatchString(p) && placeholderPattern.FindString(p) == p
}

// Sensitive header names (lower case). Any other header whose name matches
// sensitiveHeaderPattern is masked as well.
var sensitiveHeaders = map[string]string{ //nolint:gochecknoglobals // static table
	"authorization":        "authorization",
	"proxy-authorization":  "authorization",
	"cookie":               "cookie",
	"set-cookie":           "cookie",
	"x-api-key":            "api_key",
	"api-key":              "api_key",
	"apikey":               "api_key",
	"x-auth-token":         "token",
	"x-access-token":       "token",
	"x-csrf-token":         "token",
	"x-xsrf-token":         "token",
	"private-token":        "token",
	"x-amz-security-token": "token",
	"x-goog-api-key":       "api_key",
}

var sensitiveHeaderPattern = regexp.MustCompile(`(?i)(token|secret|passw|api[-_]?key|session|auth|signature|credential)`)

// sensitiveParam matches query/form/JSON names whose value is a secret.
var sensitiveParam = regexp.MustCompile(`(?i)^(access[-_]?token|id[-_]?token|refresh[-_]?token|token|auth[-_]?token|api[-_]?key|apikey|key|secret|client[-_]?secret|password|passwd|pwd|pass|passphrase|sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token|session|sessionid|session[-_]?id|sid|jwt|code|auth|private[-_]?key|credentials?)$`)

// Shapes of credentials anywhere in text.
var shapePatterns = []struct { //nolint:gochecknoglobals // static table
	kind string
	re   *regexp.Regexp
}{
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"aws_key", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`)},
	{"token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{20,}\b`)},
	{"token", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{20,}\b`)},
	{"token", regexp.MustCompile(`\bglpat-[0-9A-Za-z_-]{20,}\b`)},
	{"token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{"api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"api_key", regexp.MustCompile(`\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b`)},
}

// bearerPattern: "Bearer <token>" / "Basic <creds>" anywhere in text.
var bearerPattern = regexp.MustCompile(`(?i)\b(bearer|basic|token|digest)\s+([A-Za-z0-9._~+/=-]{8,})`)

// jsonPair: "name": "value" with a sensitive name.
var jsonPair = regexp.MustCompile(`"([A-Za-z0-9_.-]{1,64})"\s*:\s*"((?:[^"\\]|\\.)+)"`)

// assignPair: name=value / name: value (forms, query strings, config text).
var assignPair = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]{1,64})(\s*[:=]\s*)(['"]?)([^\s'"&;,<>]+)`)

// cookieInText: a Cookie / Set-Cookie header written inside text (a curl
// command, a log line).
var cookieInText = regexp.MustCompile(`(?i)\b(set-cookie|cookie)\s*:\s*([^'"\r\n]+)`)

// urlInText finds URLs inside text, to mask their userinfo and query.
var urlInText = regexp.MustCompile(`https?://[^\s"'<>]+`)

type masker struct {
	byValue map[string]string
	counts  map[string]int
	secrets []Secret
}

func newMasker() *masker {
	return &masker{byValue: map[string]string{}, counts: map[string]int{}}
}

// add registers value as a secret of kind and returns its placeholder.
func (m *masker) add(kind, value string) {
	value = strings.TrimSpace(value)
	if value == "" || IsPlaceholder(value) || strings.HasPrefix(value, placeholderPrefix) || alreadyMasked(value) {
		return
	}
	if _, ok := m.byValue[value]; ok {
		return
	}
	kind = cleanKind(kind)
	m.counts[kind]++
	p := placeholderPrefix + kind + "#" + strconv.Itoa(m.counts[kind]) + "»"
	m.byValue[value] = p
	if len(m.secrets) < MaxSecretsPerItem {
		m.secrets = append(m.secrets, Secret{Placeholder: p, Kind: kind, Value: value})
	}
}

// alreadyMasked reports a value a tool masked before the platform saw it
// (nuclei writes "***", the sensor "[REDACTED]"): there is nothing to keep
// or reveal.
func alreadyMasked(v string) bool {
	if v == "[REDACTED]" || strings.EqualFold(v, "redacted") {
		return true
	}
	return strings.Trim(v, "*") == ""
}

func cleanKind(k string) string {
	k = strings.ToLower(k)
	k = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || r == '_' {
			return r
		}
		if r == '-' || r == ' ' {
			return '_'
		}
		return -1
	}, k)
	if k == "" {
		return "secret"
	}
	if len(k) > 32 {
		k = k[:32]
	}
	return k
}

// Mask takes every secret value out of a normalized item. It returns the
// masked item (each value replaced by its placeholder wherever it appears:
// headers, URLs, bodies, text, extracted values, the command) and the
// secrets. Tool-marked spans (Sensitive) are honored on top of the
// platform's own detection, which always runs; the spans are dropped from
// the result. Body match ranges are moved to where the matched text sits
// after masking, and dropped when it can no longer be found.
func Mask(it Item) (Item, []Secret) {
	m := newMasker()
	decodeTextBodies(&it)
	matched := matchedTexts(it)

	m.collectMarked(it)
	if it.HTTP != nil {
		m.collectHTTP(it.HTTP)
	}
	for _, s := range textFields(&it) {
		m.collectText(*s)
	}
	it.Sensitive = nil
	if len(m.byValue) == 0 {
		return it, nil
	}

	r := m.replacer()
	for _, s := range textFields(&it) {
		*s = r.Replace(*s)
	}
	if it.HTTP != nil {
		for _, hs := range []*[]Header{headersOf(it.HTTP.Request), headersOf2(it.HTTP.Response)} {
			if hs == nil {
				continue
			}
			for i := range *hs {
				(*hs)[i].Value = maskHeaderValue((*hs)[i], r)
			}
		}
	}
	remapMatches(&it, matched, r)
	return it, m.secrets
}

// decodeTextBodies turns a base64 body that is valid UTF-8 text into text,
// so the detectors can see it.
func decodeTextBodies(it *Item) {
	if it.HTTP == nil {
		return
	}
	dec := func(body *string, enc *string) {
		if *enc != encBase64 {
			return
		}
		b, err := base64.StdEncoding.DecodeString(*body)
		if err != nil || !utf8.Valid(b) || strings.ContainsRune(string(b), 0) {
			return
		}
		*body, *enc = string(b), ""
	}
	if q := it.HTTP.Request; q != nil {
		dec(&q.Body, &q.BodyEncoding)
	}
	if s := it.HTTP.Response; s != nil {
		dec(&s.Body, &s.BodyEncoding)
	}
}

func headersOf(q *HTTPRequest) *[]Header {
	if q == nil {
		return nil
	}
	return &q.Headers
}

func headersOf2(s *HTTPResponse) *[]Header {
	if s == nil {
		return nil
	}
	return &s.Headers
}

// textFields are every free string of an item that can carry a secret.
func textFields(it *Item) []*string {
	out := []*string{&it.Text, &it.Command, &it.Label}
	for i := range it.Extracted {
		out = append(out, &it.Extracted[i])
	}
	if it.File != nil {
		out = append(out, &it.File.Snippet)
	}
	if it.HTTP != nil {
		if q := it.HTTP.Request; q != nil {
			out = append(out, &q.URL)
			if q.BodyEncoding == "" {
				out = append(out, &q.Body)
			}
		}
		if s := it.HTTP.Response; s != nil && s.BodyEncoding == "" {
			out = append(out, &s.Body)
		}
	}
	return out
}

// collectMarked registers the spans a tool marked as sensitive.
func (m *masker) collectMarked(it Item) {
	for _, sp := range it.Sensitive {
		v, ok := resolvePointer(it, sp.Pointer)
		if !ok {
			continue
		}
		if sp.Start != nil && sp.End != nil && *sp.Start >= 0 && *sp.End > *sp.Start && *sp.End <= len(v) {
			v = v[*sp.Start:*sp.End]
		}
		kind := sp.Kind
		if kind == "" {
			kind = "secret"
		}
		m.add(kind, v)
	}
}

// resolvePointer reads the string a JSON pointer names, for the pointers a
// tool may mark.
func resolvePointer(it Item, p string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "text":
		return it.Text, true
	case len(parts) == 1 && parts[0] == "command":
		return it.Command, true
	case len(parts) == 2 && parts[0] == "extracted":
		i, err := strconv.Atoi(parts[1])
		if err != nil || i < 0 || i >= len(it.Extracted) {
			return "", false
		}
		return it.Extracted[i], true
	case len(parts) >= 3 && parts[0] == "http" && it.HTTP != nil:
		var hs []Header
		var url, body string
		switch parts[1] {
		case "request":
			if it.HTTP.Request == nil {
				return "", false
			}
			hs, url, body = it.HTTP.Request.Headers, it.HTTP.Request.URL, it.HTTP.Request.Body
		case "response":
			if it.HTTP.Response == nil {
				return "", false
			}
			hs, body = it.HTTP.Response.Headers, it.HTTP.Response.Body
		default:
			return "", false
		}
		switch {
		case len(parts) == 3 && parts[2] == "url":
			return url, url != ""
		case len(parts) == 3 && parts[2] == "body":
			return body, body != ""
		case len(parts) == 5 && parts[2] == "headers" && parts[4] == "value":
			i, err := strconv.Atoi(parts[3])
			if err != nil || i < 0 || i >= len(hs) {
				return "", false
			}
			return hs[i].Value, true
		}
	}
	return "", false
}

// collectHTTP finds secrets by position in an exchange: sensitive headers
// and the URL's userinfo and sensitive query parameters.
func (m *masker) collectHTTP(h *HTTP) {
	if q := h.Request; q != nil {
		m.collectHeaders(q.Headers)
		m.collectURL(q.URL)
		m.collectForm(q.Body, q.Headers)
	}
	if s := h.Response; s != nil {
		m.collectHeaders(s.Headers)
	}
}

func (m *masker) collectHeaders(hs []Header) {
	for _, h := range hs {
		name := strings.ToLower(h.Name)
		switch name {
		case "location", "referer", "origin", "content-location", "link", "refresh":
			for _, u := range urlInText.FindAllString(h.Value, -1) {
				m.collectURL(u)
			}
			continue
		}
		kind, ok := sensitiveHeaders[name]
		if !ok {
			if !sensitiveHeaderPattern.MatchString(name) {
				continue
			}
			kind = "token"
		}
		switch {
		case name == "cookie":
			for _, part := range strings.Split(h.Value, ";") {
				if _, v, ok := strings.Cut(part, "="); ok {
					m.add(kind, v)
				}
			}
		case name == "set-cookie":
			first, _, _ := strings.Cut(h.Value, ";")
			if _, v, ok := strings.Cut(first, "="); ok {
				m.add(kind, v)
			}
		case kind == "authorization":
			if scheme, cred, ok := strings.Cut(strings.TrimSpace(h.Value), " "); ok && isAuthScheme(scheme) {
				m.add(kind, cred)
			} else {
				m.add(kind, h.Value)
			}
		default:
			m.add(kind, h.Value)
		}
	}
}

func isAuthScheme(s string) bool {
	switch strings.ToLower(s) {
	case "bearer", "basic", "digest", "token", "negotiate", "ntlm", "aws4-hmac-sha256", "hoba", "mutual", "apikey":
		return true
	}
	return false
}

func (m *masker) collectURL(raw string) {
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			m.add("password", p)
		}
	}
	for name, vals := range u.Query() {
		if sensitiveParam.MatchString(name) {
			for _, v := range vals {
				m.add("token", v)
				m.add("token", url.QueryEscape(v))
			}
		}
	}
}

// collectForm reads an application/x-www-form-urlencoded request body.
func (m *masker) collectForm(body string, hs []Header) {
	form := false
	for _, h := range hs {
		if strings.EqualFold(h.Name, "content-type") && strings.Contains(strings.ToLower(h.Value), "x-www-form-urlencoded") {
			form = true
		}
	}
	if !form || body == "" {
		return
	}
	vals, err := url.ParseQuery(body)
	if err != nil {
		return
	}
	for name, vs := range vals {
		if sensitiveParam.MatchString(name) {
			for _, v := range vs {
				m.add("password", v)
				m.add("password", url.QueryEscape(v))
			}
		}
	}
}

// collectText finds secrets in free text by name and by shape.
func (m *masker) collectText(s string) {
	if s == "" {
		return
	}
	for _, p := range shapePatterns {
		for _, v := range p.re.FindAllString(s, 50) {
			m.add(p.kind, v)
		}
	}
	for _, g := range bearerPattern.FindAllStringSubmatch(s, 50) {
		m.add("authorization", g[2])
	}
	for _, g := range jsonPair.FindAllStringSubmatch(s, 200) {
		if sensitiveParam.MatchString(g[1]) || sensitiveHeaderPattern.MatchString(g[1]) {
			m.add("token", g[2])
		}
	}
	for _, g := range assignPair.FindAllStringSubmatch(s, 200) {
		if sensitiveParam.MatchString(g[1]) {
			m.add("token", g[4])
		}
	}
	for _, u := range urlInText.FindAllString(s, 50) {
		m.collectURL(u)
	}
	for _, g := range cookieInText.FindAllStringSubmatch(s, 50) {
		m.collectHeaders([]Header{{Name: g[1], Value: g[2]}})
	}
	for _, line := range strings.Split(s, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || len(name) > 64 || strings.ContainsAny(name, " \t") {
			continue
		}
		h := Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)}
		if _, known := sensitiveHeaders[strings.ToLower(h.Name)]; known {
			m.collectHeaders([]Header{h})
		}
	}
}

// replacer replaces every collected value (longest first, so a value that
// contains another is replaced whole).
func (m *masker) replacer() *strings.Replacer {
	vals := make([]string, 0, len(m.byValue))
	for v := range m.byValue {
		if len(v) >= minSecretLen {
			vals = append(vals, v)
		}
	}
	sort.Slice(vals, func(i, j int) bool {
		if len(vals[i]) != len(vals[j]) {
			return len(vals[i]) > len(vals[j])
		}
		return vals[i] < vals[j]
	})
	pairs := make([]string, 0, 2*len(vals))
	for _, v := range vals {
		pairs = append(pairs, v, m.byValue[v])
	}
	return strings.NewReplacer(pairs...)
}

// maskHeaderValue masks a header: the global replacement, plus the whole
// value of a sensitive header whose value is too short to replace globally.
func maskHeaderValue(h Header, r *strings.Replacer) string {
	v := r.Replace(h.Value)
	name := strings.ToLower(h.Name)
	_, known := sensitiveHeaders[name]
	if !known && !sensitiveHeaderPattern.MatchString(name) {
		return v
	}
	if strings.Contains(v, placeholderPrefix) || v == "" || alreadyMasked(v) {
		return v
	}
	// A sensitive header whose value no rule replaced (shorter than
	// minSecretLen): hide it without keeping the plaintext.
	return placeholderPrefix + "redacted#0»"
}

type matchedText struct {
	idx  int
	text string
}

// matchedTexts captures the text each body match points at before masking.
func matchedTexts(it Item) []matchedText {
	var out []matchedText
	for i, mt := range it.Match {
		if mt.Part != partBody || mt.Start == nil || mt.End == nil {
			continue
		}
		body := bodyOf(it, mt.Location)
		if *mt.End <= len(body) {
			out = append(out, matchedText{idx: i, text: body[*mt.Start:*mt.End]})
		}
	}
	return out
}

// remapMatches points each body match at its (masked) text in the masked body.
func remapMatches(it *Item, before []matchedText, r *strings.Replacer) {
	if len(before) == 0 {
		return
	}
	drop := map[int]bool{}
	for _, mt := range before {
		m := &it.Match[mt.idx]
		body := bodyOf(*it, m.Location)
		want := r.Replace(mt.text)
		from := 0
		if *m.Start < len(body) {
			from = max(0, *m.Start-len(want)-64)
		}
		pos := strings.Index(body[from:], want)
		if pos < 0 {
			pos = strings.Index(body, want)
			from = 0
		}
		if pos < 0 || want == "" {
			drop[mt.idx] = true
			continue
		}
		s, e := from+pos, from+pos+len(want)
		m.Start, m.End = &s, &e
	}
	if len(drop) == 0 {
		return
	}
	kept := it.Match[:0]
	for i, mt := range it.Match {
		if !drop[i] {
			kept = append(kept, mt)
		}
	}
	it.Match = kept
}
