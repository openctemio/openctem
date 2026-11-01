package pagemon

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Parse bounds.
const (
	MaxScripts      = 200
	MaxURLsPerFile  = 500
	MaxURLBytesKept = 512
	MaxTextBytes    = 256 << 10
	maxTextLines    = 5000
	maxTokens       = 200000
)

// ScriptRef is one script a page loads.
type ScriptRef struct {
	// Src is the resolved source ("" for an inline script).
	Src string `json:"src,omitempty"`
	// ID is the identity diffs compare: the source without cache busters
	// and build hashes, or "inline:<hash>".
	ID   string `json:"id"`
	Host string `json:"host,omitempty"`
	// ThirdParty: the host is not the organization's (see FirstParty).
	ThirdParty bool `json:"third_party,omitempty"`
	Inline     bool `json:"inline,omitempty"`
	// Integrity: the tag carries a subresource integrity attribute.
	Integrity bool `json:"integrity,omitempty"`
}

// cacheBusters are query parameters that change per deploy or per request.
var cacheBusters = map[string]bool{
	"v": true, "ver": true, "version": true, "t": true, "ts": true, "_": true, "cb": true,
	"cachebust": true, "cache": true, "rev": true, "build": true, "hash": true, "nocache": true,
}

var (
	hexPart   = regexp.MustCompile(`^[0-9a-f]{6,}$`)
	alnumPart = regexp.MustCompile(`^[0-9A-Za-z_]{8,}$`)
	hasDigit  = regexp.MustCompile(`[0-9]`)
	hasLetter = regexp.MustCompile(`[A-Za-z]`)
	// volatile tokens in text and inline scripts.
	longToken = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)
	digitRun  = regexp.MustCompile(`[0-9]{6,}`)
	nonceAttr = regexp.MustCompile(`(?i)nonce\s*[=:]\s*["']?[^"'\s>]+`)
	// URLs and absolute paths in JavaScript.
	absURLRe  = regexp.MustCompile("https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[^\\s\"'<>`\\\\)]*)?")
	quotedAbs = regexp.MustCompile("[\"'`](/[A-Za-z0-9_\\-./]{1,200})[\"'`]")
)

// buildHash reports whether a file name part looks like a build hash.
func buildHash(p string) bool {
	if hexPart.MatchString(p) && hasDigit.MatchString(p) {
		return true
	}
	return alnumPart.MatchString(p) && hasDigit.MatchString(p) && hasLetter.MatchString(p)
}

// ScriptIdentity is the identity of a script source: host and path with
// build hashes in the file name replaced by "*", cache-buster parameters
// dropped and the rest of the query sorted. A rebuilt bundle keeps its
// identity.
func ScriptIdentity(u *url.URL) string {
	dir, file := path.Split(u.EscapedPath())
	parts := strings.Split(file, ".")
	for i, p := range parts {
		if i == len(parts)-1 && len(parts) > 1 {
			break // never the extension
		}
		// "main-3f9a1c7e": a hash after the last dash.
		if j := strings.LastIndex(p, "-"); j > 0 && buildHash(p[j+1:]) {
			parts[i] = p[:j] + "-*"
		} else if buildHash(p) {
			parts[i] = "*"
		}
	}
	id := "//" + strings.ToLower(u.Host) + dir + strings.Join(parts, ".")
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		if !cacheBusters[strings.ToLower(k)] {
			keys = append(keys, k)
		}
	}
	if len(keys) > 0 {
		slices.Sort(keys)
		vals := url.Values{}
		for _, k := range keys {
			vals[k] = q[k]
		}
		id += "?" + vals.Encode()
	}
	return id
}

// Volatile replaces tokens that change on every response (nonces, long
// tokens, timestamps and other digit runs) with fixed placeholders.
func Volatile(s string) string {
	s = nonceAttr.ReplaceAllString(s, "nonce=#")
	s = longToken.ReplaceAllString(s, "#tok")
	return digitRun.ReplaceAllString(s, "#num")
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ParseHTML reads the scripts of a page and, when text is set, its visible
// text (one line per text block, whitespace collapsed). It never builds a
// DOM or runs anything; it stops after a fixed number of tokens.
func ParseHTML(body string, page *url.URL, text bool) (scripts []ScriptRef, lines []string) {
	p := &htmlParser{z: html.NewTokenizer(strings.NewReader(body)), page: page, text: text, seen: map[string]bool{}}
	for n := 0; n < maxTokens; n++ {
		tt := p.z.Next()
		switch tt {
		case html.ErrorToken:
			return p.scripts, p.lines
		case html.StartTagToken, html.SelfClosingTagToken:
			p.start(tt)
		case html.EndTagToken:
			p.end()
		case html.TextToken:
			p.textToken()
		}
	}
	return p.scripts, p.lines
}

// htmlParser is the state of one ParseHTML pass.
type htmlParser struct {
	z         *html.Tokenizer
	page      *url.URL
	text      bool
	skipDepth int // inside script/style/template/noscript
	inScript  bool
	inline    strings.Builder
	textBytes int
	seen      map[string]bool
	scripts   []ScriptRef
	lines     []string
}

func (p *htmlParser) add(r ScriptRef) {
	if len(p.scripts) < MaxScripts && !p.seen[r.ID] {
		p.seen[r.ID] = true
		p.scripts = append(p.scripts, r)
	}
}

func (p *htmlParser) start(tt html.TokenType) {
	tn, hasAttr := p.z.TagName()
	switch atom.Lookup(tn) {
	case atom.Script:
		src, integrity := "", false
		for hasAttr {
			var k, v []byte
			k, v, hasAttr = p.z.TagAttr()
			switch string(k) {
			case "src":
				src = strings.TrimSpace(string(v))
			case "integrity":
				integrity = strings.TrimSpace(string(v)) != ""
			}
		}
		if src != "" {
			if r, ok := externalScript(src, p.page, integrity); ok {
				p.add(r)
			}
		} else if tt == html.StartTagToken {
			p.inScript = true
			p.inline.Reset()
		}
	case atom.Style, atom.Template, atom.Noscript:
	default:
		return
	}
	if tt == html.StartTagToken {
		p.skipDepth++
	}
}

func (p *htmlParser) end() {
	tn, _ := p.z.TagName()
	switch atom.Lookup(tn) {
	case atom.Script:
		if p.inScript {
			if t := strings.TrimSpace(p.inline.String()); t != "" {
				h := sha(Volatile(t))
				p.add(ScriptRef{ID: "inline:" + h[:16], Inline: true})
			}
			p.inScript = false
		}
	case atom.Style, atom.Template, atom.Noscript:
	default:
		return
	}
	if p.skipDepth > 0 {
		p.skipDepth--
	}
}

func (p *htmlParser) textToken() {
	if p.inScript {
		if p.inline.Len() < MaxBodyBytes {
			p.inline.Write(p.z.Text())
		}
		return
	}
	if !p.text || p.skipDepth > 0 || p.textBytes >= MaxTextBytes || len(p.lines) >= maxTextLines {
		return
	}
	if t := strings.Join(strings.Fields(string(p.z.Text())), " "); t != "" {
		t = clip(Volatile(t), 1000)
		p.textBytes += len(t) + 1
		p.lines = append(p.lines, t)
	}
}

func externalScript(src string, page *url.URL, integrity bool) (ScriptRef, bool) {
	ref, err := url.Parse(src)
	if err != nil {
		return ScriptRef{}, false
	}
	u := page.ResolveReference(ref)
	if !webScheme(u.Scheme) || u.Host == "" || u.User != nil {
		return ScriptRef{}, false
	}
	u.Fragment, u.RawFragment = "", ""
	s := u.String()
	if len(s) > MaxURLBytes {
		return ScriptRef{}, false
	}
	return ScriptRef{Src: s, ID: ScriptIdentity(u), Host: strings.ToLower(u.Hostname()), Integrity: integrity}, true
}

// ExtractURLs returns the absolute URLs and absolute paths found in a
// script body, sorted, deduplicated and capped.
func ExtractURLs(body string) []string {
	set := map[string]bool{}
	for _, m := range absURLRe.FindAllString(body, MaxURLsPerFile*4) {
		set[clip(strings.TrimRight(m, ".,;"), MaxURLBytesKept)] = true
	}
	for _, m := range quotedAbs.FindAllStringSubmatch(body, MaxURLsPerFile*4) {
		p := m[1]
		if strings.HasPrefix(p, "//") || len(p) < 2 {
			continue
		}
		set[clip(p, MaxURLBytesKept)] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	if len(out) > MaxURLsPerFile {
		out = out[:MaxURLsPerFile]
	}
	return out
}

func webScheme(s string) bool { return s == "http" || s == "https" }
