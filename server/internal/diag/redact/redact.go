// Package redact masks everything in a support bundle that could identify the
// installation's data: secrets and tokens, connection strings, e-mail
// addresses, IP addresses, host names, cookies, authorization headers,
// request and response bodies, and long opaque strings
// (docs/operations/diagnose-and-get-support.md).
//
// A masked value becomes "[kind:xxxxxxxx]". The eight hex characters are the
// start of an HMAC of the value under a random key that lives only for one
// bundle and is never written anywhere: two occurrences of the same value in
// one bundle carry the same mark, so a support engineer can follow a value
// through the logs, while nobody can recover a short value (an IP address)
// by trying candidates, and marks of two bundles cannot be joined.
//
// The package fails closed: where a rule cannot tell a host name from another
// dotted word, the word is masked.
package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/openctemio/openctem/server/pkg/safetext"
)

// Kinds of a mark.
const (
	KindSecret = "secret"
	KindDSN    = "dsn"
	KindEmail  = "email"
	KindIP     = "ip"
	KindHost   = "host"
	KindQuery  = "query"
	KindOpaque = "opaque"
	KindValue  = "value"
)

// MaxLineBytes caps one redacted log line.
const MaxLineBytes = 8 << 10

// Redactor masks text for one bundle.
type Redactor struct{ key []byte }

// New returns a redactor with a fresh random key.
func New() (*Redactor, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &Redactor{key: key}, nil
}

// NewWithKey returns a redactor with a fixed key (tests).
func NewWithKey(key []byte) *Redactor { return &Redactor{key: append([]byte(nil), key...)} }

// Mark returns the placeholder of value: "[kind:xxxxxxxx]".
func (r *Redactor) Mark(kind, value string) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(value))
	return "[" + kind + ":" + hex.EncodeToString(m.Sum(nil)[:4]) + "]"
}

// markRE matches a placeholder, so no later rule looks inside one.
var markRE = regexp.MustCompile(`\[[a-z]+:[0-9a-f]{8}\]`)

var (
	// A URL of a data store: the whole URL goes (user, password, host, port,
	// database name and options).
	dsnURLRE = regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|pgx|redis|rediss|mysql|mariadb|mongodb(?:\+srv)?|amqps?|nats|kafka|sqlserver|clickhouse|s3)://[^\s"'<>]+`)
	// Userinfo of any other URL.
	userinfoRE = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{1,15}://)[^\s/@"'<>]+@`)
	// The query string of a URL or a request path.
	queryRE = regexp.MustCompile(`\?[A-Za-z0-9_%\[][^\s"'<>#]*`)
	// The parts of a key=value connection string a secret rule does not
	// cover.
	kvConnRE = regexp.MustCompile(`(?i)\b(host|hostaddr|user|username|dbname|database|server|sslrootcert|sslcert|sslkey)=('[^']*'|"[^"]*"|[^\s'";,]+)`)

	// An address in any of its common forms: plain, URL-encoded "@", with a
	// "+tag", a quoted local part, an internal domain without a top label.
	// The domain must not be a version ("lib@1.2.3", "mod@v1.2.3") or a
	// digest ("image@sha256:...").
	emailRE    = regexp.MustCompile(`(?i)(?:"[^"\s]{1,64}"|[\p{L}\p{N}._%+'~-]{1,64})(?:@|%40)([\p{L}\p{N}](?:[\p{L}\p{N}.-]{0,253}[\p{L}\p{N}])?)`)
	notADomain = regexp.MustCompile(`(?i)^(?:v?\d+(?:\.\d+)*(?:[-+.][0-9a-z.]+)?|sha(?:1|256|512))$`)

	ipv6RE = regexp.MustCompile(`(?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{0,4}){2,8}(?:(?:\.\d{1,3}){3})?(?:%[0-9A-Za-z]+)?`)
	ipv4RE = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b(?:/\d{1,2}\b)?`)

	// A dotted name whose last label starts with a letter.
	hostRE = regexp.MustCompile(`\b(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}\b`)

	// The platform's own token formats and other well-known key prefixes.
	prefixedTokenRE = regexp.MustCompile(`\b(?:oct[a-z]{0,3}_|sk-|pk-|rk-|glpat-|xoxb-)[A-Za-z0-9_\-]{8,}`)
	// Long opaque strings: hex of 32 characters or more, base64 of 40 or
	// more.
	longHexRE = regexp.MustCompile(`\b[0-9A-Fa-f]{32,}\b`)
	longB64RE = regexp.MustCompile(`[A-Za-z0-9+/_\-]{40,}={0,2}`)

	// Values PostgreSQL prints in an error detail.
	pgKeyDetailRE = regexp.MustCompile(`(Key \([^)]*\)=)\(([^)]*)\)`)
	pgRowDetailRE = regexp.MustCompile(`((?i:failing row contains) )\((.*)\)`)
	// Quoted strings. A double-quoted word after one of these words is a
	// schema identifier and stays.
	quotedRE     = regexp.MustCompile("\"([^\"\\n]+)\"|'([^'\\n]+)'|`([^`\\n]+)`")
	identifierRE = regexp.MustCompile(`(?i)(?:relation|column|constraint|index|function|type|table|trigger|sequence|view|schema|operator|extension)s? $`)
	plainIdentRE = regexp.MustCompile(`^[a-z_][a-z0-9_.]{0,62}$`)
)

// safeHosts are dotted names that say nothing about an installation: module
// path hosts in stack traces and the project's own sites.
var safeHosts = map[string]bool{
	"github.com": true, "golang.org": true, "gopkg.in": true, "google.golang.org": true,
	"go.opentelemetry.io": true, "go.uber.org": true, "ghcr.io": true,
	"openctem.io": true, "docs.openctem.io": true,
}

// fileSuffixes are last labels of file names; none is a top-level domain.
var fileSuffixes = map[string]bool{
	"go": true, "sql": true, "json": true, "yaml": true, "yml": true, "log": true, "txt": true,
	"pem": true, "crt": true, "gz": true, "tar": true, "html": true, "js": true, "ts": true,
	"tsx": true, "proto": true, "toml": true, "conf": true, "lock": true, "sum": true,
	"mod": true, "tmpl": true, "csv": true, "xml": true, "sock": true, "pid": true, "prom": true,
}

type span struct {
	start, end int
	repl       string
}

// Text masks every sensitive value the rules find in free text. It is
// idempotent: masked text passes through unchanged.
func (r *Redactor) Text(s string) string { return r.text(s, true) }

// Code is Text without the host name rule, for text made of the code's own
// dotted words (a capability, a caller, a statement's shape).
func (r *Redactor) Code(s string) string { return r.text(s, false) }

func (r *Redactor) text(s string, hosts bool) string {
	if s == "" {
		return s
	}
	if strings.Contains(s, "://") {
		s = r.urls(s)
	}
	if strings.Contains(s, "=") {
		s = r.replaceSub(s, kvConnRE, func(g []string) string {
			if isMark(g[2]) {
				return g[0]
			}
			return g[1] + "=" + r.Mark(KindValue, g[2])
		})
	}
	if strings.Contains(s, "?") {
		s = r.replaceRE(s, queryRE, func(m string) string { return "?" + r.Mark(KindQuery, m[1:]) })
	}
	return r.rest(s, hosts)
}

// urls masks data store URLs whole and the credentials of any other URL.
func (r *Redactor) urls(s string) string {
	s = r.replaceRE(s, dsnURLRE, func(m string) string { return r.Mark(KindDSN, m) })
	s = r.replaceSub(s, userinfoRE, func(g []string) string {
		if isMark(g[0][len(g[1]) : len(g[0])-1]) {
			return g[0]
		}
		return g[1] + r.Mark(KindSecret, g[0]) + "@"
	})
	return s
}

// rest applies the rules after the URL rules.
func (r *Redactor) rest(s string, hosts bool) string {
	// Secrets by shape (private key blocks, cookies, authorization headers,
	// bearer tokens, key=value secrets, well-known token formats): the
	// platform's one secret finder.
	s = r.replaceSpans(s, func(s string) []span {
		found := safetext.FindSecrets(s)
		out := make([]span, 0, len(found))
		for _, f := range found {
			out = append(out, span{f.Start, f.End, r.Mark(KindSecret, s[f.Start:f.End])})
		}
		return out
	})
	s = r.replaceRE(s, prefixedTokenRE, func(m string) string { return r.Mark(KindSecret, m) })
	if strings.Contains(s, "@") || strings.Contains(s, "%40") {
		s = r.replaceSub(s, emailRE, func(g []string) string {
			if notADomain.MatchString(g[1]) {
				return g[0]
			}
			return r.Mark(KindEmail, strings.ToLower(strings.Replace(g[0], "%40", "@", 1)))
		})
	}
	if strings.Count(s, ":") >= 2 {
		s = r.replaceRE(s, ipv6RE, r.maskIPv6)
	}
	if strings.Contains(s, ".") {
		s = r.replaceRE(s, ipv4RE, r.maskIPv4)
		if hosts {
			s = r.replaceRE(s, hostRE, r.maskHost)
		}
	}
	if len(s) >= 32 {
		s = r.replaceRE(s, longHexRE, func(m string) string { return r.Mark(KindOpaque, m) })
		s = r.replaceRE(s, longB64RE, func(m string) string {
			if !looksEncoded(m) {
				return m
			}
			return r.Mark(KindOpaque, m)
		})
	}
	return s
}

// Message is Text for a log message or an error text: it also masks the row
// values PostgreSQL prints in an error detail and every quoted string that is
// not a schema identifier.
func (r *Redactor) Message(s string) string {
	if s == "" {
		return s
	}
	detail := func(g []string) string {
		if isMark(g[2]) {
			return g[0]
		}
		return g[1] + "(" + r.Mark(KindValue, g[2]) + ")"
	}
	s = r.replaceSub(s, pgKeyDetailRE, detail)
	s = r.replaceSub(s, pgRowDetailRE, detail)
	s = r.replaceSpans(s, func(s string) []span {
		var out []span
		for _, m := range quotedRE.FindAllStringSubmatchIndex(s, -1) {
			inner := s[m[0]+1 : m[1]-1]
			if isMark(inner) {
				continue
			}
			if s[m[0]] == '"' && plainIdentRE.MatchString(inner) && identifierRE.MatchString(s[:m[0]]) {
				continue
			}
			out = append(out, span{m[0] + 1, m[1] - 1, r.Mark(KindValue, inner)})
		}
		return out
	})
	return r.Text(s)
}

// Value masks a whole value.
func (r *Redactor) Value(s string) string {
	if s == "" {
		return s
	}
	return r.Mark(KindValue, s)
}

func (r *Redactor) maskIPv4(m string) string {
	addr := m
	if i := strings.IndexByte(m, '/'); i >= 0 {
		addr = m[:i]
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		// Not an address (an octet over 255): still four dotted numbers of
		// unknown meaning, masked.
		return r.Mark(KindIP, m)
	}
	if a.IsLoopback() || a.IsUnspecified() {
		return m
	}
	return r.Mark(KindIP, m)
}

func (r *Redactor) maskIPv6(m string) string {
	// The candidate may carry one separator colon before or after the
	// address ("peer:fe80::1", "fe80::1: timeout").
	start, end := 0, len(m)
	if strings.HasPrefix(m, ":") && !strings.HasPrefix(m, "::") {
		start = 1
	}
	for end > start {
		c := m[start:end]
		if strings.Count(c, ":") < 2 {
			return m
		}
		if a, err := netip.ParseAddr(c); err == nil {
			if a.IsLoopback() || a.IsUnspecified() {
				return m
			}
			return m[:start] + r.Mark(KindIP, a.String()) + m[end:]
		}
		if !strings.HasSuffix(c, ":") {
			return m
		}
		end--
	}
	return m
}

func (r *Redactor) maskHost(m string) string {
	lower := strings.ToLower(m)
	if safeHosts[lower] {
		return m
	}
	if i := strings.LastIndexByte(lower, '.'); i >= 0 && fileSuffixes[lower[i+1:]] {
		return m
	}
	return r.Mark(KindHost, lower)
}

// looksEncoded reports whether a long run of base64 characters is an encoded
// value and not a path or an identifier: it mixes upper case, lower case and
// digits, and has no long run of path segments.
func looksEncoded(s string) bool {
	var upper, lower, digit bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

// replaceRE replaces every match of re outside placeholders.
func (r *Redactor) replaceRE(s string, re *regexp.Regexp, f func(string) string) string {
	return r.replaceSpans(s, func(s string) []span {
		var out []span
		for _, m := range re.FindAllStringIndex(s, -1) {
			old := s[m[0]:m[1]]
			if repl := f(old); repl != old {
				out = append(out, span{m[0], m[1], repl})
			}
		}
		return out
	})
}

// replaceSub is replaceRE with the submatches.
func (r *Redactor) replaceSub(s string, re *regexp.Regexp, f func(groups []string) string) string {
	return r.replaceSpans(s, func(s string) []span {
		var out []span
		for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
			groups := make([]string, len(m)/2)
			for i := range groups {
				if m[2*i] >= 0 {
					groups[i] = s[m[2*i]:m[2*i+1]]
				}
			}
			if repl := f(groups); repl != groups[0] {
				out = append(out, span{m[0], m[1], repl})
			}
		}
		return out
	})
}

// isMark reports whether s is exactly one placeholder.
func isMark(s string) bool { return markRE.FindString(s) == s && s != "" }

// replaceSpans applies the spans find returns. Overlapping spans are merged
// into one. A span that touches a placeholder already in the text is widened
// to cover it and masked as one value, unless nothing but placeholders and
// punctuation is in it (text masked by an earlier pass stays as it is).
func (r *Redactor) replaceSpans(s string, find func(string) []span) string {
	spans := find(s)
	if len(spans) == 0 {
		return s
	}
	marks := markRE.FindAllStringIndex(s, -1)
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for i := 0; i < len(spans); i++ {
		sp := spans[i]
		if sp.end <= sp.start {
			continue
		}
		changed := false
		for again := true; again; {
			again = false
			for i+1 < len(spans) && spans[i+1].start < sp.end {
				if spans[i+1].end > sp.end {
					sp.end = spans[i+1].end
				}
				changed, again = true, true
				i++
			}
			for _, m := range marks {
				if sp.start < m[1] && sp.end > m[0] && (m[0] < sp.start || m[1] > sp.end) {
					sp.start, sp.end = min(sp.start, m[0]), max(sp.end, m[1])
					changed, again = true, true
				}
			}
		}
		if sp.start < prev {
			sp.start = prev
			if sp.end <= sp.start {
				continue
			}
			changed = true
		}
		text := s[sp.start:sp.end]
		if markRE.MatchString(text) {
			if !hasWord(markRE.ReplaceAllString(text, "")) {
				continue
			}
			changed = true
		}
		if changed {
			sp.repl = r.Mark(KindValue, text)
		}
		b.WriteString(s[prev:sp.start])
		b.WriteString(sp.repl)
		prev = sp.end
	}
	b.WriteString(s[prev:])
	return b.String()
}

func hasWord(s string) bool {
	for _, c := range s {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			return true
		}
	}
	return false
}
