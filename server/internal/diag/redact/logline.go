package redact

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Log lines. A structured line (a JSON object, or key=value pairs) is masked
// field by field: the value of a field whose name says it holds an
// identity, an address, a credential, a body or evidence is replaced whole;
// every other text value goes through Message. A line of any other shape is
// free text and goes through Message as a whole.

// wholeTokens are the words of a field name whose value is replaced whole,
// whatever it holds (nested objects included).
var wholeTokens = map[string]bool{
	// identities
	"email": true, "mail": true, "user": true, "username": true, "login": true, "name": true,
	"actor": true, "owner": true, "assignee": true, "recipient": true, "recipients": true,
	"to": true, "from": true, "cc": true, "bcc": true, "subject": true, "tenant": true,
	"org": true, "organization": true, "slug": true, "title": true, "description": true,
	"summary": true, "label": true, "labels": true, "tag": true, "tags": true, "comment": true,
	// network identities and targets
	"host": true, "hostname": true, "hosts": true, "domain": true, "domains": true, "fqdn": true,
	"target": true, "targets": true, "asset": true, "assets": true, "url": true, "uri": true,
	"referer": true, "referrer": true, "origin": true, "ip": true, "ips": true, "addr": true,
	"address": true, "addresses": true, "remote": true, "peer": true, "client": true, "sni": true,
	"cidr": true, "range": true, "endpoint": true, "dsn": true, "database": true, "dbname": true,
	"filename": true, "file": true, "agent": true,
	// credentials
	"cookie": true, "cookies": true, "authorization": true, "auth": true, "token": true,
	"tokens": true, "secret": true, "secrets": true, "password": true, "passwd": true, "pwd": true,
	"key": true, "keys": true, "apikey": true, "credential": true, "credentials": true,
	"signature": true, "jwt": true, "bearer": true, "session": true, "csrf": true, "otp": true,
	"code": true, "pepper": true, "salt": true, "nonce": true,
	// bodies and finding content
	"body": true, "payload": true, "evidence": true, "content": true, "data": true, "raw": true,
	"header": true, "headers": true, "query": true, "params": true, "args": true, "form": true,
	"input": true, "output": true, "stdout": true, "stderr": true, "snippet": true,
	"match": true, "matched": true, "proof": true, "finding": true, "findings": true,
	"value": true, "values": true, "sql": true, "statement": true,
}

// safeSuffixes are last words of a field name that make it a count, a
// duration, a time or an identifier, not content: "user_id", "host_count",
// "token_ttl_seconds". An identifier's value still has to look like one.
var safeSuffixes = map[string]bool{
	"id": true, "ids": true, "count": true, "total": true, "ms": true, "bytes": true,
	"seconds": true, "secs": true, "at": true, "kind": true, "type": true, "status": true,
	"state": true, "len": true, "length": true, "size": true, "version": true, "ttl": true,
	"configured": true, "enabled": true, "present": true, "set": true, "level": true,
	"health": true, "mode": true, "duration": true, "latency": true, "attempt": true,
	"attempts": true, "retries": true, "limit": true, "max": true, "min": true, "age": true,
}

// verbatimKeys are fields whose value is a fixed word of the code (a level, a
// controller name, a capability): only secrets, addresses and e-mails are
// masked in them, dotted names stay.
var verbatimKeys = map[string]bool{
	keyTime: true, "ts": true, "timestamp": true, "level": true, "lvl": true, "caller": true,
	"source": true, "logger": true, "component": true, "controller": true, "capability": true,
	"stage": true, "method": true, "alert": true, "job": true, "reason": true, "route": true,
	"request_id": true, "trace_id": true, "span_id": true, "go_version": true, "service": true,
	"function": true, "func": true, "line": true, "proto": true,
}

// keyTime is the time field of the server's own log lines.
const keyTime = "time"

var (
	composePrefixRE = regexp.MustCompile(`^([A-Za-z0-9_.-]{1,64})\s+\| `)
	dockerTimeRE    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) `)
	logfmtPairRE    = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.-]*)=("(?:[^"\\]|\\.)*"|[^\s]*)`)
	identifierValRE = regexp.MustCompile(`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\d{1,20}|[a-z][a-z0-9_]{0,31})$`)
	safeWordRE      = regexp.MustCompile(`^[A-Za-z0-9_.:+-]{0,64}$`)
	// A dotted or word-like value that is one of the code's own words.
	verbatimValRE = regexp.MustCompile(`^[A-Za-z0-9_.:@/{}+ -]{0,160}$`)
)

var lineTimeRE = regexp.MustCompile(`(?:"(?:time|ts|timestamp|@timestamp)"\s*:\s*"|\b(?:time|ts)=)(\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2}))`)

// LineTime returns the time a log line carries without masking it: the
// container runtime's timestamp in front of it, or its own time field. Zero
// when it carries none.
func LineTime(line string) time.Time {
	if m := composePrefixRE.FindString(line); m != "" {
		line = line[len(m):]
	}
	if m := dockerTimeRE.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
			return t
		}
	}
	head := line
	if len(head) > 512 {
		head = head[:512]
	}
	if m := lineTimeRE.FindStringSubmatch(head); m != nil {
		if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
			return t
		}
	}
	return time.Time{}
}

// LogLine masks one log line and reports the time it carries (zero when it
// carries none this function understands).
func (r *Redactor) LogLine(line string) (string, time.Time) {
	line = strings.TrimRight(line, "\r\n")
	var prefix string
	var at time.Time
	if m := composePrefixRE.FindStringSubmatch(line); m != nil {
		// The container name is the Compose service name; a project name in
		// front of it is the operator's choice, so only the last words stay.
		prefix, line = serviceOf(m[1])+" | ", line[len(m[0]):]
	}
	if m := dockerTimeRE.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
			at = t
		}
		prefix, line = prefix+m[1]+" ", line[len(m[0]):]
	}
	var out string
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}"):
		var obj map[string]any
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&obj); err == nil && !dec.More() {
			if t := lineTime(obj); !t.IsZero() {
				at = t
			}
			out = r.jsonLine(obj)
			break
		}
		out = r.Message(line)
	case isLogfmt(trimmed):
		var t time.Time
		out, t = r.logfmtLine(trimmed)
		if !t.IsZero() {
			at = t
		}
	default:
		out = r.Message(line)
	}
	out = prefix + out
	if len(out) > MaxLineBytes {
		out = out[:MaxLineBytes] + " [line cut]"
	}
	return out, at
}

// serviceOf keeps the service part of a Compose container name
// ("project-api-1" becomes "api-1"): the project name is free text.
func serviceOf(name string) string {
	parts := strings.Split(name, "-")
	if n := len(parts); n >= 3 && isDigits(parts[n-1]) {
		return parts[n-2] + "-" + parts[n-1]
	}
	if !safeWordRE.MatchString(name) {
		return "service"
	}
	return name
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func lineTime(obj map[string]any) time.Time {
	for _, k := range []string{keyTime, "ts", "timestamp", "@timestamp"} {
		switch v := obj[k].(type) {
		case string:
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				return t
			}
		case json.Number:
			if f, err := v.Float64(); err == nil && f > 1e9 && f < 1e11 {
				return time.Unix(int64(f), 0).UTC()
			}
		}
	}
	return time.Time{}
}

func (r *Redactor) jsonLine(obj map[string]any) string {
	clean := r.object(obj)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(clean); err != nil {
		return r.Mark(KindValue, "unencodable line")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (r *Redactor) object(obj map[string]any) map[string]any {
	out := make(map[string]any, len(obj))
	for k, v := range obj {
		out[r.keyName(k)] = r.field(k, v)
	}
	return out
}

// keyName keeps a field name that is a plain word; a name that is not (a
// header name carrying a value, a map keyed by host) is masked.
func (r *Redactor) keyName(k string) string {
	if safeWordRE.MatchString(k) && r.Text(k) == k {
		return k
	}
	return r.Mark(KindValue, k)
}

func (r *Redactor) field(key string, v any) any {
	switch class := classify(key); class {
	case classWhole:
		return r.whole(v)
	case classIdentifier:
		if s, ok := v.(string); ok && !identifierValRE.MatchString(s) && !isTime(s) {
			return r.Mark(KindValue, s)
		}
	}
	switch t := v.(type) {
	case string:
		if verbatimKeys[strings.ToLower(key)] && verbatimValRE.MatchString(t) {
			return r.verbatim(t)
		}
		return r.Message(t)
	case map[string]any:
		return r.object(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = r.field(key, e)
		}
		return out
	default:
		// Numbers, booleans and null carry no text.
		return v
	}
}

// verbatim masks secrets, e-mails and addresses but keeps dotted words.
func (r *Redactor) verbatim(s string) string {
	masked := r.Text(s)
	if masked == s {
		return s
	}
	// Only host marks may be undone: compare with the text masked by every
	// rule but the host rule.
	return r.Code(s)
}

func (r *Redactor) whole(v any) any {
	switch t := v.(type) {
	case nil, bool, json.Number, float64:
		return v
	case string:
		if t == "" {
			return t
		}
		return r.Mark(KindValue, t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return r.Mark(KindValue, "unencodable")
		}
		return r.Mark(KindValue, string(b))
	}
}

const (
	classText = iota
	classWhole
	classIdentifier
)

// classify decides how a field is masked from the words of its name.
func classify(key string) int {
	words := keyWords(key)
	if len(words) == 0 {
		return classWhole
	}
	last := words[len(words)-1]
	sensitive := false
	for _, w := range words {
		if wholeTokens[w] {
			sensitive = true
		}
	}
	if !sensitive {
		return classText
	}
	if safeSuffixes[last] && !wholeTokens[last] {
		return classIdentifier
	}
	return classWhole
}

// keyWords splits a field name into lower-case words at separators and at
// camel-case boundaries.
func keyWords(key string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(key)
	for i, c := range runes {
		switch {
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			flush()
		case unicode.IsUpper(c) && i > 0 && unicode.IsLower(runes[i-1]):
			flush()
			cur = append(cur, c)
		default:
			cur = append(cur, c)
		}
	}
	flush()
	return words
}

func isTime(s string) bool {
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

func isLogfmt(line string) bool {
	if !strings.HasPrefix(line, "time=") && !strings.HasPrefix(line, "level=") && !strings.HasPrefix(line, "ts=") {
		return false
	}
	return len(logfmtPairRE.FindAllStringIndex(line, 3)) >= 2
}

func (r *Redactor) logfmtLine(line string) (string, time.Time) {
	var at time.Time
	matches := logfmtPairRE.FindAllStringSubmatchIndex(line, -1)
	var b strings.Builder
	prev := 0
	for _, m := range matches {
		// Text between pairs is free text.
		b.WriteString(r.Message(line[prev:m[0]]))
		key, raw := line[m[2]:m[3]], line[m[4]:m[5]]
		val, quoted := raw, false
		if len(raw) >= 2 && raw[0] == '"' {
			quoted = true
			if err := json.Unmarshal([]byte(raw), &val); err != nil {
				val = raw[1 : len(raw)-1]
			}
		}
		if key == keyTime || key == "ts" {
			if t, err := time.Parse(time.RFC3339Nano, val); err == nil {
				at = t
			}
		}
		var masked string
		switch v := r.field(key, val).(type) {
		case string:
			masked = v
		default:
			masked = r.Mark(KindValue, val)
		}
		b.WriteString(r.keyName(key))
		b.WriteByte('=')
		if quoted || strings.ContainsAny(masked, " \t\"") {
			q, _ := json.Marshal(masked)
			b.Write(q)
		} else {
			b.WriteString(masked)
		}
		prev = m[1]
	}
	b.WriteString(r.Message(line[prev:]))
	return b.String(), at
}

// SortedKeys returns the keys of m in order (stable output for tests and
// manifests).
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
