package apierror

import (
	"log/slog"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The message of an error response is English fallback text for a person.
// The web picks the words it shows from the code (errors.<CODE> in its
// dictionaries); the message is what an API client, a CI log or an
// untranslated code shows instead. It must therefore never carry what only
// the server should see: entity ids, SQL and driver errors, dial errors with
// internal hosts, file paths, Go type names or an upstream service's raw
// body. Those belong in the server log, next to the request id the response
// carries.
//
// Every response is written through publicMessage, so a call site that
// still passes err.Error() or formats an id into a message cannot leak it:
//   - a message with technical text is replaced whole by the code's default
//     message, and the original goes to the log with the request id;
//   - UUIDs are cut out (a reference by id means nothing to a person; the
//     page already names the thing);
//   - the generic prefixes of the shared domain errors ("validation error: ")
//     are dropped.
//
// tools/lint/errleak keeps new call sites from relying on this net.

// maxMessageRunes caps a message; anything longer is not a sentence a person
// reads in a toast.
const maxMessageRunes = 300

var (
	uuidRe = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

	// technicalRe matches text that only makes sense to the server: SQL and
	// driver errors, network and TLS errors, Go runtime and encoding errors,
	// absolute paths, loopback or cluster-internal hosts and raw HTML/JSON
	// bodies from an upstream.
	technicalRe = regexp.MustCompile(`(?i)(` + strings.Join([]string{
		`sqlstate`, `\bpq: `, `\bpgx\b`, `pgconn`, `\bsql: `, `duplicate key value`,
		`violates [a-z -]*constraint`, `null value in column`, `\brelation "`, `\bcolumn "`,
		`syntax error at or near`, `deadlock detected`, `canceling statement`, `current transaction is aborted`,
		`\bdial (tcp|udp)\b`, `\blookup [^ ]+ on `, `no such host`, `connection refused`, `connection reset`,
		`i/o timeout`, `broken pipe`, `context deadline exceeded`, `context canceled`, `client\.timeout exceeded`,
		`\bx509: `, `\btls: `, `remote error: `, `unexpected eof`, `\bnet/http: `, `\bredis: `,
		`runtime error`, `invalid memory address`, `nil pointer`, `\bgoroutine \d`, `\bpanic\b`, `%!`,
		`\.go:\d+`, `json: cannot unmarshal`, `go struct field`, `invalid character '.' (looking|after|in)`,
		`\*errors\.`, `<nil>`, `\bmap\[`, `cipher: `, `crypto/`, `0x[0-9a-f]{6,}`,
		`(^|[\s"'(=])/(home|var|tmp|etc|usr|app|opt|root|proc|srv)/`, `\b[a-z]:\\\\`,
		`\blocalhost:\d+`, `\b127\.0\.0\.1\b`, `\.svc\.cluster\.local`, `\bopenctemio-[a-z]`,
		`<html`, `<!doctype`, `\{"[a-z_]+"\s*:`,
	}, "|") + `)`)

	// genericPrefixRe is the text of the shared domain sentinels
	// (pkg/domain/shared) that fmt.Errorf("%w: ...") puts in front.
	genericPrefixRe = regexp.MustCompile(`(?i)^(validation error|invalid input|not found|conflict|forbidden|unauthorized|already exists|internal error)\s*:\s*`)

	// Left over around a removed UUID: "(id )", "id:", "with id".
	idHoleRe   = regexp.MustCompile(`(?i)\s*\(\s*(?:id\s*[:=]?\s*)?\x00\s*\)|(?:\s+(?:with\s+)?(?:id|ID)\s*[:=]?)?\s*\x00`)
	spacesRe   = regexp.MustCompile(`\s{2,}`)
	spacePunct = regexp.MustCompile(`\s+([,.;:)])`)
	quoteHole  = regexp.MustCompile(`["'“”]\s*["'“”]`)
)

// IsTechnical reports whether a message carries text that only the server
// should see (SQL, network, runtime, paths, internal hosts, raw bodies).
func IsTechnical(msg string) bool {
	return technicalRe.MatchString(msg)
}

// ContainsUUID reports whether s carries a UUID.
func ContainsUUID(s string) bool {
	return uuidRe.MatchString(s)
}

// SafeMessage returns the text a response may carry for msg, and whether it
// had to change it. A technical message becomes DefaultMessage(code,
// status); UUIDs are cut out; generic sentinel prefixes are dropped.
func SafeMessage(code Code, status int, msg string) (string, bool) {
	orig := msg
	if strings.TrimSpace(msg) == "" || IsTechnical(msg) {
		return DefaultMessage(code, status), true
	}
	for {
		next := genericPrefixRe.ReplaceAllString(msg, "")
		if next == msg {
			break
		}
		msg = next
	}
	if uuidRe.MatchString(msg) {
		msg = uuidRe.ReplaceAllString(msg, "\x00")
		msg = idHoleRe.ReplaceAllString(msg, "")
		msg = strings.ReplaceAll(msg, "\x00", "")
		msg = quoteHole.ReplaceAllString(msg, "")
	}
	msg = spacePunct.ReplaceAllString(msg, "$1")
	msg = strings.TrimSpace(spacesRe.ReplaceAllString(msg, " "))
	msg = strings.TrimLeft(msg, ":;,. ")
	if msg == "" {
		return DefaultMessage(code, status), true
	}
	if utf8.RuneCountInString(msg) > maxMessageRunes {
		r := []rune(msg)
		msg = strings.TrimSpace(string(r[:maxMessageRunes-1])) + "…"
	}
	if msg != orig {
		msg = capitalizeWord(msg)
	}
	return msg, msg != orig
}

// publicMessage is the message a response carries. When it differs from
// what the call site passed, the original goes to the log (never to the
// client) with the request id, so the cause is still found.
func (e *Error) publicMessage(requestID string) string {
	msg, changed := SafeMessage(e.Code, e.Status, e.Message)
	if changed && IsTechnical(e.Message) {
		slog.Default().Warn("apierror: technical text kept out of an error response",
			"code", string(e.Code), "status", e.Status, "request_id", requestID, "original", e.Message)
	}
	return msg
}

// capitalizeWord starts a sentence that lost its prefix with a capital,
// unless the first word is a name such as a host, a path or an identifier.
func capitalizeWord(msg string) string {
	first, _, _ := strings.Cut(msg, " ")
	if strings.ContainsAny(first, "./:_-@0123456789") {
		return msg
	}
	if r, n := utf8.DecodeRuneInString(msg); unicode.IsLower(r) {
		return string(unicode.ToUpper(r)) + msg[n:]
	}
	return msg
}
