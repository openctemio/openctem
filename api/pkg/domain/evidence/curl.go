package evidence

import (
	"strings"
)

// Curl builds a reproduction command from an exchange's request. It is built
// from the stored (masked) item, so placeholders stay placeholders; the web
// client substitutes revealed values only on "Copy curl with secrets". Every
// argument is single-quoted, so no part of the request can break out of it.
func Curl(it Item) string {
	if it.HTTP == nil || it.HTTP.Request == nil || it.HTTP.Request.URL == "" {
		return ""
	}
	q := it.HTTP.Request
	var b strings.Builder
	b.WriteString("curl -sS -i")
	if q.Method != "" && q.Method != "GET" {
		b.WriteString(" -X ")
		b.WriteString(shellQuote(q.Method))
	}
	for _, h := range q.Headers {
		switch strings.ToLower(h.Name) {
		case "host", "content-length", "connection":
			continue
		}
		b.WriteString(" -H ")
		b.WriteString(shellQuote(h.Name + ": " + h.Value))
	}
	if q.Body != "" && q.BodyEncoding == "" {
		b.WriteString(" --data-binary ")
		b.WriteString(shellQuote(q.Body))
	}
	b.WriteString(" ")
	b.WriteString(shellQuote(q.URL))
	return b.String()
}

// shellQuote single-quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
