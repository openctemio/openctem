package logger

import (
	"regexp"
	"strings"
)

// urlRe finds an absolute URL inside free text. It stops at white space and
// at the quote and angle characters that delimit a URL in an error message
// (net/http quotes it: Get "https://host/path?query": ...).
var urlRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)

// RedactURLs removes the parts of every URL in s that carry credentials: the
// userinfo (user:password@) and the whole query string and fragment, which is
// where presigned download links (object storage, release assets) put their
// signature, token and key parameters. Scheme, host, port and path stay, so
// the text still says which endpoint failed. Text without a URL is returned
// unchanged.
func RedactURLs(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return urlRe.ReplaceAllStringFunc(s, redactURL)
}

func redactURL(u string) string {
	i := strings.Index(u, "://") + len("://")
	scheme, rest := u[:i], u[i:]
	// Authority ends at the first '/', '?' or '#'.
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
		rest = redacted + "@" + rest[at+1:]
	}
	if q := strings.IndexAny(rest, "?#"); q >= 0 {
		rest = rest[:q] + "?" + redacted
	}
	return scheme + rest
}
