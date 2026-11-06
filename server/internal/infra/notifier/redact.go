package notifier

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Error strings built in this package are not private. They become
// SendResult.Error, which the integration service stores as the integration's
// status_message (returned to every caller with integrations:read), the outbox
// stores as last_error and archives into notification_events, and the workers
// log. Two things must therefore never reach them:
//
//   - the request URL. For several providers the URL is the credential: a
//     Telegram bot token sits in the path (/bot<token>/sendMessage), and a
//     Slack, Teams or generic webhook URL carries its secret in the path or the
//     query. Go's *url.Error prints the full URL ("Post \"https://...\": ..."),
//     so a timeout, a DNS failure or an SSRF-guard refusal would publish it.
//   - an unbounded response body. The receiving endpoint is tenant-controlled;
//     echoing up to 1 MiB of whatever it answers turns the status field into a
//     read channel for the response of any host the URL reaches.

// maxEchoedBody caps how much of a provider's response body an error string
// carries. Enough for a provider's error message, not enough to exfiltrate.
const maxEchoedBody = 256

// redactedSecret replaces a known secret that still appears in an error.
const redactedSecret = "[REDACTED]"

// transportError renders an outbound request error with the request URL
// reduced to scheme and host, and with every given secret scrubbed from what
// remains. Use it for every error that comes from building or sending an HTTP
// request in this package.
func transportError(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		msg = fmt.Sprintf("%s %s: %v", ue.Op, redactURL(ue.URL), ue.Err)
	}
	return scrubSecrets(msg, secrets...)
}

// redactURL keeps only the scheme and host of raw, which is enough to tell
// the operator which endpoint failed without exposing a path- or query-borne
// credential.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<url>"
	}
	return u.Scheme + "://" + u.Host
}

// echoBody returns at most maxEchoedBody bytes of a response body for an error
// string, cut on a rune boundary, with every given secret scrubbed.
func echoBody(body []byte, secrets ...string) string {
	truncated := false
	if len(body) > maxEchoedBody {
		body = body[:maxEchoedBody]
		for len(body) > 0 && !utf8.Valid(body) {
			body = body[:len(body)-1]
		}
		truncated = true
	}
	s := scrubSecrets(strings.TrimSpace(string(body)), secrets...)
	if truncated {
		s += " (truncated)"
	}
	return s
}

func scrubSecrets(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, redactedSecret)
	}
	return s
}
