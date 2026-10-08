package httpsec

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"unicode"
)

// maxUpstreamSnippet bounds the part of an upstream error body that is logged.
const maxUpstreamSnippet = 256

// UpstreamStatusError is the error an outbound integration client returns for
// an unexpected HTTP status. It carries the provider and the status only: the
// response body of a third-party service is never put into an error, because
// errors reach API responses, audit entries and the tenant's UI, and a body can
// echo request data, tokens or internal details of the upstream (RFC-049 F-2).
// The body is logged at debug level only, bounded and sanitized, by
// NewUpstreamStatusError.
type UpstreamStatusError struct {
	Provider string
	Status   int
}

func (e *UpstreamStatusError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d", e.Provider, e.Status)
}

// NewUpstreamStatusError logs a bounded, sanitized snippet of body at debug
// level (status and provider at the same line) and returns an error that
// holds no part of it.
func NewUpstreamStatusError(ctx context.Context, provider string, status int, body []byte) *UpstreamStatusError {
	slog.Default().DebugContext(ctx, "upstream error response",
		"provider", provider, "status", status, "body_snippet", BodySnippet(body))
	return &UpstreamStatusError{Provider: provider, Status: status}
}

// BodySnippet returns at most maxUpstreamSnippet runes of body with control
// and bidi-formatting characters replaced, for debug logs only.
func BodySnippet(body []byte) string {
	var b strings.Builder
	n := 0
	for _, r := range string(body) {
		if n >= maxUpstreamSnippet {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
