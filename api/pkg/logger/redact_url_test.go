package logger

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// A presigned release-asset link as net/http quotes it in a fetch error.
const presigned = `https://release-assets.githubusercontent.com/github-production-release-asset/1412195454/2029b8c5?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-11-01T21%3A50%3A57Z&rscd=attachment%3B+filename%3Dlatest.v2.dsse.json&skoid=96c2d410&sktid=398a6654&skt=2026-11-01T20&sig=UUs2wDCn%2BPJk09fC6NGje3eEnSitnWaV9BuSbOTN3VU%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIn0.T7qHjh&response-content-type=application%2Foctet-stream`

var secretParts = []string{"sig=", "jwt=", "skoid", "sktid", "UUs2wDCn", "eyJ0eXAi", "se=2026"}

func TestRedactURLs(t *testing.T) {
	cases := []struct{ in, want string }{
		{`Get "` + presigned + `": read tcp 172.30.84.2:38184->185.199.109.133:443: read: connection reset by peer`,
			`Get "https://release-assets.githubusercontent.com/github-production-release-asset/1412195454/2029b8c5?[REDACTED]": read tcp 172.30.84.2:38184->185.199.109.133:443: read: connection reset by peer`},
		{"dial https://user:pa55@mirror.example:8443/feed/x.json failed", "dial https://[REDACTED]@mirror.example:8443/feed/x.json failed"},
		{"proxyconnect http://u:p@10.0.0.1:3128?x=1", "proxyconnect http://[REDACTED]@10.0.0.1:3128?[REDACTED]"},
		{"https://h/p#frag-token", "https://h/p?[REDACTED]"},
		{"https://h/path/user@example", "https://h/path/user@example"},
		{"https://h/p?email=a@b.c", "https://h/p?[REDACTED]"},
		{"Get \"https://www.cisa.gov/feeds/kev.json\": dial tcp [2600:1413::1]:443: connect: network is unreachable", "Get \"https://www.cisa.gov/feeds/kev.json\": dial tcp [2600:1413::1]:443: connect: network is unreachable"},
		{"no url here: a=b?c", "no url here: a=b?c"},
		{"two: https://a/x?k=1 and http://b/y?t=2", "two: https://a/x?[REDACTED] and http://b/y?[REDACTED]"},
	}
	for _, c := range cases {
		if got := RedactURLs(c.in); got != c.want {
			t.Errorf("RedactURLs(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func assertNoSecrets(t *testing.T, where, out string) {
	t.Helper()
	for _, p := range secretParts {
		if strings.Contains(out, p) {
			t.Fatalf("%s leaks %q: %s", where, p, out)
		}
	}
}

// Every logged error passes the handler: a fetch error (a *url.Error, wrapped
// as callers do) logged under any key loses its query string, the message and
// string attributes too, in both output formats.
func TestLoggerRedactsURLCredentials(t *testing.T) {
	ue := &url.Error{Op: "Get", URL: presigned, Err: errors.New("read: connection reset by peer")}
	wrapped := fmt.Errorf("vulnfeed fetch keyset.dsse.json: %w", ue)
	for _, format := range []string{"json", "text"} {
		var buf bytes.Buffer
		l := New(Config{Level: "debug", Format: format, Output: &buf})
		l.Warn("transfer: origin failed", "err", ue)
		l.Warn("vulnerability bundle not imported", "error", wrapped)
		l.WithError(wrapped).Info("with error")
		l.Info("fetch "+presigned, "url", presigned)
		l.Stdlib().Info("library logger", "err", ue) // what ctis/transfer receives
		out := buf.String()
		assertNoSecrets(t, format, out)
		if !strings.Contains(out, "release-assets.githubusercontent.com/github-production-release-asset/1412195454/2029b8c5") {
			t.Fatalf("%s: host and path must stay: %s", format, out)
		}
		if !strings.Contains(out, "connection reset by peer") {
			t.Fatalf("%s: the cause must stay: %s", format, out)
		}
	}
}

func TestSanitizeErrorRedactsURLs(t *testing.T) {
	err := &url.Error{Op: "Get", URL: presigned, Err: errors.New("i/o timeout")}
	assertNoSecrets(t, "SanitizeError", SanitizeError(err))
	assertNoSecrets(t, "RedactText", RedactText(err.Error()))
}
