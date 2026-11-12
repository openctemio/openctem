package pagemon

import (
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PropertyKey is the reserved asset property that carries fetch results
// (= asset.PropKeyWebContent).
const PropertyKey = "web_content"

// Caps on what a report may carry, whatever the sensor claims.
const (
	MaxCapturesPerReport  = 200
	MaxBodyBytes          = 512 << 10
	MaxBodyBytesPerReport = 24 << 20
	MaxContentTypeBytes   = 100
)

// ErrInvalid marks a capture that cannot be used.
var ErrInvalid = errors.New("invalid web content capture")

// Capture is one validated fetch of a watched URL.
type Capture struct {
	URL           string
	FinalURL      string
	StatusCode    int
	ContentType   string
	Size          int64
	SHA256        string
	Truncated     bool
	Body          string
	BodyTruncated bool
	FetchedAt     time.Time
	Tool          string
}

// Item is one report asset's raw property with the stored asset it resolved to.
type Item struct {
	AssetID shared.ID
	Raw     any
}

// FromProperty reads the captures of one report asset. budget is the body
// bytes the report may still carry; it is reduced by what is kept. Invalid
// captures are skipped and counted.
func FromProperty(v any, tool string, now time.Time, budget *int) (out []Capture, skipped int) {
	list, ok := v.([]any)
	if !ok {
		if v != nil {
			return nil, 1
		}
		return nil, 0
	}
	for _, raw := range list {
		m, ok := raw.(map[string]any)
		if !ok {
			skipped++
			continue
		}
		c, err := Normalize(m, tool, now)
		if err != nil {
			skipped++
			continue
		}
		if budget != nil {
			if len(c.Body) > *budget {
				c.Body, c.BodyTruncated = "", true
			}
			*budget -= len(c.Body)
		}
		out = append(out, c)
	}
	return out, skipped
}

// Normalize validates one raw capture.
func Normalize(m map[string]any, tool string, now time.Time) (Capture, error) {
	c := Capture{Tool: clip(singleLine(tool), 64), FetchedAt: now}
	u, err := NormalizeURL(str(m["url"]))
	if err != nil {
		return Capture{}, ErrInvalid
	}
	c.URL = u
	if fu := str(m["final_url"]); fu != "" {
		if f, ferr := NormalizeURL(fu); ferr == nil && sameHost(u, f) {
			c.FinalURL = f
		}
	}
	if code, ok := num(m["status_code"]); ok && code >= 100 && code <= 599 {
		c.StatusCode = int(code)
	}
	c.ContentType = strings.ToLower(clip(singleLine(str(m["content_type"])), MaxContentTypeBytes))
	if n, ok := num(m["size"]); ok && n >= 0 && n <= 1<<40 {
		c.Size = n
	}
	if h := strings.ToLower(strings.TrimSpace(str(m["sha256"]))); len(h) == 64 {
		if _, herr := hex.DecodeString(h); herr == nil {
			c.SHA256 = h
		}
	}
	c.Truncated, _ = m["truncated"].(bool)
	body := str(m["body"])
	if !utf8.ValidString(body) {
		body = strings.ToValidUTF8(body, "�")
	}
	if len(body) > MaxBodyBytes {
		body = clip(body, MaxBodyBytes)
		c.BodyTruncated = true
	}
	c.Body = body
	if b, ok := m["body_truncated"].(bool); ok && b {
		c.BodyTruncated = true
	}
	if t, perr := time.Parse(time.RFC3339, str(m["fetched_at"])); perr == nil && !t.After(now.Add(time.Minute)) && t.After(now.Add(-7*24*time.Hour)) {
		c.FetchedAt = t.UTC()
	}
	return c, nil
}

// OK reports whether the fetch answered with content worth keeping.
func (c Capture) OK() bool { return c.StatusCode >= 200 && c.StatusCode < 400 }

func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && strings.EqualFold(ua.Hostname(), ub.Hostname())
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if n != n || n > 1<<53 || n < -(1<<53) { // NaN or out of exact range
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

// clip cuts s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func singleLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
