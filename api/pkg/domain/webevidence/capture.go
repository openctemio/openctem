// Package webevidence is what a web asset looked like when a sensor fetched
// it: the final URL, status, title, a short masked response snippet and,
// when the organization turned screenshots on, a screenshot.
// Design: docs/rfcs/RFC-081-web-evidence-screenshots.md.
//
// A sensor sends captures in the reserved asset property `web_evidence`.
// Everything in it is hostile input: every field is capped, the snippet is
// masked like finding evidence, and a screenshot is decoded and re-encoded
// as a fresh PNG (no metadata, no appended payload) within strict size and
// dimension limits before anything is stored.
package webevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // decoders for the formats a sensor may send
	"image/png"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PropertyKey is the reserved asset property that carries captures.
const PropertyKey = "web_evidence" // = asset.PropKeyWebEvidence

// Caps, enforced on every capture whatever the sensor claims.
const (
	MaxCapturesPerAsset  = 5
	MaxCapturesPerReport = 50
	MaxURLBytes          = 2048
	MaxTitleBytes        = 300
	MaxServerBytes       = 200
	MaxContentTypeBytes  = 100
	MaxSnippetBytes      = 4 << 10
	// MaxScreenshotBytes bounds the decoded image a sensor sends.
	MaxScreenshotBytes = 1 << 20
	// MaxScreenshotWidth / Height bound the decoded pixels (memory while
	// re-encoding is about width*height*4 bytes).
	MaxScreenshotWidth  = 1920
	MaxScreenshotHeight = 2400
	// ScreenshotRetention is how long a screenshot is kept (decision O7).
	ScreenshotRetention = 30 * 24 * time.Hour
	// Retention is how long the capture text is kept.
	Retention = 365 * 24 * time.Hour
	// ScreenshotMediaType is the only type a stored screenshot has.
	ScreenshotMediaType = "image/png"
)

// ErrInvalid marks a capture that cannot be stored.
var ErrInvalid = errors.New("invalid web evidence")

// Capture is one normalized fetch of a web asset.
type Capture struct {
	URL              string
	FinalURL         string
	StatusCode       int
	Title            string
	Server           string
	ContentType      string
	Snippet          string
	SnippetTruncated bool
	CapturedAt       time.Time
	Tool             string
	// Screenshot is the re-encoded PNG, nil when none was sent or kept.
	Screenshot *Screenshot
}

// Screenshot is a validated, re-encoded PNG.
type Screenshot struct {
	Data          []byte
	SHA256        string
	Width, Height int
}

// FromProperty reads and normalizes the captures of one report asset.
// keepScreenshots is the organization's switch: off drops every image.
// Invalid captures are skipped and counted, never fatal.
func FromProperty(v any, tool string, now time.Time, keepScreenshots bool) (out []Capture, skipped int) {
	list, ok := v.([]any)
	if !ok {
		if v != nil {
			return nil, 1
		}
		return nil, 0
	}
	for _, raw := range list {
		if len(out) >= MaxCapturesPerAsset {
			skipped++
			continue
		}
		m, ok := raw.(map[string]any)
		if !ok {
			skipped++
			continue
		}
		c, err := Normalize(m, tool, now, keepScreenshots)
		if err != nil {
			skipped++
			continue
		}
		out = append(out, c)
	}
	return out, skipped
}

// Normalize validates one raw capture.
func Normalize(m map[string]any, tool string, now time.Time, keepScreenshots bool) (Capture, error) {
	c := Capture{Tool: clip(singleLine(tool), 100), CapturedAt: now}
	var err error
	if c.URL, err = webURL(str(m["url"])); err != nil {
		return Capture{}, err
	}
	if fu := str(m["final_url"]); fu != "" {
		if c.FinalURL, err = webURL(fu); err != nil {
			c.FinalURL = ""
		}
	}
	if code, ok := num(m["status_code"]); ok && code >= 100 && code <= 599 {
		c.StatusCode = code
	}
	c.Title = clip(singleLine(str(m["title"])), MaxTitleBytes)
	c.Server = clip(singleLine(str(m["server"])), MaxServerBytes)
	c.ContentType = clip(singleLine(str(m["content_type"])), MaxContentTypeBytes)
	if t, perr := time.Parse(time.RFC3339, str(m["captured_at"])); perr == nil && !t.After(now.Add(time.Minute)) && t.After(now.Add(-30*24*time.Hour)) {
		c.CapturedAt = t.UTC()
	}
	c.Snippet, c.SnippetTruncated = snippet(str(m["snippet"]))
	if b, ok := m["snippet_truncated"].(bool); ok && b {
		c.SnippetTruncated = true
	}
	if keepScreenshots {
		if s, ok := m["screenshot"].(map[string]any); ok {
			shot, serr := DecodeScreenshot(str(s["data"]))
			if serr == nil {
				c.Screenshot = shot
			}
		}
	}
	return c, nil
}

// DecodeScreenshot decodes a base64 PNG or JPEG within the caps and
// re-encodes it as a PNG. Only the pixels survive.
func DecodeScreenshot(b64 string) (*Screenshot, error) {
	if b64 == "" || base64.StdEncoding.DecodedLen(len(b64)) > MaxScreenshotBytes+3 {
		return nil, fmt.Errorf("%w: screenshot missing or too large", ErrInvalid)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) > MaxScreenshotBytes {
		return nil, fmt.Errorf("%w: screenshot is not base64 within the size cap", ErrInvalid)
	}
	if !bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) && !bytes.HasPrefix(raw, []byte{0xFF, 0xD8, 0xFF}) {
		return nil, fmt.Errorf("%w: screenshot is not a PNG or JPEG", ErrInvalid)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxScreenshotWidth || cfg.Height > MaxScreenshotHeight {
		return nil, fmt.Errorf("%w: screenshot dimensions out of range", ErrInvalid)
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: screenshot does not decode", ErrInvalid)
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("%w: screenshot does not re-encode", ErrInvalid)
	}
	sum := sha256.Sum256(buf.Bytes())
	b := img.Bounds()
	return &Screenshot{Data: buf.Bytes(), SHA256: hex.EncodeToString(sum[:]), Width: b.Dx(), Height: b.Dy()}, nil
}

// webURL accepts an absolute http(s) URL without credentials.
func webURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxURLBytes || !utf8.ValidString(s) {
		return "", fmt.Errorf("%w: url missing or too long", ErrInvalid)
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%w: url must be absolute http or https", ErrInvalid)
	}
	u.User = nil
	return u.String(), nil
}

// snippet keeps the first MaxSnippetBytes of valid UTF-8 text, masked like
// finding evidence (credentials and secret-looking values become
// placeholders; the values are not kept anywhere).
func snippet(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "")
	truncated := false
	if len(s) > MaxSnippetBytes {
		s = clip(s, MaxSnippetBytes)
		truncated = true
	}
	return evidence.RedactText(s), truncated
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), n == float64(int(n))
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

func singleLine(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }), " ")
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

// Record is a stored capture.
type Record struct {
	ID       string
	TenantID string
	AssetID  string
	Capture
	ScreenshotKey       string
	ScreenshotProvider  string
	ScreenshotSHA256    string
	ScreenshotSize      int
	ScreenshotWidth     int
	ScreenshotHeight    int
	ScreenshotExpiresAt *time.Time
	CreatedAt           time.Time
}

// HasScreenshot reports whether a screenshot is stored for the record.
func (r Record) HasScreenshot() bool { return r.ScreenshotKey != "" }

// Item is one report asset's raw captures, resolved to the stored asset the
// report may change.
type Item struct {
	AssetID shared.ID
	Raw     any
}

// BlobRef locates a stored screenshot.
type BlobRef struct {
	TenantID, Provider, Key string
}
