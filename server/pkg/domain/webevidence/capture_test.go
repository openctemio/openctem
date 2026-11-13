package webevidence

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"
)

func pngB64(t *testing.T, w, h int, trailer []byte) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	buf.Write(trailer)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestNormalize(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	raw := map[string]any{
		"url":          "https://user:pw@app.example.com/login",
		"final_url":    "javascript:alert(1)",
		"status_code":  float64(200),
		"title":        "Sign in\n\x1b[31mevil",
		"content_type": "text/html",
		"snippet":      "<html>token=abcdef1234567890abcdef Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl</html>",
		"captured_at":  "2026-10-11T11:00:00Z",
		"screenshot":   map[string]any{"data": pngB64(t, 4, 3, []byte("<?php system($_GET[1]); ?>"))},
	}
	c, err := Normalize(raw, "screenshot", now, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.URL != "https://app.example.com/login" {
		t.Errorf("credentials kept in url: %s", c.URL)
	}
	if c.FinalURL != "" {
		t.Errorf("non-http final url kept: %s", c.FinalURL)
	}
	if strings.ContainsAny(c.Title, "\n\x1b") {
		t.Errorf("control characters kept in title: %q", c.Title)
	}
	if strings.Contains(c.Snippet, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("credential kept in snippet: %s", c.Snippet)
	}
	if c.CapturedAt != time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC) || c.StatusCode != 200 {
		t.Errorf("fields: %+v", c)
	}
	if c.Screenshot == nil || c.Screenshot.Width != 4 || c.Screenshot.Height != 3 {
		t.Fatalf("screenshot: %+v", c.Screenshot)
	}
	if bytes.Contains(c.Screenshot.Data, []byte("php")) {
		t.Error("appended payload survived the re-encode")
	}
	off, err := Normalize(raw, "screenshot", now, false)
	if err != nil || off.Screenshot != nil {
		t.Errorf("screenshot kept with the switch off: %v %+v", err, off.Screenshot)
	}
}

func TestNormalizeRefuses(t *testing.T) {
	now := time.Now()
	for _, u := range []string{"", "ftp://x.example.com", "/relative", "https://" + strings.Repeat("a", MaxURLBytes)} {
		if _, err := Normalize(map[string]any{"url": u}, "", now, true); err == nil {
			t.Errorf("url %.40q accepted", u)
		}
	}
	// Future or ancient capture times fall back to now.
	c, _ := Normalize(map[string]any{"url": "https://a.example.com", "captured_at": "2099-01-01T00:00:00Z"}, "", now, true)
	if !c.CapturedAt.Equal(now) {
		t.Errorf("future capture time kept: %v", c.CapturedAt)
	}
	// Long snippets are cut and marked.
	c, _ = Normalize(map[string]any{"url": "https://a.example.com", "snippet": strings.Repeat("é", MaxSnippetBytes)}, "", now, true)
	if len(c.Snippet) > MaxSnippetBytes || !c.SnippetTruncated {
		t.Errorf("snippet %d bytes, truncated=%v", len(c.Snippet), c.SnippetTruncated)
	}
}

func TestDecodeScreenshotRefuses(t *testing.T) {
	cases := map[string]string{
		"not base64": "%%%",
		"not image":  base64.StdEncoding.EncodeToString([]byte("GIF89a....")),
		"svg":        base64.StdEncoding.EncodeToString([]byte("<svg onload=alert(1)>")),
		"too wide":   pngB64(t, MaxScreenshotWidth+1, 1, nil),
		"too large":  base64.StdEncoding.EncodeToString(append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, MaxScreenshotBytes)...)),
		"truncated":  base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nxx")),
	}
	for name, b := range cases {
		if _, err := DecodeScreenshot(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFromProperty(t *testing.T) {
	now := time.Now()
	items := make([]any, 0, 8)
	for i := 0; i < 7; i++ {
		items = append(items, map[string]any{"url": "https://a.example.com/"})
	}
	items = append(items, "garbage")
	got, skipped := FromProperty(items, "httpx", now, false)
	if len(got) != MaxCapturesPerAsset || skipped != 3 {
		t.Fatalf("got %d skipped %d", len(got), skipped)
	}
	if got, skipped := FromProperty("nope", "", now, false); got != nil || skipped != 1 {
		t.Fatal("non-list accepted")
	}
}
