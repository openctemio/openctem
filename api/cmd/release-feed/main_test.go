package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func runOK(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(args, &out, now); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.String()
}

// build writes the payload to sign, assemble joins it with a Sigstore bundle,
// and verify refuses a bundle the embedded trusted root does not know.
func TestBuildAssembleVerify(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	releases := `[
	  {"tagName":"v0.9.8","publishedAt":"2026-10-15T10:00:00Z","isDraft":false,"isPrerelease":false},
	  {"tagName":"v0.9.9-rc.1","publishedAt":"2026-10-15T11:00:00Z","isDraft":false,"isPrerelease":true},
	  {"tagName":"v1.0.0","publishedAt":"0001-01-01T00:00:00Z","isDraft":true,"isPrerelease":false},
	  {"tagName":"ui/v0.8.0","publishedAt":"2026-01-01T00:00:00Z","isDraft":false,"isPrerelease":false},
	  {"tagName":"v0.9.7","publishedAt":"2026-10-14T10:00:00Z","isDraft":false,"isPrerelease":false}
	]`
	_ = os.WriteFile(p("releases.json"), []byte(releases), 0o600)
	_ = os.WriteFile(p("advisories.json"), []byte(`{"advisories":[{"id":"OCTEM-2026-0001","severity":"high","title":"t","fixed_in":"v0.9.8","published_at":"2026-10-15T10:00:00Z"}]}`), 0o600)
	runOK(t, "build", "-releases", p("releases.json"), "-advisories", p("advisories.json"), "-out", p("feed.json"))
	payload, _ := os.ReadFile(p("feed.json"))
	if !strings.Contains(string(payload), `"v0.9.8"`) || strings.Contains(string(payload), "rc.1") || strings.Contains(string(payload), "ui/") {
		t.Fatalf("payload: %s", payload)
	}
	// A bundle that is not a valid Sigstore bundle assembles (the builder
	// only joins) but verify refuses it: nothing but the trusted root decides.
	_ = os.WriteFile(p("bundle.json"), []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), 0o600)
	runOK(t, "assemble", "-feed", p("feed.json"), "-bundle", p("bundle.json"), "-out", p("openctem-releases.json"))
	if err := run([]string{"verify", p("openctem-releases.json")}, &bytes.Buffer{}, now); err == nil {
		t.Fatal("verified a feed with an empty bundle")
	}
	_ = os.WriteFile(p("notjson.json"), []byte(`nope`), 0o600)
	if err := run([]string{"assemble", "-feed", p("feed.json"), "-bundle", p("notjson.json"), "-out", p("x.json")}, &bytes.Buffer{}, now); err == nil {
		t.Fatal("assembled a bundle that is not JSON")
	}
	if err := run([]string{"keygen", "-out", p("k")}, &bytes.Buffer{}, now); err == nil {
		t.Fatal("the keygen command still exists: the feed has no signing key")
	}
}

func TestBuildRefusals(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "empty.json"), []byte(`[]`), 0o600)
	cases := map[string][]string{
		"days over 45": {"build", "-days", "46"},
		"foreign repo": {"build", "-repo", "someone/else"},
		"no releases":  {"build", "-releases", filepath.Join(dir, "empty.json")},
		"unknown":      {"nope"},
		"keyset gone":  {"keyset", "-root", filepath.Join(dir, "missing")},
	}
	for name, args := range cases {
		if err := run(args, &bytes.Buffer{}, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// components lists every built-in sensor product with its repository and
// image, and the SDK.
func TestComponents(t *testing.T) {
	got := runOK(t, "components")
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) < 2 {
		t.Fatalf("components: %q", got)
	}
	if !strings.Contains(got, "sensor openctemio/sensor ghcr.io/openctemio/sensor\n") {
		t.Fatalf("no scanning sensor line in %q", got)
	}
	if lines[len(lines)-1] != "sdk openctemio/sdk-go -" {
		t.Fatalf("last line %q", lines[len(lines)-1])
	}
	for _, l := range lines {
		if f := strings.Fields(l); len(f) != 3 || !strings.HasPrefix(f[1], "openctemio/") {
			t.Fatalf("line %q", l)
		}
	}
}

// A components file goes into the feed payload; an invalid or unknown-field
// one is refused.
func TestBuildWithComponents(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	_ = os.WriteFile(p("releases.json"), []byte(`[{"tagName":"v0.9.8","publishedAt":"2026-10-15T10:00:00Z"}]`), 0o600)
	digest := "sha256:" + strings.Repeat("0a", 32)
	_ = os.WriteFile(p("components.json"), []byte(`[
	  {"component":"sensor","version":"v0.23.2","published_at":"2026-10-15T10:00:00Z",
	   "notes_url":"https://github.com/openctemio/sensor/releases/tag/v0.23.2","digest":"`+digest+`"},
	  {"component":"sdk","version":"v0.34.0","published_at":"2026-10-15T10:00:00Z"}]`), 0o600)
	runOK(t, "build", "-releases", p("releases.json"),
		"-components", p("components.json"), "-out", p("feed.json"))
	payload, _ := os.ReadFile(p("feed.json"))
	if !strings.Contains(string(payload), `"sensor"`) || !strings.Contains(string(payload), digest) {
		t.Fatalf("payload: %s", payload)
	}

	for name, body := range map[string]string{
		"unknown field": `[{"component":"sensor","version":"v0.23.2","published_at":"2026-10-15T10:00:00Z","image":"evil/x"}]`,
		"bad version":   `[{"component":"sensor","version":"latest","published_at":"2026-10-15T10:00:00Z"}]`,
		"foreign link":  `[{"component":"sensor","version":"v1.0.0","published_at":"2026-10-15T10:00:00Z","notes_url":"https://example.com/"}]`,
		"not an array":  `{"component":"sensor"}`,
	} {
		_ = os.WriteFile(p("bad.json"), []byte(body), 0o600)
		if err := run([]string{"build", "-releases", p("releases.json"),
			"-components", p("bad.json"), "-out", p("bad-feed.json")}, &bytes.Buffer{}, now); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
