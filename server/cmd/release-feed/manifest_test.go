package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testDigest = "sha256:0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"

// manifestFixture writes a feed payload and the other inputs of `manifest`.
func manifestFixture(t *testing.T) (string, func(string) string) {
	t.Helper()
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	write := func(n, body string) {
		if err := os.WriteFile(p(n), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// v0.9.10 sorts above v0.9.9 by version, whatever the list order.
	write("releases.json", `[
	  {"tagName":"v0.9.9","publishedAt":"2026-10-16T10:00:00Z"},
	  {"tagName":"v0.9.10","publishedAt":"2026-10-15T10:00:00Z"},
	  {"tagName":"v0.9.11","publishedAt":"2026-10-17T10:00:00Z","isPrerelease":true}]`)
	write("components.json", `[
	  {"component":"sensor","version":"v0.41.0","published_at":"2026-10-15T10:00:00Z","digest":"`+testDigest+`"},
	  {"component":"sdk","version":"v0.50.0","published_at":"2026-10-15T10:00:00Z"},
	  {"component":"ci","version":"v0.4.0","published_at":"2026-10-15T10:00:00Z","digest":"`+testDigest+`"}]`)
	runOK(t, "build", "-releases", p("releases.json"), "-components", p("components.json"), "-out", p("feed.json"))
	write("images.txt", "# name source-reference index-digest archive archive-sha256\n"+
		"openctem ghcr.io/openctemio/openctem:v0.9.10 "+testDigest+" a.oci.tar 00\n"+
		"openctem-api ghcr.io/openctemio/openctem-api:v0.9.10 "+testDigest+" b.oci.tar 00\n")
	write("versions.yaml", `sensor:
  product: openctemio-sensor
  latest: v0.41.0
  min: v0.36.0
  image: ghcr.io/openctemio/sensor
  install: sensor
  release_identity: https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml
sdk:
  latest: v0.50.0
  min: v0.46.0
  advisories: ""
ci:
  latest: v0.4.0
  min: v0.4.0
`)
	write("compat.json", `{"requires":[
	  {"component":"sensor","from":"v0.40.0","platform":"v0.9.10","reason":"signed pairing answers"},
	  {"component":"sensor","from":"v0.38.0","platform":"v0.9.9","reason":"sealed task secrets"},
	  {"component":"sensor","from":"v0.42.0","platform":"v1.0.0","reason":"a later release"}]}`)
	write("index.yaml", `apiVersion: v1
entries:
  openctem:
  - version: 0.41.1
    appVersion: v0.9.10
  - version: 0.42.0-rc.1
    appVersion: v0.9.11
  - version: 0.9.0
    appVersion: v0.1.0
  other:
  - version: 9.9.9
    appVersion: v9.9.9
`)
	return dir, p
}

func TestManifest(t *testing.T) {
	_, p := manifestFixture(t)
	if got := strings.TrimSpace(runOK(t, "platform", "-feed", p("feed.json"))); got != "v0.9.10" {
		t.Fatalf("platform = %q, want the newest stable release by version", got)
	}
	runOK(t, "manifest", "-feed", p("feed.json"), "-images", p("images.txt"), "-versions", p("versions.yaml"),
		"-compat", p("compat.json"), "-chart-index", p("index.yaml"), "-out", p("m.json"))
	raw, _ := os.ReadFile(p("m.json"))
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Schema != ManifestSchema || m.Platform.Version != "v0.9.10" || len(m.Platform.Previous) != 1 {
		t.Fatalf("platform: %+v", m.Platform)
	}
	if len(m.Platform.Images) != 2 || m.Platform.Images[0].Digest != testDigest {
		t.Fatalf("images: %+v", m.Platform.Images)
	}
	if m.Platform.Accepts["sensor"] != "v0.36.0" || m.Platform.Accepts["sdk"] != "v0.46.0" || m.Platform.Accepts["ci"] != "v0.4.0" {
		t.Fatalf("accepts: %+v", m.Platform.Accepts)
	}
	if m.Chart.Version != "0.41.1" || m.Chart.AppVersion != "v0.9.10" {
		t.Fatalf("chart: %+v (a pre-release or another chart was picked)", m.Chart)
	}
	var sensor ManifestComponent
	for _, c := range m.Components {
		if c.Component == "sensor" {
			sensor = c
		}
	}
	// The highest platform of the entries that apply; an entry from a later
	// sensor release does not apply.
	if sensor.RequiresPlatform != "v0.9.10" || len(sensor.Requirements) != 2 || sensor.Repository != "openctemio/sensor" {
		t.Fatalf("sensor: %+v", sensor)
	}
	if strings.Contains(string(raw), "rc.1") || strings.Contains(string(raw), "v0.9.11") {
		t.Fatalf("a pre-release reached the manifest: %s", raw)
	}
}

func TestManifestRefusals(t *testing.T) {
	_, p := manifestFixture(t)
	base := map[string]string{"-feed": p("feed.json"), "-images": p("images.txt"), "-versions": p("versions.yaml"),
		"-compat": p("compat.json"), "-chart-index": p("index.yaml")}
	bad := map[string][2]string{
		"image of another release": {"-images", "openctem ghcr.io/openctemio/openctem:v0.9.9 " + testDigest + "\n"},
		"foreign image":            {"-images", "openctem docker.io/evil/openctem:v0.9.10 " + testDigest + "\n"},
		"bad digest":               {"-images", "openctem ghcr.io/openctemio/openctem:v0.9.10 sha256:00\n"},
		"no image":                 {"-images", "# nothing\n"},
		"unknown compat component": {"-compat", `{"requires":[{"component":"x","from":"v1.0.0","platform":"v1.0.0","reason":"r"}]}`},
		"compat without reason":    {"-compat", `{"requires":[{"component":"sensor","from":"v1.0.0","platform":"v1.0.0","reason":""}]}`},
		"compat unknown field":     {"-compat", `{"requires":[],"extra":1}`},
		"no stable chart":          {"-chart-index", "entries:\n  openctem:\n  - version: 1.0.0-rc.1\n    appVersion: v1.0.0\n"},
	}
	for name, c := range bad {
		args := []string{"manifest", "-out", p("bad.json")}
		for k, v := range base {
			if k == c[0] {
				_ = os.WriteFile(p("bad-input"), []byte(c[1]), 0o600)
				v = p("bad-input")
			}
			args = append(args, k, v)
		}
		if err := run(args, &bytes.Buffer{}, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := run([]string{"manifest", "-feed", p("feed.json")}, &bytes.Buffer{}, now); err == nil {
		t.Error("accepted missing inputs")
	}
}

// The committed compatibility file is valid and names known components.
func TestCommittedCompat(t *testing.T) {
	if _, err := readCompat(filepath.Join("..", "..", "..", ".github", "release-feed", "compat.json")); err != nil {
		t.Fatal(err)
	}
}
