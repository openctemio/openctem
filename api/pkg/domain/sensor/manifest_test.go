package sensor

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const liveManifest = `{
  "schema": 1,
  "sensor": {"name": "openctemio-sensor", "version": "v0.7.0", "commit": "83db392", "build_time": "2026-10-02T09:00:00Z"},
  "sdk": {"name": "openctem-sdk-go", "version": "v0.13.0"},
  "platform": {"os": "linux", "arch": "amd64"},
  "resources": {"cpu_cores": 4, "mem_total_bytes": 8589934592},
  "concurrency": {"ceiling": 0, "model": "dynamic"},
  "capabilities": ["validate"],
  "tools": [
    {"name": "nuclei", "kind": "scanner", "version": "v3.11.1", "installed": true,
     "capabilities": ["dast", "validate:nuclei"], "target_types": ["url", "host", "URL", "bad type"],
     "content": [{"name": "nuclei-templates", "version": "v10.4.9", "managed": true}]},
    {"name": "semgrep", "kind": "scanner", "version": "1.179.0", "installed": true, "capabilities": ["sast"]},
    {"name": "trivy", "kind": "scanner", "installed": false, "capabilities": ["sca"]}
  ]
}`

// The digest is over the canonical document: member order and whitespace do
// not change it, a value does.
func TestManifestDigestCanonical(t *testing.T) {
	a, err := ManifestDigest([]byte(`{"schema":1,"tools":[{"name":"nuclei","installed":true}],"capabilities":["validate"]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ManifestDigest([]byte("{\n \"capabilities\": [\"validate\"],\n \"tools\": [{\"installed\": true, \"name\": \"nuclei\"}],\n \"schema\": 1\n}"))
	if a != b {
		t.Fatalf("reordered document: %s != %s", a, b)
	}
	if !strings.HasPrefix(a, "sha256:") || len(a) != len("sha256:")+64 {
		t.Fatalf("digest format %q", a)
	}
	c, _ := ManifestDigest([]byte(`{"schema":1,"tools":[{"name":"nuclei","installed":false}],"capabilities":["validate"]}`))
	if a == c {
		t.Fatal("a changed value kept the digest")
	}
	// No HTML escaping: "<" is digested as itself either way it is written.
	d1, _ := ManifestDigest([]byte(`{"schema":1,"x":"<a>"}`))
	d2, _ := ManifestDigest([]byte(`{"schema":1,"x":"<a>"}`))
	if d1 != d2 {
		t.Fatal("escaped and literal forms digest differently")
	}
}

func TestParseManifestErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want error
	}{
		"not json":       {`{"schema":`, ErrManifestInvalid},
		"not an object":  {`[1,2]`, ErrManifestInvalid},
		"no schema":      {`{"tools":[]}`, ErrManifestInvalid},
		"wrong type":     {`{"schema":1,"tools":"nuclei"}`, ErrManifestInvalid},
		"trailing data":  {`{"schema":1} {"schema":1}`, ErrManifestInvalid},
		"future schema":  {`{"schema":2}`, ErrManifestSchemaUnsupported},
		"too large":      {`{"schema":1,"x":"` + strings.Repeat("a", MaxManifestBytes) + `"}`, ErrManifestTooLarge},
		"schema as text": {`{"schema":"1"}`, ErrManifestInvalid},
	} {
		if _, _, _, err := ParseManifest([]byte(tc.raw)); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

// A newer sensor's unknown members are ignored and listed, never an error.
func TestParseManifestUnknownMembers(t *testing.T) {
	m, digest, ignored, err := ParseManifest([]byte(`{"schema":1,"labels":{"zone":"dc"},"future":true,"tools":[]}`))
	if err != nil || m.Schema != 1 || digest == "" {
		t.Fatalf("parse: %v %+v %q", err, m, digest)
	}
	want := []ManifestIgnored{{Path: "future", Reason: IgnoredUnknownMember}, {Path: "labels", Reason: IgnoredUnknownMember}}
	if !reflect.DeepEqual(ignored, want) {
		t.Fatalf("ignored = %+v", ignored)
	}
}

// The manifest's flat capability list follows the SDK registry's rule:
// installed tools' names and capabilities plus the sensor-wide ones.
func TestManifestCapabilityInput(t *testing.T) {
	m, _, _, err := ParseManifest([]byte(liveManifest))
	if err != nil {
		t.Fatal(err)
	}
	in := m.CapabilityInput()
	if want := []string{"nuclei", "dast", "validate:nuclei", "semgrep", "sast", "validate"}; !reflect.DeepEqual(in.Capabilities, want) {
		t.Fatalf("flat capabilities = %v", in.Capabilities)
	}
	if len(in.Tools) != 3 || in.Tools[0].Kind != "scanner" || in.Tools[2].Installed {
		t.Fatalf("tools = %+v", in.Tools)
	}
	if in.MaxConcurrentJobs != 0 || in.OS != "linux" || in.Arch != "amd64" {
		t.Fatalf("ceiling/platform = %d %s/%s", in.MaxConcurrentJobs, in.OS, in.Arch)
	}
	if c := in.Tools[0].Content; len(c) != 1 || c[0].Name != "nuclei-templates" || c[0].Version != "v10.4.9" {
		t.Fatalf("content = %+v", c)
	}
}

// Sanitizing keeps what the catalog knows and lists every drop with its
// path and reason.
func TestManifestSanitized(t *testing.T) {
	raw := `{"schema":1,
	  "sensor":{"name":"openctemio-sensor","version":"0.7.0"},
	  "concurrency":{"ceiling":500,"model":"magic"},
	  "resources":{"cpu_cores":-2,"mem_total_bytes":1024},
	  "capabilities":["validate","made-up"],
	  "tools":[
	    {"name":"nuclei","kind":"scanner","installed":true,"capabilities":["dast","xss-v2"],"target_types":["url","URL","bad type"]},
	    {"name":"zap","installed":true},
	    {"name":"../etc","installed":true}
	  ]}`
	m, _, _, err := ParseManifest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	in := m.CapabilityInput()
	rep := in.Sanitize(map[string]bool{"nuclei": true}, map[string]bool{"dast": true})
	clean, ignored := m.Sanitized(rep, time.Now())

	if len(clean.Tools) != 1 || clean.Tools[0].Name != "nuclei" ||
		!reflect.DeepEqual(clean.Tools[0].Capabilities, []string{"dast"}) ||
		!reflect.DeepEqual(clean.Tools[0].TargetTypes, []string{"url"}) {
		t.Fatalf("tools = %+v", clean.Tools)
	}
	if !reflect.DeepEqual(clean.Capabilities, []string{"validate"}) {
		t.Fatalf("sensor-wide = %v", clean.Capabilities)
	}
	if clean.Concurrency == nil || clean.Concurrency.Ceiling != MaxReportedJobs || clean.Concurrency.Model != "" {
		t.Fatalf("concurrency = %+v", clean.Concurrency)
	}
	if clean.Resources == nil || clean.Resources.CPUCores != 0 || clean.Resources.MemTotalBytes != 1024 {
		t.Fatalf("resources = %+v", clean.Resources)
	}
	if clean.Sensor == nil || clean.Sensor.Name != "openctemio-sensor" || clean.Sensor.Version != "0.7.0" {
		t.Fatalf("build = %+v", clean.Sensor)
	}
	want := []ManifestIgnored{
		{Path: "tools[0].capabilities[1]", Value: "xss-v2", Reason: IgnoredUnknownCapability},
		{Path: "tools[1]", Value: "zap", Reason: IgnoredUnknownTool},
		{Path: "tools[2]", Value: "../etc", Reason: IgnoredInvalidName},
		{Path: "capabilities[1]", Value: "made-up", Reason: IgnoredUnknownCapability},
	}
	if !reflect.DeepEqual(ignored, want) {
		t.Fatalf("ignored = %+v\nwant %+v", ignored, want)
	}
}

// A heartbeat's report becomes a manifest whose sensor-wide capabilities
// are the ones no installed tool provides; the same report gives the same
// digest, and a content version bump a new one.
func TestManifestFromReport(t *testing.T) {
	rep := CapabilityReport{
		Tools: []ReportedTool{
			{Name: "nuclei", Kind: "scanner", Version: "v3.11.1", Installed: true, Capabilities: []string{"dast", "validate:nuclei"},
				Content: []ReportedContent{{Name: "nuclei-templates", Version: "v10.4.9", Managed: true}}},
			{Name: "trivy", Installed: false},
		},
		Capabilities:      []string{"nuclei", "dast", "validate:nuclei", "validate"},
		MaxConcurrentJobs: 8,
		OS:                "linux", Arch: "amd64",
	}
	build := BuildInfo{SDKName: "openctem-sdk-go", SDKVersion: "v0.11.0", Product: "openctemio-sensor"}
	m := ManifestFromReport(rep, build, "v0.6.1")
	if !reflect.DeepEqual(m.Capabilities, []string{"validate"}) || m.Concurrency.Ceiling != 8 || len(m.Tools) != 2 {
		t.Fatalf("derived = %+v", m)
	}
	if m.Sensor.Version != "v0.6.1" || m.SDK.Version != "v0.11.0" || m.Platform.OS != "linux" {
		t.Fatalf("build/platform = %+v %+v %+v", m.Sensor, m.SDK, m.Platform)
	}
	d1, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d2, _ := ManifestFromReport(rep, build, "v0.6.1").Digest(); d1 != d2 {
		t.Fatal("same report, different digest")
	}
	rep.Tools[0].Content[0].Version = "v10.5.0"
	if d3, _ := ManifestFromReport(rep, build, "v0.6.1").Digest(); d3 == d1 {
		t.Fatal("a content version bump kept the digest")
	}
	// Content timestamps are not part of it.
	at := time.Now()
	rep.Tools[0].Content[0].Version = "v10.4.9"
	rep.Tools[0].Content[0].CheckedAt = &at
	if d4, _ := ManifestFromReport(rep, build, "v0.6.1").Digest(); d4 != d1 {
		t.Fatal("a content timestamp changed the digest")
	}
}

// The SDK computes the same digest for the same manifest (sdk-go
// pkg/core TestManifestDigestMatchesPlatform pins this value); its JSON
// encoder escapes "<", which the canonical form does not.
func TestManifestDigestMatchesSDK(t *testing.T) {
	raw := `{"schema":1,"capabilities":["validate"],"tools":[{"name":"nuclei","kind":"scanner","installed":true,"capabilities":["dast","<x>"]}]}`
	got, err := ManifestDigest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:053d2bb0ced8606d7b0278818bb6dc30e49116b36d6e6380d228de3e82fe4d51"; got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
}

func TestDiffManifests(t *testing.T) {
	prev := Manifest{Schema: 1, Capabilities: []string{"validate"},
		Concurrency: &ManifestConcurrency{Ceiling: 0, Model: "dynamic"},
		Tools: []ManifestTool{
			{Name: "nuclei", Version: "v3.11.1", Installed: true, Capabilities: []string{"dast"},
				Content: []ManifestContent{{Name: "nuclei-templates", Version: "v10.4.9"}}},
			{Name: "trivy", Version: "0.75.0", Installed: true, Capabilities: []string{"sca"}},
		}}
	next := Manifest{Schema: 1, Capabilities: []string{"validate"},
		Concurrency: &ManifestConcurrency{Ceiling: 4, Model: "dynamic"},
		Tools: []ManifestTool{
			{Name: "nuclei", Version: "v3.12.0", Installed: true, Capabilities: []string{"dast", "validate:nuclei"},
				Content: []ManifestContent{{Name: "nuclei-templates", Version: "v10.5.0"}}},
			{Name: "semgrep", Version: "1.179.0", Installed: true, Capabilities: []string{"sast"}},
		}}
	d := DiffManifests(prev, next)
	if !reflect.DeepEqual(d.ToolsAdded, []string{"semgrep"}) || !reflect.DeepEqual(d.ToolsRemoved, []string{"trivy"}) ||
		len(d.Versions) != 1 || d.Versions[0].To != "v3.12.0" ||
		len(d.Capabilities) != 1 || !reflect.DeepEqual(d.Capabilities[0].Added, []string{"validate:nuclei"}) ||
		d.SensorWide != nil || !reflect.DeepEqual(d.Other, []string{"concurrency"}) {
		t.Fatalf("diff = %+v", d)
	}
	if got := d.Summary(); got != "Manifest changed: added semgrep; removed trivy; nuclei v3.11.1 → v3.12.0; capabilities of 1 changed; concurrency changed" {
		t.Fatalf("summary %q", got)
	}
	// A content version alone is not a manifest_changed (content_updated
	// covers it).
	same := prev
	same.Tools = []ManifestTool{prev.Tools[0], prev.Tools[1]}
	same.Tools[0].Content = []ManifestContent{{Name: "nuclei-templates", Version: "v10.6.0"}}
	if d := DiffManifests(prev, same); !d.IsEmpty() {
		t.Fatalf("content-only diff = %+v", d)
	}
	// A long summary fits sensor_events.summary.
	many := Manifest{Schema: 1}
	for i := range 64 {
		many.Tools = append(many.Tools, ManifestTool{Name: strings.Repeat("t", 40) + string(rune('a'+i%26)) + string(rune('a'+i/26))})
	}
	if s := DiffManifests(Manifest{Schema: 1}, many).Summary(); len(s) > 500 {
		t.Fatalf("summary %d bytes", len(s))
	}
}

func TestSensorManifestPolicy(t *testing.T) {
	a := &Sensor{MaxConcurrentJobs: 5, Reported: CapabilityReport{
		Tools:        []ReportedTool{{Name: "nuclei", Installed: true}, {Name: "semgrep", Installed: true}},
		Capabilities: []string{"nuclei", "semgrep", "sast"}, MaxConcurrentJobs: 3,
	}}
	p := a.ManifestPolicy()
	if !reflect.DeepEqual(p.AllowedTools, []string{"nuclei", "semgrep"}) || p.MaxJobs != 3 || len(p.AllowedCapabilities) != 3 {
		t.Fatalf("policy %+v", p)
	}
}
