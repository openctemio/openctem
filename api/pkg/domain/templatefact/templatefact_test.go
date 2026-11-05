package templatefact

import (
	"strings"
	"testing"
)

const testPack = `schema: 1
entries:
  - id: tech
    match: {templates: [tech-detect]}
    class: technology
    technology: {name_from: matcher, confidence: 60}
    names:
      nginx: {name: nginx, category: web_server}
      generic: {skip: true}
  - id: ver
    match: {templates: [nginx-version]}
    class: technology
    technology: {name: nginx, version_from: extracted, confidence: 70}
  - id: wp
    match: {template_prefix: wordpress-, metadata: plugin_namespace}
    class: technology
    technology: {name_from: "metadata:plugin_namespace", version_from: extracted}
  - id: hdr
    match: {templates: [http-missing-security-headers]}
    class: posture
    posture:
      Strict-Transport-Security: {hsts: false, hsts_max_age: 0}
      x-frame-options: {frame_options: none}
  - id: robots
    match: {templates: [robots-txt-endpoint]}
    class: surface
    surface: {path_from: extracted, source: robots}
  - id: files
    match: {templates: [security-txt]}
    class: surface
    surface: {path_from: matched, source: probe}
  - id: panels
    match: {tags: [panel]}
    class: exposure
    exposure: {event_type: web_interface_exposed}
  - id: pii
    match: {templates: [email-extractor]}
    class: discard
`

func testMap(t *testing.T) *Map {
	t.Helper()
	entries, err := ParseFile([]byte(testPack))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Compile("test@1", entries)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestClassifyTechnology(t *testing.T) {
	m := testMap(t)
	f, ok := m.Classify(Input{TemplateID: "tech-detect", Matcher: "NGINX"})
	if !ok || f.Class != ClassTechnology || len(f.Technologies) != 1 || f.Technologies[0].Name != "nginx" ||
		f.Technologies[0].Category != "web_server" || f.Technologies[0].Confidence != 60 {
		t.Fatalf("got %+v %v", f, ok)
	}
	// An unlisted matcher becomes its own name (name_from matcher).
	f, _ = m.Classify(Input{TemplateID: "tech-detect", Matcher: "caddy"})
	if len(f.Technologies) != 1 || f.Technologies[0].Name != "caddy" {
		t.Fatalf("unlisted %+v", f)
	}
	// A skip matcher is consumed, no technology.
	f, ok = m.Classify(Input{TemplateID: "tech-detect", Matcher: "generic"})
	if !ok || f.Class != ClassTechnology || len(f.Technologies) != 0 {
		t.Fatalf("skip %+v", f)
	}
}

func TestClassifyRefusesHostileValues(t *testing.T) {
	m := testMap(t)
	for _, matcher := range []string{"<script>alert(1)</script>", "a\nb", strings.Repeat("x", 65), "", "-lead"} {
		f, ok := m.Classify(Input{TemplateID: "tech-detect", Matcher: matcher})
		if !ok || len(f.Technologies) != 0 {
			t.Fatalf("matcher %q gave %+v", matcher, f)
		}
	}
	f, _ := m.Classify(Input{TemplateID: "wordpress-x", Metadata: map[string]string{"plugin_namespace": "a\"><img src=x>"}})
	if len(f.Technologies) != 0 {
		t.Fatalf("metadata name %+v", f)
	}
	// Versions: bounded, dotted, from the first value that has one.
	f, _ = m.Classify(Input{TemplateID: "nginx-version", Extracted: []string{"<b>", "nginx/1.25.3 (Ubuntu)"}})
	if f.Technologies[0].Version != "1.25.3" {
		t.Fatalf("version %+v", f)
	}
	f, _ = m.Classify(Input{TemplateID: "nginx-version", Extracted: []string{strings.Repeat("1.", 200)}})
	if f.Technologies[0].Version != "" {
		t.Fatalf("over-long extracted value read: %+v", f)
	}
}

func TestClassifyMetadataPrefix(t *testing.T) {
	m := testMap(t)
	f, ok := m.Classify(Input{TemplateID: "wordpress-akismet", Metadata: map[string]string{"plugin_namespace": "akismet"}, Extracted: []string{"5.3.1"}})
	if !ok || f.Technologies[0].Name != "akismet" || f.Technologies[0].Version != "5.3.1" || f.Technologies[0].Confidence != DefaultConfidence {
		t.Fatalf("got %+v", f)
	}
	// Without the metadata key the prefix entry does not apply.
	if _, ok := m.Classify(Input{TemplateID: "wordpress-login"}); ok {
		t.Fatal("prefix matched without its metadata")
	}
}

func TestClassifyPostureSurfaceExposureDiscard(t *testing.T) {
	m := testMap(t)
	f, _ := m.Classify(Input{TemplateID: "http-missing-security-headers", Matcher: "strict-transport-security"})
	if f.Class != ClassPosture || f.Posture["hsts"] != false || f.Posture["hsts_max_age"] != 0 {
		t.Fatalf("posture %+v", f)
	}
	f, _ = m.Classify(Input{TemplateID: "http-missing-security-headers", Matcher: "x-frame-options"})
	if f.Posture["frame_options"] != "none" {
		t.Fatalf("frame options %+v", f)
	}
	f, _ = m.Classify(Input{TemplateID: "http-missing-security-headers", Matcher: "unknown-header"})
	if f.Class != ClassPosture || len(f.Posture) != 0 {
		t.Fatalf("unknown header %+v", f)
	}

	f, _ = m.Classify(Input{TemplateID: "robots-txt-endpoint", URL: "https://a.example/robots.txt",
		Extracted: []string{"/admin", "/wp-*", "https://a.example/private", "https://evil.example/x", "/a?b=c", "/admin", "rel"}})
	if f.Class != ClassSurface || f.Source != "robots" || strings.Join(f.Paths, ",") != "/admin,/private" {
		t.Fatalf("robots %+v", f)
	}
	f, _ = m.Classify(Input{TemplateID: "security-txt", URL: "https://a.example/.well-known/security.txt"})
	if strings.Join(f.Paths, ",") != "/.well-known/security.txt" || f.Source != "probe" {
		t.Fatalf("matched %+v", f)
	}
	f, _ = m.Classify(Input{TemplateID: "security-txt", URL: "ftp://a.example/x"})
	if len(f.Paths) != 0 {
		t.Fatalf("non-http url %+v", f)
	}

	f, _ = m.Classify(Input{TemplateID: "grafana-login", Tags: []string{"Panel", "grafana"}})
	if f.Class != ClassExposure || f.EventType != "web_interface_exposed" || f.Class.IsFact() {
		t.Fatalf("panel %+v", f)
	}
	f, _ = m.Classify(Input{TemplateID: "email-extractor"})
	if f.Class != ClassDiscard || !f.Class.IsFact() {
		t.Fatalf("discard %+v", f)
	}
	if _, ok := m.Classify(Input{TemplateID: "brand-new-template"}); ok {
		t.Fatal("an unmapped template was classified")
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]string{
		"schema":          "schema: 2\nentries: [{id: aa, match: {tags: [x]}, class: discard}]",
		"unknown key":     "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: discard, extra: 1}]",
		"class":           "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: finding}]",
		"no match":        "schema: 1\nentries: [{id: aa, match: {}, class: discard}]",
		"strong":          "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: technology, technology: {name: x, confidence: 80}}]",
		"category":        "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: technology, technology: {name: x, category: cms}}]",
		"posture key":     "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: posture, posture: {x: {server: nginx}}}]",
		"posture value":   "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: posture, posture: {x: {frame_options: bogus}}}]",
		"surface source":  "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: surface, surface: {path_from: matched, source: crawl}}]",
		"exposure type":   "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: exposure, exposure: {event_type: credential_leaked}}]",
		"version pattern": "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: technology, technology: {name: x, version_from: extracted, version_pattern: '(\\d+)'}}]",
		"wrong section":   "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: discard, surface: {path_from: matched, source: probe}}]",
		"name markup":     "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: technology, technology: {name: '<b>'}}]",
	}
	for name, doc := range cases {
		if _, err := ParseFile([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dup := "schema: 1\nentries: [{id: aa, match: {tags: [x]}, class: discard}, {id: aa, match: {tags: [y]}, class: discard}]"
	entries, err := ParseFile([]byte(dup))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile("x", entries); err == nil {
		t.Error("duplicate ids compiled")
	}
}

func TestPrecedenceExactBeforePrefixBeforeTags(t *testing.T) {
	doc := `schema: 1
entries:
  - {id: by-tag, match: {tags: [tech]}, class: discard}
  - {id: short, match: {template_prefix: wor}, class: discard}
  - {id: long, match: {template_prefix: wordpress-}, class: discard}
  - {id: exact, match: {templates: [wordpress-x]}, class: discard}
`
	entries, err := ParseFile([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Compile("x", entries)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"wordpress-x": "exact", "wordpress-y": "long", "word": "short", "other": "by-tag"} {
		f, _ := m.Classify(Input{TemplateID: id, Tags: []string{"tech"}})
		if f.Entry != want {
			t.Errorf("%s: entry %s, want %s", id, f.Entry, want)
		}
	}
}

func TestNilMapClassifiesNothing(t *testing.T) {
	var m *Map
	if _, ok := m.Classify(Input{TemplateID: "tech-detect"}); ok || m.Len() != 0 {
		t.Fatal("nil map classified")
	}
}
