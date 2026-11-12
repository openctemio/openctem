package notices

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, elem ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{"testdata"}, elem...)...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// goListStream is what `go list -deps -json ./cmd/server` prints, cut down:
// a standard package, a main-module package, two packages of one module, a
// module without a license file and a replaced module.
func goListStream(t *testing.T) string {
	t.Helper()
	mod := func(name string) string { return fixture(t, "modcache", "example.com", name) }
	pkgs := []map[string]any{
		{"ImportPath": "fmt", "Standard": true},
		{"ImportPath": "github.com/openctemio/openctem/server/cmd/server", "Module": map[string]any{"Path": "github.com/openctemio/openctem/server", "Main": true, "Dir": "/src/server"}},
		{"ImportPath": "example.com/mit", "Module": map[string]any{"Path": "example.com/mit", "Version": "v1.0.0", "Dir": mod("mit")}},
		{"ImportPath": "example.com/mit/sub", "Module": map[string]any{"Path": "example.com/mit", "Version": "v1.0.0", "Dir": mod("mit")}},
		{"ImportPath": "example.com/apache", "Module": map[string]any{"Path": "example.com/apache", "Version": "v2.1.0", "Dir": mod("apache")}},
		{"ImportPath": "example.com/none", "Module": map[string]any{"Path": "example.com/none", "Version": "v0.1.0", "Dir": mod("none")}},
		{"ImportPath": "example.com/orig", "Module": map[string]any{
			"Path": "example.com/orig", "Version": "v1.0.0", "Dir": "/does/not/exist",
			"Replace": map[string]any{"Path": "example.com/replaced", "Version": "v1.2.0", "Dir": mod("replaced")},
		}},
	}
	var b strings.Builder
	for _, p := range pkgs {
		data, err := json.MarshalIndent(p, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestGenerator_FromGoListAndModuleFiles(t *testing.T) {
	mods, err := ParseGoList(strings.NewReader(goListStream(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 4 {
		t.Fatalf("modules = %d, want 4 (main module, stdlib and duplicates left out): %+v", len(mods), mods)
	}
	pkgs, err := GoPackages(mods)
	if err != nil {
		t.Fatal(err)
	}
	std, err := GoStdlib(fixture(t, "goroot"), "go1.27.3")
	if err != nil {
		t.Fatal(err)
	}
	pkgs = append(pkgs, std)
	Sort(pkgs)

	got := map[string]Package{}
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		got[p.Name] = p
		names = append(names, p.Name)
	}
	if want := "example.com/apache example.com/mit example.com/none example.com/orig go (standard library)"; strings.Join(names, " ") != want {
		t.Fatalf("order = %q, want %q", strings.Join(names, " "), want)
	}
	cases := []struct{ name, version, license, textHas string }{
		{"example.com/mit", "v1.0.0", "MIT", "Copyright (c) 2020 Example"},
		{"example.com/apache", "v2.1.0", "Apache-2.0", "Example Apache component"},
		{"example.com/none", "v0.1.0", "Unknown", ""},
		{"example.com/orig", "v1.2.0", "BSD-3-Clause", "Neither the name"},
		{"go (standard library)", "go1.27.3", "BSD-3-Clause", "The Go Authors"},
	}
	for _, c := range cases {
		p := got[c.name]
		if p.Version != c.version || p.License != c.license {
			t.Errorf("%s = %s %s, want %s %s", c.name, p.Version, p.License, c.version, c.license)
		}
		if c.textHas == "" && p.Text != "" {
			t.Errorf("%s text = %q, want empty", c.name, p.Text)
		}
		if !strings.Contains(p.Text, c.textHas) {
			t.Errorf("%s text lacks %q", c.name, c.textHas)
		}
	}
	// The license comes before the NOTICE file; PATENTS is not a license file.
	if a := got["example.com/apache"].Text; strings.Index(a, "Apache License") > strings.Index(a, "Example Apache component") {
		t.Errorf("NOTICE before LICENSE: %q", a)
	}
	if strings.Contains(got["go (standard library)"].Text, "patents") {
		t.Error("PATENTS read as a license file")
	}
}

func TestParseGoList_RejectsGarbage(t *testing.T) {
	if _, err := ParseGoList(strings.NewReader("{not json")); err == nil {
		t.Fatal("want an error")
	}
}

func TestIsLicenseFile(t *testing.T) {
	for name, want := range map[string]bool{
		"LICENSE": true, "LICENSE.md": true, "license-mit": true, "LICEN" + "CE": true, "COPYING": true, // the British spelling
		"NOTICE.txt": true, "PATENTS": false, "README.md": false, "licenses.go": false, "license_test.go": true,
	} {
		if IsLicenseFile(name) != want {
			t.Errorf("IsLicenseFile(%q) = %v, want %v", name, !want, want)
		}
	}
}

func TestDetectLicense(t *testing.T) {
	for text, want := range map[string]string{
		"":                                   "Unknown",
		"Apache License\n Version 2.0":       "Apache-2.0",
		"Mozilla Public License Version 2.0": "MPL-2.0",
		"Permission is hereby granted, free of\ncharge, to any person":                                         "MIT",
		"Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee": "ISC",
		"Redistribution and use in source and binary forms, with or without modification":                      "BSD-2-Clause",
		"GNU LESSER GENERAL PUBLIC LICENSE Version 3":                                                          "LGPL-3.0",
		"something else entirely": "Unknown",
	} {
		if got := DetectLicense(text); got != want {
			t.Errorf("DetectLicense(%q) = %s, want %s", text, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	doc, err := Load(filepath.Join(dir, "missing.json"), "api")
	if err != nil || doc.Generated || doc.Packages == nil || len(doc.Packages) != 0 {
		t.Fatalf("missing file = %+v, %v; want empty, generated=false, no error", doc, err)
	}

	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"generated":true,"component":"api","packages":[{"name":"a","version":"v1","license":"MIT","text":"t"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err = Load(good, "api")
	if err != nil || !doc.Generated || len(doc.Packages) != 1 || doc.Packages[0].License != "MIT" {
		t.Fatalf("good file = %+v, %v", doc, err)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"packages":`), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err = Load(bad, "api")
	if err == nil || doc.Generated || len(doc.Packages) != 0 {
		t.Fatalf("bad file = %+v, %v; want empty and an error", doc, err)
	}
}
