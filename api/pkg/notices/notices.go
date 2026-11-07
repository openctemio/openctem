// Package notices holds the third-party notices of a build: every open-source
// component linked into a binary or shipped in a bundle, with its version, its
// license identifier and its license text.
//
// The notices are generated at build time (cmd/third-party-notices for the
// API, web/scripts/third-party-notices.mjs for the web app and the console),
// written to a JSON file inside the image and served read-only by About >
// Open-source licenses. Nothing is fetched at run time. The page belongs to
// the core and is always present: no brand pack, white-label setting or
// extension removes or replaces it (docs/architecture/third-party-notices.md).
package notices

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
)

// DefaultPath is where the API image keeps its notices, relative to the
// server's working directory (/app in the image, like api/openapi/swagger.yaml).
// The path is fixed: nothing in a request chooses which file is read.
const DefaultPath = "third-party-notices.json"

// MaxFileBytes bounds the notices file read at start-up. A real file is a few
// MiB; anything larger is not a notices file.
const MaxFileBytes = 32 << 20

// Package is one third-party component.
type Package struct {
	// Name is the Go module path or the npm package name.
	Name    string `json:"name"`
	Version string `json:"version"`
	// License is an SPDX identifier (or expression), "Unknown" when neither the
	// package metadata nor its license text says which license it is.
	License string `json:"license"`
	// Text is the license text shipped with the package (its LICENSE and
	// NOTICE files), empty when the package ships none.
	Text string `json:"text"`
}

// Document is the notices file and the endpoint's response.
type Document struct {
	// Generated is false when the build carries no notices file (a
	// development build): the list is then empty, not an error.
	Generated bool `json:"generated"`
	// Component names what the list covers: "api", "web".
	Component string    `json:"component"`
	Packages  []Package `json:"packages"`
}

// Empty is the document of a build without a notices file.
func Empty(component string) Document {
	return Document{Generated: false, Component: component, Packages: []Package{}}
}

// Load reads the notices file at path. A missing file gives Empty and no
// error (a development build); an unreadable, oversized or malformed file
// gives Empty and the error, for the caller to log.
func Load(path, component string) (Document, error) {
	f, err := os.Open(path) // #nosec G304 -- fixed path chosen by the binary, never by a request
	if errors.Is(err, fs.ErrNotExist) {
		return Empty(component), nil
	}
	if err != nil {
		return Empty(component), fmt.Errorf("open notices: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return Empty(component), fmt.Errorf("read notices: %w", err)
	}
	if len(data) > MaxFileBytes {
		return Empty(component), fmt.Errorf("notices file is larger than %d bytes", MaxFileBytes)
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Empty(component), fmt.Errorf("parse notices: %w", err)
	}
	if doc.Packages == nil {
		doc.Packages = []Package{}
	}
	doc.Generated = true
	if doc.Component == "" {
		doc.Component = component
	}
	return doc, nil
}

// Sort orders packages by name, then version, so the generated file is the
// same for the same dependencies.
func Sort(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
}

// licenseFile matches the files that carry a package's license or notices at
// the package root: LICENSE (either spelling), COPYING, NOTICE, with any extension or
// suffix (LICENSE.md, LICENSE-MIT, COPYING.txt).
var licenseFile = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice)([.\-_].*)?$`)

// IsLicenseFile reports whether a file name is a license or notices file.
func IsLicenseFile(name string) bool { return licenseFile.MatchString(name) }

// isNoticeFile is a NOTICE file: it follows the license text.
func isNoticeFile(name string) bool { return strings.HasPrefix(strings.ToLower(name), "notice") }

// ReadLicenseText returns the license text found at the root of dir: the
// license files first, then the NOTICE files, each in name order, separated by
// a blank line. Empty when the directory has none.
func ReadLicenseText(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var licenses, noticesFiles []string
	for _, e := range entries {
		if e.IsDir() || !IsLicenseFile(e.Name()) {
			continue
		}
		if isNoticeFile(e.Name()) {
			noticesFiles = append(noticesFiles, e.Name())
		} else {
			licenses = append(licenses, e.Name())
		}
	}
	sort.Strings(licenses)
	sort.Strings(noticesFiles)
	parts := make([]string, 0, len(licenses)+len(noticesFiles))
	for _, name := range append(licenses, noticesFiles...) {
		b, err := os.ReadFile(dir + string(os.PathSeparator) + name) // #nosec G304 -- build-time tool reading the module cache
		if err != nil {
			return "", err
		}
		if t := strings.TrimSpace(string(b)); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n\n"), nil
}

// spaces collapses runs of whitespace for matching.
var spaces = regexp.MustCompile(`\s+`)

// DetectLicense names the license of a license text by its distinctive
// sentences. It is a best effort for packages whose metadata carries no
// identifier (Go modules never do): "Unknown" when nothing matches.
func DetectLicense(text string) string {
	t := strings.ToLower(spaces.ReplaceAllString(text, " "))
	has := func(s string) bool { return strings.Contains(t, s) }
	switch {
	case t == "":
		return "Unknown"
	case has("apache license") && has("version 2.0"):
		return "Apache-2.0"
	case has("mozilla public license") && (has("version 2.0") || has("v. 2.0")):
		return "MPL-2.0"
	case has("gnu affero general public license"):
		return "AGPL-3.0"
	case has("gnu lesser general public license") && has("version 3"):
		return "LGPL-3.0"
	case has("gnu lesser general public license"), has("gnu library general public license"):
		return "LGPL-2.1"
	case has("gnu general public license") && has("version 3"):
		return "GPL-3.0"
	case has("gnu general public license") && has("version 2"):
		return "GPL-2.0"
	case has("eclipse public license") && has("2.0"):
		return "EPL-2.0"
	case has("eclipse public license"):
		return "EPL-1.0"
	case has("permission is hereby granted, free of charge"):
		return "MIT"
	case has("permission to use, copy, modify, and/or distribute this software for any purpose"),
		has("permission to use, copy, modify, and distribute this software for any purpose with or without fee"):
		return "ISC"
	case has("redistribution and use in source and binary forms"):
		if has("neither the name") || has("endorse or promote") {
			return "BSD-3-Clause"
		}
		return "BSD-2-Clause"
	case has("this is free and unencumbered software released into the public domain"):
		return "Unlicense"
	case has("cc0 1.0 universal"):
		return "CC0-1.0"
	case has("this software is provided 'as-is', without any express or implied warranty"):
		return "Zlib"
	default:
		return "Unknown"
	}
}
