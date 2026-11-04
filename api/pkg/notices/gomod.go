package notices

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

// GoModule is the module part of one `go list -deps -json` package.
type GoModule struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version"`
	Dir     string    `json:"Dir"`
	Main    bool      `json:"Main"`
	Replace *GoModule `json:"Replace"`
}

type goListPackage struct {
	Standard bool      `json:"Standard"`
	Module   *GoModule `json:"Module"`
}

// ParseGoList reads the JSON stream of `go list -deps -json <pkg>` and
// returns the third-party modules the packages come from, once each. The main
// module and the standard library are left out (the standard library is added
// by GoStdlib). A replaced module is listed under its own path with the
// replacement's version and files, which is what is linked.
func ParseGoList(r io.Reader) ([]GoModule, error) {
	dec := json.NewDecoder(r)
	seen := map[string]bool{}
	var mods []GoModule
	for {
		var p goListPackage
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if p.Standard || p.Module == nil || p.Module.Main {
			continue
		}
		m := *p.Module
		if m.Replace != nil {
			if m.Replace.Version != "" {
				m.Version = m.Replace.Version
			}
			if m.Replace.Dir != "" {
				m.Dir = m.Replace.Dir
			}
			m.Replace = nil
		}
		if seen[m.Path] {
			continue
		}
		seen[m.Path] = true
		mods = append(mods, m)
	}
	return mods, nil
}

// GoPackages turns modules into notices: the license files at each module's
// root and the license they name. A module without a license file is still
// listed (license "Unknown", no text) so the list stays complete.
func GoPackages(mods []GoModule) ([]Package, error) {
	pkgs := make([]Package, 0, len(mods))
	for _, m := range mods {
		text := ""
		if m.Dir != "" {
			t, err := ReadLicenseText(m.Dir)
			if err != nil {
				return nil, fmt.Errorf("module %s: %w", m.Path, err)
			}
			text = t
		}
		pkgs = append(pkgs, Package{Name: m.Path, Version: m.Version, License: DetectLicense(text), Text: text})
	}
	return pkgs, nil
}

// GoStdlib is the notice of the Go standard library and runtime, which every
// Go binary links: GOROOT/LICENSE, at the toolchain's version.
func GoStdlib(goroot, goVersion string) (Package, error) {
	text, err := ReadLicenseText(filepath.Clean(goroot))
	if err != nil {
		return Package{}, fmt.Errorf("go standard library: %w", err)
	}
	return Package{Name: "go (standard library)", Version: goVersion, License: DetectLicense(text), Text: text}, nil
}
