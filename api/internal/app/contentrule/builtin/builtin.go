// Package builtin holds the curated detection rule packs of this build:
// web fingerprint rules and sensitive-information rules, written for this
// project (docs/architecture/rule-packs.md), and the template facts mapping
// (docs/architecture/template-facts.md). The API installs them as
// platform packs on first start when the pack name has no stable channel,
// through the same canonical form, lint and platform signature as an
// administrator's upload.
package builtin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/templatefact"
)

//go:embed web-fingerprints-core/*.yaml secret-rules-core/*.yaml template-facts-core/*.yaml
var files embed.FS

// Release is the version of the embedded packs. Change it whenever a rule
// file changes: a platform pack is immutable by name and version.
const Release = "2026.10.1"

// TemplateFactsRelease is the version of the embedded template facts pack.
// Change it whenever facts.yaml changes.
const TemplateFactsRelease = "2026.11.1"

// TemplateFactsName is the name of the embedded template facts pack.
const TemplateFactsName = "template-facts-core"

// Pack is one embedded pack.
type Pack struct {
	Name    string
	Kind    string
	Release string
	// Files are the pack's files, by path inside the pack.
	Files map[string][]byte
}

// Packs returns the embedded packs.
func Packs() ([]Pack, error) {
	defs := []struct{ name, kind, release string }{
		{"web-fingerprints-core", "web-fingerprints", Release},
		{"secret-rules-core", "secret-rules", Release},
		{TemplateFactsName, "template-facts", TemplateFactsRelease},
	}
	out := make([]Pack, 0, len(defs))
	for _, d := range defs {
		p := Pack{Name: d.name, Kind: d.kind, Release: d.release, Files: map[string][]byte{}}
		err := fs.WalkDir(files, d.name, func(p2 string, de fs.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return err
			}
			data, err := files.ReadFile(p2)
			if err != nil {
				return err
			}
			p.Files[path.Base(p2)] = data
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("builtin rule packs: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Archive is the pack as a gzip-compressed tar with fixed metadata, so the
// same files always give the same bytes.
func (p Pack) Archive() ([]byte, error) {
	names := make([]string, 0, len(p.Files))
	for n := range p.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		data := p.Files[n]
		hdr := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(data)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var (
	factsOnce sync.Once
	facts     *templatefact.Map
	factsErr  error
)

// TemplateFacts is the embedded template facts mapping, compiled once.
func TemplateFacts() (*templatefact.Map, error) {
	factsOnce.Do(func() {
		packs, err := Packs()
		if err != nil {
			factsErr = err
			return
		}
		for _, p := range packs {
			if p.Name != TemplateFactsName {
				continue
			}
			names := make([]string, 0, len(p.Files))
			for n := range p.Files {
				names = append(names, n)
			}
			sort.Strings(names)
			var entries []templatefact.Entry
			for _, n := range names {
				e, err := templatefact.ParseFile(p.Files[n])
				if err != nil {
					factsErr = fmt.Errorf("builtin template facts %s: %w", n, err)
					return
				}
				entries = append(entries, e...)
			}
			facts, factsErr = templatefact.Compile(p.Name+"@"+p.Release, entries)
			return
		}
		factsErr = fmt.Errorf("builtin template facts: pack missing")
	})
	return facts, factsErr
}
