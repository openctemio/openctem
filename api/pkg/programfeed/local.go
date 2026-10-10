package programfeed

// Local bundles (RFC-065 §16.6, owner option A): an operator who runs
// `programfeed build --local-only` on the platform host gets an unsigned
// bundle (latest.json, snapshot.manifest.json, delta.manifest.json and the
// same record files) that may hold records of platforms that do not allow
// redistribution. It is read only from a directory the server configuration
// names (PROGRAMFEED_LOCAL_BUNDLE_DIR), only after a platform administrator
// enabled the source, with every rule of the signed path except the
// signatures: strict decoding, newer sequence only, the delta only on top of
// the applied sequence, 7-day validity, size and SHA-256 per file, every
// record re-validated. A local-only manifest is accepted here and never on
// the signed path; the catalog marks these programs local-only and every
// target stays a suggestion until a follower confirms it.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// Unsigned file names of a local bundle.
const (
	LocalLatestFile = "latest.json"
)

// localName is the unsigned counterpart of a pointer's manifest name.
func localName(kind string) string { return kind + ".manifest.json" }

// VerifyLocalDir verifies an unsigned local bundle in dir.
//
//nolint:cyclop // one refusal per contract rule
func VerifyLocalDir(dir string, opt Options) (*Verified, error) {
	v := &Verified{Dir: dir}
	raw, err := readCapped(filepath.Join(dir, LocalLatestFile), MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	if err := feedsign.DecodeStrict(raw, &v.Latest); err != nil {
		return nil, fmt.Errorf("pointer: %w", err)
	}
	l := v.Latest
	switch {
	case l.Schema != LatestSchema:
		return nil, fmt.Errorf("pointer: schema %q", l.Schema)
	case l.Sequence <= opt.AppliedSequence:
		return nil, ErrNotNewer
	case !opt.Now.Before(l.ExpiresAt) || l.ExpiresAt.Sub(l.CreatedAt) > MaxBundleValidity:
		return nil, errors.New("pointer: expired or valid for more than 7 days")
	case l.Snapshot != ManifestName(KindSnapshot) || (l.Delta != "" && l.Delta != ManifestName(KindDelta)):
		return nil, errors.New("pointer: manifest names")
	}
	kind := KindSnapshot
	if l.Delta != "" && opt.AppliedSequence > 0 && l.BaseSequence == opt.AppliedSequence {
		kind = KindDelta
	}
	if raw, err = readCapped(filepath.Join(dir, localName(kind)), MaxManifestBytes); err != nil {
		return nil, err
	}
	var m Manifest
	if err := feedsign.DecodeStrict(raw, &m); err != nil {
		return nil, fmt.Errorf("%s manifest: %w", kind, err)
	}
	switch {
	case m.Schema != ManifestSchema:
		return nil, fmt.Errorf("%s manifest: schema %q", kind, m.Schema)
	case m.Kind != kind:
		return nil, fmt.Errorf("%s manifest: kind %q", kind, m.Kind)
	case m.Sequence != l.Sequence:
		return nil, fmt.Errorf("%s manifest: sequence differs from the pointer", kind)
	case kind == KindDelta && m.BaseSequence != opt.AppliedSequence:
		return nil, errors.New("delta manifest: base is not the applied sequence")
	case !opt.Now.Before(m.ExpiresAt) || m.ExpiresAt.Sub(m.CreatedAt) > MaxBundleValidity:
		return nil, fmt.Errorf("%s manifest: expired or valid for more than 7 days", kind)
	case len(m.Files) != 2 || m.Files[0].Name != FileName(kind, "programs") || m.Files[1].Name != FileName(kind, "changes"):
		return nil, fmt.Errorf("%s manifest: files must be %s, %s", kind, FileName(kind, "programs"), FileName(kind, "changes"))
	}
	for _, f := range m.Files {
		if strings.ContainsAny(f.Name, `/\`) {
			return nil, fmt.Errorf("file %q: name", f.Name)
		}
		if err := checkFile(dir, f); err != nil {
			return nil, err
		}
	}
	v.Use = m
	return v, nil
}
