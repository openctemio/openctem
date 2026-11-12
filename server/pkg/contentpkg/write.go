package contentpkg

import (
	"archive/tar"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// The functions in this file sign and write bundles. They run where the
// catalog keys are (the release pipeline's generator, tests); an instance
// only verifies.

// SignKeySet signs a key set listing online with the offline root.
func SignKeySet(root ed25519.PrivateKey, version uint64, issued, notAfter time.Time, online ...ed25519.PublicKey) ([]byte, error) {
	if len(online) == 0 {
		return nil, errors.New("a key set lists at least one online key")
	}
	pub, _ := root.Public().(ed25519.PublicKey)
	ks := feedsign.KeySet{
		Kind: KeySetKind, Version: version, IssuedAt: issued.UTC(), NotAfter: notAfter.UTC(),
		RootKeyID: jobsign.KeyID(pub), RootPublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	for _, k := range online {
		ks.Keys = append(ks.Keys, jobsign.NewPublicKey(k))
	}
	return Sign(root, KeySetPayloadType, ks)
}

// RootKeyID is the id an instance pins for root.
func RootKeyID(root ed25519.PublicKey) string { return jobsign.KeyID(root) }

// PackageInput is one package version to put in a bundle.
type PackageInput struct {
	ManifestRaw []byte
	// Artifact is nil for OCI and feed artifacts.
	Artifact []byte
	// Publisher is publisher.sigstore.json; nil for OCI and feed artifacts.
	Publisher  []byte
	Origin     string
	ReviewedAt time.Time
}

// BundleInput is everything a bundle holds.
type BundleInput struct {
	KeySet      []byte
	Online      ed25519.PrivateKey
	Sequence    uint64
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Revocations Revocations
	Packages    []PackageInput
}

// WriteBundle signs the statements, the index and the revocation list with
// the online key and writes the bundle as a tar to w. Every manifest is
// validated first, and every artifact must match its digest.
func WriteBundle(w io.Writer, in BundleInput) error {
	files := map[string][]byte{FileKeySet: in.KeySet}
	ix := Index{Kind: IndexKind, Sequence: in.Sequence, IssuedAt: in.IssuedAt.UTC(), ExpiresAt: in.ExpiresAt.UTC(),
		Packages: []IndexEntry{}}
	for _, p := range in.Packages {
		m, err := ParseManifest(p.ManifestRaw)
		if err != nil {
			return err
		}
		if p.Artifact != nil && (Digest(p.Artifact) != m.Artifact.Digest || int64(len(p.Artifact)) != m.Artifact.Size) {
			return fmt.Errorf("%s@%s: the artifact does not match the manifest", m.ID, m.Version)
		}
		st, err := Sign(in.Online, StatementPayloadType, NewStatement(m, p.ManifestRaw, p.Origin, p.ReviewedAt))
		if err != nil {
			return err
		}
		dir := PackageDir(m.ID, m.Version)
		files[dir+"/"+FileManifest] = p.ManifestRaw
		files[dir+"/"+FileStatement] = st
		if p.Artifact != nil {
			files[dir+"/"+FileArtifact] = p.Artifact
		}
		if p.Publisher != nil {
			files[dir+"/"+FilePublisher] = p.Publisher
		}
		ix.Packages = append(ix.Packages, IndexEntry{ID: m.ID, Version: m.Version,
			ManifestDigest: Digest(p.ManifestRaw), ArtifactDigest: m.Artifact.Digest})
	}
	var err error
	if files[FileIndex], err = Sign(in.Online, IndexPayloadType, ix); err != nil {
		return err
	}
	rv := in.Revocations
	rv.Kind = RevocationsKind
	if rv.Entries == nil {
		rv.Entries = []RevocationEntry{}
	}
	if files[FileRevocations], err = Sign(in.Online, RevocationsPayloadType, rv); err != nil {
		return err
	}
	return WriteFiles(w, files)
}

// WriteFiles writes files as a deterministic tar (sorted names, fixed
// modes and times).
func WriteFiles(w io.Writer, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	tw := tar.NewWriter(w)
	for _, n := range names {
		h := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), ModTime: time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return err
		}
	}
	return tw.Close()
}
