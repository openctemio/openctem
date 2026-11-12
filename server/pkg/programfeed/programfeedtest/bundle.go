// Package programfeedtest builds signed program-feed bundles for tests: a
// fresh offline root and online key per Builder, so no key is ever
// committed and no test reaches the network. Bundles the collector itself
// wrote are in pkg/programfeed/testdata/collector.
package programfeedtest

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/programfeed"
)

// Builder writes bundles signed by its keys.
type Builder struct {
	RootPriv   ed25519.PrivateKey
	OnlinePriv ed25519.PrivateKey
	// KeySetVersion is the version of the key set it signs (default 1).
	KeySetVersion uint64
	// LocalOnly marks the manifest local-only (an unsigned self-hoster
	// build the signed-feed path must refuse).
	LocalOnly bool
	Now       time.Time
}

// New returns a builder with fresh keys.
func New(t *testing.T, now time.Time) *Builder {
	t.Helper()
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, online, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Builder{RootPriv: root, OnlinePriv: online, KeySetVersion: 1, Now: now}
}

// RootKeyID is the id the platform pins.
func (b *Builder) RootKeyID() string {
	return jobsign.KeyID(b.RootPriv.Public().(ed25519.PublicKey))
}

func gz(t *testing.T, lines []map[string]any) []byte {
	t.Helper()
	var raw bytes.Buffer
	for _, r := range lines {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(line)
		raw.WriteByte('\n')
	}
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	_, _ = w.Write(raw.Bytes())
	_ = w.Close()
	return out.Bytes()
}

// Write writes a snapshot bundle of program records (with an empty change
// log) at sequence to a new directory and returns it.
func (b *Builder) Write(t *testing.T, sequence uint64, programs []map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	rootPub := b.RootPriv.Public().(ed25519.PublicKey)
	onlinePub := b.OnlinePriv.Public().(ed25519.PublicKey)
	ks := feedsign.KeySet{Kind: programfeed.KeySetKind, Version: b.KeySetVersion, IssuedAt: b.Now.Add(-time.Hour),
		NotAfter: b.Now.Add(90 * 24 * time.Hour), Keys: []jobsign.PublicKey{jobsign.NewPublicKey(onlinePub)},
		RootKeyID: jobsign.KeyID(rootPub), RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	b.sign(t, dir, programfeed.KeySetFile, b.RootPriv, programfeed.KeySetPayloadType, ks)

	files := make([]programfeed.File, 0, 2)
	for _, f := range []struct {
		records string
		lines   []map[string]any
	}{{"programs", programs}, {"changes", nil}} {
		name := programfeed.FileName(programfeed.KindSnapshot, f.records)
		data := gz(t, f.lines)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		files = append(files, programfeed.File{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), Records: len(f.lines)})
	}
	m := programfeed.Manifest{Schema: programfeed.ManifestSchema, Sequence: sequence, Kind: programfeed.KindSnapshot,
		CreatedAt: b.Now, ExpiresAt: b.Now.Add(48 * time.Hour),
		Sources: []programfeed.Source{{Name: "fixture", AsOf: b.Now, Licence: "test"}}, Files: files, //nolint:misspell // the collector wire name
		Collector: programfeed.Collector{LocalOnly: b.LocalOnly}}
	b.sign(t, dir, programfeed.ManifestName(programfeed.KindSnapshot), b.OnlinePriv, programfeed.ManifestPayloadType, m)
	l := programfeed.Latest{Schema: programfeed.LatestSchema, Sequence: sequence, Tag: fmt.Sprintf("v1-%d", sequence),
		Snapshot: programfeed.ManifestName(programfeed.KindSnapshot), CreatedAt: b.Now, ExpiresAt: b.Now.Add(48 * time.Hour)}
	b.sign(t, dir, programfeed.LatestFile, b.OnlinePriv, programfeed.LatestPayloadType, l)
	return dir
}

func (b *Builder) sign(t *testing.T, dir, name string, priv ed25519.PrivateKey, payloadType string, v any) {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	env, err := feedsign.Sign(priv, payloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), env, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Record is a valid v1 program record "<source>:<slug>" with published
// in-scope targets and out-of-scope targets.
func Record(source, slug string, inScope, outOfScope []string, asOf time.Time) map[string]any {
	targets := func(ids []string) []map[string]string {
		out := make([]map[string]string, 0, len(ids))
		for _, id := range ids {
			typ := "domain"
			if len(id) > 2 && id[:2] == "*." {
				typ = "wildcard"
			}
			out = append(out, map[string]string{"type": typ, "value": id, "confidence": "published"})
		}
		return out
	}
	ts := asOf.UTC().Format(time.RFC3339)
	return map[string]any{
		"id": source + ":" + slug, "source": source, "platform": "self-hosted", "name": "Program " + slug,
		"url": "https://" + slug + ".example/security", "type": "bounty", "status": "open", "offers_bounty": true,
		"scope_published": true, "in_scope": targets(inScope), "out_of_scope": targets(outOfScope), "rejected": []any{},
		"rules":      map[string]any{"testing_restrictions": []string{}, "required_headers": []string{}, "safe_harbour": "unknown", "languages": []string{}}, //nolint:misspell // the collector wire name
		"terms":      map[string]any{"url": "https://" + slug + ".example/security"},
		"contact":    map[string]any{},
		"provenance": map[string]any{"source": source, "source_url": "https://" + slug + ".example/list.json", "fetched_at": ts},
		"first_seen": ts, "last_seen": ts, "last_changed": ts,
	}
}
