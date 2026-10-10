// Package programfeedtest builds signed program-feed bundles for tests: a
// fresh offline root and online key per Builder, so no key is ever
// committed and no test reaches the network.
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
	Now           time.Time
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

// Write writes a snapshot bundle of records (JSON objects, one per
// program) with the given sequence to a new directory and returns it.
func (b *Builder) Write(t *testing.T, sequence uint64, records []map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	rootPub := b.RootPriv.Public().(ed25519.PublicKey)
	onlinePub := b.OnlinePriv.Public().(ed25519.PublicKey)
	ks := feedsign.KeySet{Kind: programfeed.KeySetKind, Version: b.KeySetVersion, IssuedAt: b.Now.Add(-time.Hour),
		NotAfter: b.Now.Add(90 * 24 * time.Hour), Keys: []jobsign.PublicKey{jobsign.NewPublicKey(onlinePub)},
		RootKeyID: jobsign.KeyID(rootPub), RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	b.sign(t, dir, programfeed.KeySetFile, b.RootPriv, programfeed.KeySetPayloadType, ks)

	var raw bytes.Buffer
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(line)
		raw.WriteByte('\n')
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(raw.Bytes())
	_ = w.Close()
	if err := os.WriteFile(filepath.Join(dir, programfeed.ProgramsFile), gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(gz.Bytes())
	m := programfeed.Manifest{Schema: programfeed.ManifestSchema, Sequence: sequence, Kind: programfeed.KindSnapshot,
		CreatedAt: b.Now, ExpiresAt: b.Now.Add(48 * time.Hour),
		Sources: []programfeed.Source{{Name: "fixture", AsOf: b.Now, Terms: "test data", Attribution: "test"}},
		Files: []programfeed.File{{Name: programfeed.ProgramsFile, SHA256: hex.EncodeToString(sum[:]),
			Size: int64(gz.Len()), Records: len(records)}}}
	b.sign(t, dir, "snapshot.manifest.dsse.json", b.OnlinePriv, programfeed.ManifestPayloadType, m)
	l := programfeed.Latest{Schema: programfeed.LatestSchema, Sequence: sequence, Snapshot: "snapshot.manifest.dsse.json",
		CreatedAt: b.Now, ExpiresAt: b.Now.Add(48 * time.Hour)}
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

// Record is a valid v1 record for platform:handle with the given scope.
func Record(platform, handle string, inScope, outOfScope []string, asOf time.Time) map[string]any {
	targets := func(ids []string) []map[string]string {
		out := make([]map[string]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, map[string]string{"identifier": id})
		}
		return out
	}
	return map[string]any{
		"id": platform + ":" + handle, "platform": platform, "handle": handle, "name": "Program " + handle,
		"url": "https://" + platform + ".example/" + handle, "offers_bounty": true, "open": true,
		"in_scope": targets(inScope), "out_of_scope": targets(outOfScope),
		"rules": map[string]any{}, "terms_text": "", "source": "fixture", "as_of": asOf.Format(time.RFC3339),
	}
}
