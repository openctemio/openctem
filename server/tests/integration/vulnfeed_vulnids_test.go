package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// writeVulnIDs writes the release's vulnerability id manifest and entries.
func (f *v2Feed) writeVulnIDs(signer ed25519.PrivateKey, sequence, version uint64, entries []map[string]any, tamper bool) {
	f.t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	for _, e := range entries {
		b, err := json.Marshal(e)
		require.NoError(f.t, err)
		_, err = zw.Write(append(b, '\n'))
		require.NoError(f.t, err)
	}
	require.NoError(f.t, zw.Close())
	gz := buf.Bytes()
	sum := sha256.Sum256(gz)
	m := map[string]any{"schema": vulnbundle.VulnIDsSchema, "sequence": sequence, "version": version,
		"created_at": f.now, "expires_at": f.now.Add(6 * 24 * time.Hour),
		"files": []map[string]any{{"name": vulnbundle.VulnIDsEntriesFile, "sha256": hex.EncodeToString(sum[:]), "size": len(gz), "records": len(entries)}},
		"stats": map[string]any{"advisories": 3, "future_field": 1}}
	payload, err := json.Marshal(m)
	require.NoError(f.t, err)
	env, err := feedsign.Sign(signer, vulnbundle.VulnIDsManifestPayloadType, payload)
	require.NoError(f.t, err)
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, vulnbundle.VulnIDsManifestFile), env, 0o600))
	if tamper {
		gz = append([]byte{}, gz...)
		gz[len(gz)-1] ^= 0xff
	}
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, vulnbundle.VulnIDsEntriesFile), gz, 0o600))
}

// The release's vulnerability id alias map is applied after the bundle:
// verified against the key set and the release sequence, an id listed with
// two CVEs dropped, once per version; a map of another release, a tampered
// file or a foreign signature is refused and recorded without undoing the
// corpus import.
func TestVulnFeedVulnIDs(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	reset := `DELETE FROM feed_checkpoints WHERE feed = 'vulnfeed';
		UPDATE threat_intel_sync_status SET is_enabled = %t, metadata = '{}'::jsonb WHERE source_name = 'vulnfeed'`
	_, err := db.Exec(fmt.Sprintf(reset, true))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.Exec(fmt.Sprintf(reset, false)) })
	_, err = db.Exec(`DELETE FROM vuln_id_aliases`)
	require.NoError(t, err)

	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	X := fmt.Sprintf("CVE-2096-%d", 1000000+n.Int64())
	vendor := fmt.Sprintf("vid%d", 100000+n.Int64())
	prod := v2Product{Key: "cpe:a:" + vendor + ":widget", Part: "a", Vendor: vendor, Name: "widget", CPEVendor: vendor, CPEProduct: "widget"}
	release := func(seq uint64) v2Release {
		return v2Release{seq: seq, products: []v2Product{prod},
			vulns:  []v2Vuln{{ID: X, Status: "Published", Description: "x"}},
			ranges: []v2Range{{Vuln: X, Product: prod.Key, Scheme: "generic", End: "2.0", Source: "nvd"}}}
	}
	g1, g2 := randomGHSA(t), randomGHSA(t)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM vuln_id_aliases WHERE alias_id IN ($1, $2, 'PYSEC-2096-1')`, g1, g2)
	})
	entry := func(id, cve string) map[string]any { return map[string]any{"id": id, "cve": cve, "source": "ghsa"} }

	feed := newV2Feed(t)
	corpus := postgres.NewCVECorpusRepository(pdb)
	ti := postgres.NewThreatIntelRepository(pdb)
	im, err := vulnfeed.NewImporter(vulnfeed.Config{RootKeyID: feed.rootID, BundleDir: feed.dir}, corpus, ti.SyncStatus(),
		postgres.NewSoftwareRepository(pdb), logger.NewNop())
	require.NoError(t, err)
	vulnfeed.SetClockForTest(im, func() time.Time { return feed.now.Add(time.Hour) })
	vulnfeed.SetRemovalLimitForTest(im, 0, 1<<30)
	im.WithChunks(corpus, vulnfeed.Transfer{CacheDir: t.TempDir()})
	meta := func() map[string]any {
		var raw []byte
		require.NoError(t, db.QueryRow(`SELECT metadata FROM threat_intel_sync_status WHERE source_name = 'vulnfeed'`).Scan(&raw))
		m := map[string]any{}
		require.NoError(t, json.Unmarshal(raw, &m))
		return m
	}
	run := func() {
		t.Helper()
		_, err := im.Run(ctx)
		require.NoError(t, err)
	}
	resolve := func(id string) string {
		got, err := corpus.ResolveVulnIDAliases(ctx, []string{id})
		require.NoError(t, err)
		return got[id]
	}

	feed.publish(feed.root, release(1), nil)
	feed.writeVulnIDs(feed.online, 1, 1, []map[string]any{entry(g1, X), entry("PYSEC-2096-1", X), entry("PYSEC-2096-1", "CVE-2096-0000001"), entry("RHSA-2096:1", X)}, false)
	run()
	m := meta()
	assert.EqualValues(t, 1, m["vulnids_version"])
	assert.EqualValues(t, 1, m["vulnids_entries"])
	assert.EqualValues(t, 1, m["vulnids_conflicting"], "an id with two CVEs is dropped")
	assert.EqualValues(t, 1, m["vulnids_invalid"], "a distro advisory is never an alias")
	assert.Nil(t, m["vulnids_error"])
	assert.Equal(t, X, resolve(g1))
	assert.Empty(t, resolve("PYSEC-2096-1"))

	refused := func(seq uint64, signer ed25519.PrivateKey, built uint64, tamper bool, want string) {
		t.Helper()
		feed.publish(feed.root, release(seq), nil)
		feed.writeVulnIDs(signer, built, 9, []map[string]any{entry(g2, X)}, tamper)
		run()
		m := meta()
		assert.EqualValues(t, seq, m["applied_sequence"], "the corpus import is not undone")
		assert.EqualValues(t, 1, m["vulnids_version"])
		assert.Contains(t, fmt.Sprint(m["vulnids_error"]), want)
		assert.Empty(t, resolve(g2))
	}
	refused(2, feed.online, 1, false, "sequence")
	refused(3, feed.online, 3, true, "SHA-256")
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	refused(4, foreign, 4, false, "not signed")

	// A newer version applies and clears the error.
	feed.publish(feed.root, release(5), nil)
	feed.writeVulnIDs(feed.online, 5, 2, []map[string]any{entry(g1, X), entry(g2, X)}, false)
	run()
	m = meta()
	assert.EqualValues(t, 2, m["vulnids_version"])
	assert.Nil(t, m["vulnids_error"])
	assert.Equal(t, X, resolve(g2))
}
