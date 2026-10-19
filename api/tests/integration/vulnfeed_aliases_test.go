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

// writeAliases writes the release's alias manifest and entries, signed by
// signer, built for sequence; tamper corrupts the entries after signing.
func (f *v2Feed) writeAliases(signer ed25519.PrivateKey, sequence, version uint64, entries []map[string]any, tamper bool) {
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
	m := map[string]any{"schema": vulnbundle.AliasesSchema, "sequence": sequence, "version": version,
		"created_at": f.now, "expires_at": f.now.Add(6 * 24 * time.Hour),
		"files": []map[string]any{
			{"name": vulnbundle.AliasesEntriesFile, "sha256": hex.EncodeToString(sum[:]), "size": len(gz), "records": len(entries)},
			{"name": vulnbundle.AliasesStateFile, "sha256": hex.EncodeToString(make([]byte, 32)), "size": 0, "records": 0}},
		"stats": map[string]any{"published": 10, "resolved": 9, "unresolvable": 1, "coverage": 1.0, "future_field": 1}}
	payload, err := json.Marshal(m)
	require.NoError(f.t, err)
	env, err := feedsign.Sign(signer, vulnbundle.AliasesManifestPayloadType, payload)
	require.NoError(f.t, err)
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, vulnbundle.AliasesManifestFile), env, 0o600))
	if tamper {
		gz = append([]byte{}, gz...)
		gz[len(gz)-1] ^= 0xff
	}
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, vulnbundle.AliasesEntriesFile), gz, 0o600))
}

// The release's alias dictionary is applied after the bundle: the CNA's
// name-derived product folds into the canonical one, once per version. A
// dictionary built for another release, a tampered entries file and a
// foreign signature are refused (recorded in the feed status) without
// undoing the corpus import; a newer version applies.
func TestVulnFeedAliases(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	reset := `DELETE FROM feed_checkpoints WHERE feed = 'vulnfeed';
		UPDATE threat_intel_sync_status SET is_enabled = %t, metadata = '{}'::jsonb WHERE source_name = 'vulnfeed'`
	_, err := db.Exec(fmt.Sprintf(reset, true))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.Exec(fmt.Sprintf(reset, false)) })

	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	vendor := fmt.Sprintf("alv%d", 100000+n.Int64())
	cna := v2Product{Key: "cpe:a:" + vendor + "_inc:widget", Part: "a", Vendor: vendor + " Inc", Name: "widget", CPEVendor: vendor + "_inc", CPEProduct: "widget"}
	canon := v2Product{Key: "cpe:a:" + vendor + ":widget", Part: "a", Vendor: vendor, Name: "widget", CPEVendor: vendor, CPEProduct: "widget"}
	X, Y := fmt.Sprintf("CVE-2097-%d", 1000000+n.Int64()), fmt.Sprintf("CVE-2097-%d", 2000000+n.Int64())
	release := func(seq uint64) v2Release {
		return v2Release{seq: seq, products: []v2Product{cna, canon},
			vulns:  []v2Vuln{{ID: X, Status: "Published", Description: "x"}, {ID: Y, Status: "Published", Description: "y"}},
			ranges: []v2Range{{Vuln: X, Product: cna.Key, Scheme: "generic", End: "2.0", Source: "cve5"}, {Vuln: Y, Product: canon.Key, Scheme: "generic", End: "3.0", Source: "nvd"}}}
	}
	entry := func(value, target string) map[string]any {
		return map[string]any{"kind": "cpe", "value": value, "target": target, "basis": "learned", "support": 4}
	}
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
	productOf := func(cve string) string {
		return queryStrings(t, db, `SELECT p.cpe_vendor FROM vulnerability_affected a JOIN software_products p ON p.id = a.product_id WHERE a.cve_id = $1`, cve)[0]
	}
	run := func() {
		t.Helper()
		_, err := im.Run(ctx)
		require.NoError(t, err)
	}

	// Release 1 with dictionary v1.
	feed.publish(feed.root, release(1), nil)
	feed.writeAliases(feed.online, 1, 1, []map[string]any{entry("a:"+vendor+"_inc:widget", "a:"+vendor+":widget")}, false)
	run()
	m := meta()
	assert.EqualValues(t, 1, m["aliases_version"])
	assert.EqualValues(t, 1, m["aliases_entries"])
	assert.Nil(t, m["aliases_error"])
	assert.Equal(t, vendor, productOf(X), "the CNA-named range moved to the canonical product")
	assert.Empty(t, queryStrings(t, db, `SELECT id::text FROM software_products WHERE tenant_id IS NULL AND cpe_vendor = $1`, vendor+"_inc"))

	// Up to date: the same version is not applied again.
	run()
	assert.EqualValues(t, 1, meta()["aliases_version"])

	refused := func(seq uint64, signer ed25519.PrivateKey, built uint64, tamper bool, want string) {
		t.Helper()
		feed.publish(feed.root, release(seq), nil)
		feed.writeAliases(signer, built, 9, []map[string]any{entry("a:"+vendor+"_x:widget", "a:"+vendor+":widget")}, tamper)
		run()
		m := meta()
		assert.EqualValues(t, seq, m["applied_sequence"], "the corpus import is not undone")
		assert.EqualValues(t, 1, m["aliases_version"])
		assert.Contains(t, fmt.Sprint(m["aliases_error"]), want)
	}
	// A dictionary of another release (replayed next to a new bundle).
	refused(2, feed.online, 1, false, "sequence")
	// A tampered entries file.
	refused(3, feed.online, 3, true, "SHA-256")
	// Signed by a key outside the key set.
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	refused(4, foreign, 4, false, "not signed")
	assert.Empty(t, queryStrings(t, db, `SELECT value FROM software_product_aliases WHERE value = $1`, "a:"+vendor+"_x:widget"))

	// A newer version applies and clears the error.
	feed.publish(feed.root, release(5), nil)
	// It also carries a learned entry that would fold the canonical
	// product (NVD ranges) into another one: held, not applied, and listed.
	poison := entry("a:"+vendor+":widget", "a:"+vendor+"_evil:widget")
	feed.writeAliases(feed.online, 5, 2, []map[string]any{entry("a:"+vendor+"_inc:widget", "a:"+vendor+":widget"),
		entry("a:"+vendor+"_corp:widget", "a:"+vendor+":widget"), poison}, false)
	run()
	m = meta()
	assert.EqualValues(t, 2, m["aliases_version"])
	assert.Nil(t, m["aliases_error"])
	assert.EqualValues(t, 1, m["aliases_held"])
	assert.Equal(t, []any{"a:" + vendor + ":widget -> a:" + vendor + "_evil:widget"}, m["aliases_held_values"])
	assert.Equal(t, vendor, productOf(Y), "a held entry folds nothing")
	assert.Len(t, queryStrings(t, db, `SELECT value FROM software_product_aliases WHERE tenant_id IS NULL AND source = 'feed' AND value LIKE $1`, "a:"+vendor+"%"), 2)

	// Rollback: an older dictionary version next to a newer release is
	// not applied (and is not an error).
	feed.publish(feed.root, release(6), nil)
	feed.writeAliases(feed.online, 6, 1, []map[string]any{entry("a:"+vendor+"_old:widget", "a:"+vendor+":widget")}, false)
	run()
	m = meta()
	assert.EqualValues(t, 2, m["aliases_version"])
	assert.Nil(t, m["aliases_error"])
	assert.Empty(t, queryStrings(t, db, `SELECT value FROM software_product_aliases WHERE value = $1`, "a:"+vendor+"_old:widget"))
}
