package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// noEgress fails every request: in relay mode the importer must not make
// one.
type noEgress struct{ calls atomic.Int32 }

func (n *noEgress) RoundTrip(r *http.Request) (*http.Response, error) {
	n.calls.Add(1)
	return nil, fmt.Errorf("outbound request in relay mode: %s", r.URL.Host)
}

// relayCopy plays the relay sensor: it copies each planned file that the
// origin holds into the spool (a pinned file only when its bytes match, as
// the platform's upload check does).
func relayCopy(t *testing.T, origin, spool string, files []vulnfeed.RelayFile) {
	t.Helper()
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(origin, f.Name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err)
		if f.SHA256 != "" && (sha256Hex(b) != f.SHA256 || int64(len(b)) != f.Size) {
			continue
		}
		require.NoError(t, os.WriteFile(filepath.Join(spool, f.Name), b, 0o600))
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestFeedRelay_ImportFromTheSpoolWithNoEgress: in relay mode the importer
// reads only the relay spool, verifies everything with the pinned root and
// makes no outbound request; a release signed by another key or a tampered
// chunk in the spool is refused, never applied.
func TestFeedRelay_ImportFromTheSpoolWithNoEgress(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	_, err := db.Exec(`DELETE FROM feed_checkpoints WHERE feed = 'vulnfeed';
		UPDATE threat_intel_sync_status SET is_enabled = true, metadata = '{}'::jsonb WHERE source_name = 'vulnfeed'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM feed_checkpoints WHERE feed = 'vulnfeed';
			UPDATE threat_intel_sync_status SET is_enabled = false, metadata = '{}'::jsonb WHERE source_name = 'vulnfeed'`)
	})

	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	base := 100000 + n.Int64()
	X := fmt.Sprintf("CVE-2097-%d", base*10+1)
	vendor := fmt.Sprintf("relay%d", base)
	p := v2Product{Key: "cpe:a:" + vendor + ":alpha", Part: "a", Vendor: vendor, Name: "alpha", CPEVendor: vendor, CPEProduct: "alpha"}
	r := v2Range{Vuln: X, Product: p.Key, Scheme: "generic", End: "1.0", Source: "nvd"}

	var o uint64
	require.NoError(t, db.QueryRow(`SELECT GREATEST((SELECT COALESCE(max(feed_sequence), 0) FROM cve_records),
		(SELECT COALESCE(max(feed_sequence), 0) FROM vulnerability_affected),
		(SELECT COALESCE(max(feed_sequence), 0) FROM cve_feed_products))`).Scan(&o))

	feed := newV2Feed(t) // the publisher's release directory (the origin)
	feed.publish(feed.root, v2Release{seq: o + 1, products: []v2Product{p}, vulns: []v2Vuln{{ID: X, Status: "Analyzed", Description: "x"}},
		ranges: []v2Range{r}}, nil)

	spool := t.TempDir()
	egress := &noEgress{}
	corpus := postgres.NewCVECorpusRepository(pdb)
	ti := postgres.NewThreatIntelRepository(pdb)
	im, err := vulnfeed.NewImporter(vulnfeed.Config{RootKeyID: feed.rootID}, corpus, ti.SyncStatus(), postgres.NewSoftwareRepository(pdb), logger.NewNop())
	require.NoError(t, err)
	vulnfeed.SetClockForTest(im, func() time.Time { return feed.now.Add(time.Hour) })
	vulnfeed.SetRemovalLimitForTest(im, 0, 1<<30)
	im.WithChunks(corpus, vulnfeed.Transfer{CacheDir: t.TempDir(), Client: &http.Client{Transport: egress}})
	im.WithRelay(func(context.Context) string { return spool })

	// Before the relay delivered anything there is nothing to import, and
	// nothing is fetched from the network.
	res, err := im.Run(ctx)
	require.NoError(t, err)
	assert.False(t, res.Ran)

	// The relay cycle: head, then what the plan asks for, until ready.
	relayCopy(t, feed.dir, spool, vulnfeed.RelayHead().Files)
	var plan vulnfeed.RelayPlan
	for i := 0; i < 10; i++ {
		plan, err = im.RelayPlan(ctx, spool)
		require.NoError(t, err)
		if plan.Ready {
			break
		}
		for _, f := range plan.Files {
			assert.NotEmpty(t, f.SHA256, "%s: a file after the head is always pinned", f.Name)
		}
		relayCopy(t, feed.dir, spool, plan.Files)
	}
	require.True(t, plan.Ready, "the plan never got ready")
	assert.Equal(t, o+1, plan.Sequence)

	res, err = im.Run(ctx)
	require.NoError(t, err)
	assert.True(t, res.Ran)
	assert.Equal(t, o+1, res.Sequence)
	assert.Equal(t, []string{X}, queryStrings(t, db, `SELECT cve_id FROM cve_records WHERE cve_id = $1`, X))
	assert.Zero(t, egress.calls.Load(), "relay mode made an outbound request")

	t.Run("a release signed by another key is refused", func(t *testing.T) {
		_, otherRoot, _ := ed25519.GenerateKey(rand.Reader)
		evil := newV2Feed(t)
		evil.root = otherRoot
		evil.publish(otherRoot, v2Release{seq: o + 2, products: []v2Product{p}, vulns: []v2Vuln{{ID: X, Status: "Analyzed", Description: "evil"}},
			ranges: []v2Range{r}}, nil)
		evilSpool := t.TempDir()
		relayCopy(t, evil.dir, evilSpool, vulnfeed.RelayHead().Files)
		_, err := im.RelayPlan(ctx, evilSpool)
		require.Error(t, err, "the planner trusted a key set the pinned root did not sign")
		// Even with every file present, the import refuses it.
		entries, _ := os.ReadDir(evil.dir)
		for _, e := range entries {
			b, _ := os.ReadFile(filepath.Join(evil.dir, e.Name()))
			require.NoError(t, os.WriteFile(filepath.Join(evilSpool, e.Name()), b, 0o600))
		}
		im2, err := vulnfeed.NewImporter(vulnfeed.Config{RootKeyID: feed.rootID}, corpus, ti.SyncStatus(), postgres.NewSoftwareRepository(pdb), logger.NewNop())
		require.NoError(t, err)
		vulnfeed.SetClockForTest(im2, func() time.Time { return feed.now.Add(time.Hour) })
		im2.WithChunks(corpus, vulnfeed.Transfer{CacheDir: t.TempDir(), Client: &http.Client{Transport: egress}})
		im2.WithRelay(func(context.Context) string { return evilSpool })
		_, err = im2.Run(ctx)
		require.Error(t, err)
		assert.Equal(t, []string{"x"}, queryStrings(t, db, `SELECT description FROM cve_records WHERE cve_id = $1`, X))
		assert.Zero(t, egress.calls.Load())
	})

	t.Run("a tampered chunk in the spool is refused", func(t *testing.T) {
		rel2 := v2Release{seq: o + 3, products: []v2Product{p}, vulns: []v2Vuln{{ID: X, Status: "Analyzed", Description: "y"}},
			ranges: []v2Range{r}}
		before := map[string]bool{}
		if entries, err := os.ReadDir(spool); err == nil {
			for _, e := range entries {
				before[e.Name()] = true
			}
		}
		feed.publish(feed.root, rel2, nil)
		relayCopy(t, feed.dir, spool, vulnfeed.RelayHead().Files)
		for i := 0; i < 10; i++ {
			plan, err = im.RelayPlan(ctx, spool)
			require.NoError(t, err)
			if plan.Ready {
				break
			}
			relayCopy(t, feed.dir, spool, plan.Files)
		}
		require.True(t, plan.Ready)
		// Replace the bytes of a chunk this release added, behind the
		// platform's back (same size, same name).
		entries, _ := os.ReadDir(spool)
		var chunk string
		for _, e := range entries {
			if !before[e.Name()] && filepath.Ext(e.Name()) == ".gz" && len(e.Name()) > 70 {
				chunk = filepath.Join(spool, e.Name())
			}
		}
		require.NotEmpty(t, chunk)
		b, err := os.ReadFile(chunk)
		require.NoError(t, err)
		b[len(b)/2] ^= 0xff
		require.NoError(t, os.WriteFile(chunk, b, 0o600))
		_, err = im.Run(ctx)
		require.Error(t, err)
		assert.Equal(t, []string{"x"}, queryStrings(t, db, `SELECT description FROM cve_records WHERE cve_id = $1`, X))
		assert.Zero(t, egress.calls.Load())
	})
}
