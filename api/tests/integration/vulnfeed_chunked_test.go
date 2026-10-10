package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/sdk-go/pkg/transfer/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// Records of a vulnerability v2 bundle, as the collector writes them.
type v2Product struct {
	Key        string `json:"key"`
	Part       string `json:"part"`
	Vendor     string `json:"vendor"`
	Name       string `json:"name"`
	CPEVendor  string `json:"cpe_vendor"`
	CPEProduct string `json:"cpe_product"`
}

type v2Vuln struct {
	ID          string   `json:"id"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
	CWEs        []string `json:"cwes"`
}

type v2Range struct {
	Vuln      string `json:"vuln"`
	Product   string `json:"product"`
	Scheme    string `json:"scheme"`
	Exact     string `json:"exact,omitempty"`
	Start     string `json:"start,omitempty"`
	StartIncl bool   `json:"start_incl"`
	End       string `json:"end,omitempty"`
	EndIncl   bool   `json:"end_incl"`
	Edition   string `json:"edition"`
	Target    string `json:"target"`
	Condition string `json:"condition,omitempty"`
	Source    string `json:"source"`
}

// id is the collector's range record id: "<vuln>#<sha256(json)[:8]>".
func (r v2Range) id() string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return r.Vuln + "#" + hex.EncodeToString(sum[:8])
}

type v2Release struct {
	seq, base uint64
	kind      string
	products  []v2Product
	vulns     []v2Vuln
	ranges    []v2Range
	// badRange makes one range record invalid (signed all the same).
	badRange bool
}

type v2Feed struct {
	t       *testing.T
	dir     string
	root    ed25519.PrivateKey
	online  ed25519.PrivateKey
	rootID  string
	now     time.Time
	version uint64
}

func newV2Feed(t *testing.T) *v2Feed {
	t.Helper()
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	_, online, _ := ed25519.GenerateKey(rand.Reader)
	return &v2Feed{t: t, dir: t.TempDir(), root: root, online: online,
		rootID: jobsign.KeyID(root.Public().(ed25519.PublicKey)), now: time.Now().UTC().Truncate(time.Second), version: 1}
}

func (f *v2Feed) keySet(root ed25519.PrivateKey) []byte {
	f.t.Helper()
	pub := f.online.Public().(ed25519.PublicKey)
	rootPub := root.Public().(ed25519.PublicKey)
	ks := feedsign.KeySet{Kind: vulnbundle.KeySetKind, Version: f.version, IssuedAt: f.now.Add(-time.Hour), NotAfter: f.now.Add(30 * 24 * time.Hour),
		Keys:      []jobsign.PublicKey{{KeyID: jobsign.KeyID(pub), Algorithm: jobsign.Algorithm, PublicKey: base64.StdEncoding.EncodeToString(pub)}},
		RootKeyID: jobsign.KeyID(rootPub), RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	payload, err := json.Marshal(ks)
	require.NoError(f.t, err)
	env, err := feedsign.Sign(root, vulnbundle.KeySetPayloadType, payload)
	require.NoError(f.t, err)
	return env
}

// write writes one manifest of a release (one record per chunk, so a
// CVE's ranges always span chunks) and returns it with its file reference.
func (f *v2Feed) write(rel v2Release) (*bundle.Manifest, bundle.FileRef) {
	f.t.Helper()
	w, err := bundle.NewWriter(f.dir, bundle.WriterOptions{Feed: vulnfeed.FeedV2, Sequence: rel.seq, Kind: rel.kind,
		BaseSequence: rel.base, TargetRecords: 4, MaxRecords: 1})
	require.NoError(f.t, err)
	add := func(id string, v any) {
		b, err := json.Marshal(v)
		require.NoError(f.t, err)
		require.NoError(f.t, w.Add(id, b))
	}
	require.NoError(f.t, w.Stream("products"))
	sort.Slice(rel.products, func(i, j int) bool { return rel.products[i].Key < rel.products[j].Key })
	for _, p := range rel.products {
		add(p.Key, p)
	}
	require.NoError(f.t, w.Stream("vulns"))
	sort.Slice(rel.vulns, func(i, j int) bool { return rel.vulns[i].ID < rel.vulns[j].ID })
	for _, v := range rel.vulns {
		add(v.ID, v)
	}
	require.NoError(f.t, w.Stream("ranges"))
	sort.Slice(rel.ranges, func(i, j int) bool { return rel.ranges[i].id() < rel.ranges[j].id() })
	for i, r := range rel.ranges {
		id := r.id()
		if rel.badRange && i == len(rel.ranges)-1 {
			r.End = "not a version"
		}
		add(id, r)
	}
	meta, _ := json.Marshal(map[string]any{"sources": []map[string]any{{"name": "nvd", "as_of": f.now, "terms": "public", "attribution": "NVD"}}})
	m, ref, err := w.Finish(meta, f.now, f.now.Add(6*24*time.Hour), bundle.Ed25519Signer{Key: f.online})
	require.NoError(f.t, err)
	return m, ref
}

// publish writes a release (its snapshot and optional delta) into the
// feed directory, signed under root's key set, and returns the chunk file
// of each range id.
func (f *v2Feed) publish(root ed25519.PrivateKey, snap v2Release, delta *v2Release) map[string]string {
	f.t.Helper()
	snap.kind = bundle.KindSnapshot
	m, ref := f.write(snap)
	ptr := bundle.Pointer{Feed: vulnfeed.FeedV2, Sequence: snap.seq, Snapshot: ref, CreatedAt: f.now, ExpiresAt: f.now.Add(6 * 24 * time.Hour)}
	manifests := []*bundle.Manifest{m}
	if delta != nil {
		delta.kind, delta.seq = bundle.KindDelta, snap.seq
		dm, dref := f.write(*delta)
		ptr.Delta, ptr.BaseSequence = &dref, delta.base
		manifests = append(manifests, dm)
	}
	signer := bundle.Ed25519Signer{Key: f.online}
	require.NoError(f.t, bundle.WritePointer(f.dir, ptr, signer))
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, vulnbundle.KeySetFile), f.keySet(root), 0o600))
	chunks := map[string]string{}
	for _, m := range manifests {
		for _, c := range m.Chunks() {
			if c.Stream == "ranges" {
				chunks[c.Ref.FirstID] = filepath.Join(f.dir, bundle.ChunkFile(c.Ref.SHA256))
			}
		}
	}
	return chunks
}

// flakyStore fails a chosen chunk (before it reaches the database) or the
// finish step once, as a crash would.
type flakyStore struct {
	vulnfeed.ChunkStore
	failChunk  int // next-chunk index to fail; 0: none
	failFinish bool
	applied    int
}

func (s *flakyStore) ApplyFeedChunk(ctx context.Context, c cvecorpus.Chunk, next bundle.State) (cvecorpus.PageResult, error) {
	if s.failChunk != 0 && next.NextChunk == s.failChunk {
		s.failChunk = 0
		return cvecorpus.PageResult{}, errors.New("crash mid-bundle")
	}
	s.applied++
	return s.ChunkStore.ApplyFeedChunk(ctx, c, next)
}

func (s *flakyStore) FinishFeedBundle(ctx context.Context, f cvecorpus.Finish, done bundle.State) (cvecorpus.FinishResult, error) {
	if s.failFinish {
		s.failFinish = false
		return cvecorpus.FinishResult{}, errors.New("crash before finish")
	}
	return s.ChunkStore.FinishFeedBundle(ctx, f, done)
}

// Chunked (v2) vulnerability bundles through the real importer, consumer
// and corpus: crash and resume, a corrupted chunk and an invalid record
// refused, a CVE whose ranges span chunks replaced only at finish, the
// removal guard at finish, replay and wrong-root refusal, matcher
// re-evaluation of the changed CVEs only, and the v1 fallback.
//
//nolint:maintidx // one scenario, release after release
func TestVulnFeedChunked(t *testing.T) {
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

	// Corpus data is platform-wide: no tenant column on the new table.
	var tenantCols int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'cve_feed_products' AND column_name LIKE '%tenant%'`).Scan(&tenantCols))
	assert.Zero(t, tenantCols)

	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	base := 100000 + n.Int64()
	cve := func(i int64) string { return fmt.Sprintf("CVE-2098-%d", base*10+i) }
	vendor := fmt.Sprintf("t026v%d", base)
	prod := func(name string) v2Product {
		return v2Product{Key: "cpe:a:" + vendor + ":" + name, Part: "a", Vendor: vendor, Name: name, CPEVendor: vendor, CPEProduct: name}
	}
	pa, pb, pc := prod("alpha"), prod("beta"), prod("gamma")
	rg := func(id string, p v2Product, end string) v2Range {
		return v2Range{Vuln: id, Product: p.Key, Scheme: "generic", End: end, Edition: "", Target: "", Source: "nvd"}
	}
	vuln := func(id, desc string) v2Vuln { return v2Vuln{ID: id, Status: "Analyzed", Description: desc} }
	X, Y, Z := cve(1), cve(2), cve(3)
	x1, x2, x3 := rg(X, pa, "1.0"), rg(X, pb, "2.0"), rg(X, pc, "3.0")
	y1, z1 := rg(Y, pa, "9.0"), rg(Z, pc, "4.0")

	feed := newV2Feed(t)
	corpus := postgres.NewCVECorpusRepository(pdb)
	store := &flakyStore{ChunkStore: corpus}
	ti := postgres.NewThreatIntelRepository(pdb)
	newImporter := func(dir string, root string) *vulnfeed.Importer {
		im, err := vulnfeed.NewImporter(vulnfeed.Config{RootKeyID: root, BundleDir: dir}, corpus, ti.SyncStatus(),
			postgres.NewSoftwareRepository(pdb), logger.NewNop())
		require.NoError(t, err)
		vulnfeed.SetClockForTest(im, func() time.Time { return feed.now.Add(time.Hour) })
		return im.WithChunks(store, vulnfeed.Transfer{CacheDir: t.TempDir()})
	}
	im := newImporter(feed.dir, feed.rootID)
	// The shared test database may hold other tests' CVEs, which a snapshot
	// withdraws: the guard is exercised on its own below.
	vulnfeed.SetRemovalLimitForTest(im, 0, 1<<30)
	checkpoint := func() bundle.State {
		st, err := corpus.FeedCheckpoint().Load(ctx)
		require.NoError(t, err)
		return st
	}
	rangesOf := func(id string) []string {
		return queryStrings(t, db, `SELECT a.range_key || '@' || a.feed_sequence FROM vulnerability_affected a
			JOIN software_products p ON p.id = a.product_id AND p.tenant_id IS NULL
			WHERE a.cve_id = $1 ORDER BY 1`, id)
	}
	keys := func(seq uint64, rs ...v2Range) []string {
		out := make([]string, 0, len(rs))
		for _, r := range rs {
			out = append(out, fmt.Sprintf("%s@%d", r.id(), seq))
		}
		sort.Strings(out)
		return out
	}
	syncedAt := func() map[string]time.Time {
		rows, err := db.Query(`SELECT cve_id, synced_at FROM cve_records WHERE cve_id = ANY($1)`, pq.Array([]string{X, Y, Z}))
		require.NoError(t, err)
		defer rows.Close()
		out := map[string]time.Time{}
		for rows.Next() {
			var id string
			var at time.Time
			require.NoError(t, rows.Scan(&id, &at))
			out[id] = at
		}
		require.NoError(t, rows.Err())
		return out
	}
	status := func() string {
		var s string
		require.NoError(t, db.QueryRow(`SELECT last_sync_status FROM threat_intel_sync_status WHERE source_name = 'vulnfeed'`).Scan(&s))
		return s
	}

	// Sequences start above every one stored (the shared test database may
	// hold rows of earlier runs; a real feed's sequence only grows).
	var o uint64
	require.NoError(t, db.QueryRow(`SELECT GREATEST((SELECT COALESCE(max(feed_sequence), 0) FROM cve_records),
		(SELECT COALESCE(max(feed_sequence), 0) FROM vulnerability_affected),
		(SELECT COALESCE(max(feed_sequence), 0) FROM cve_feed_products))`).Scan(&o))

	// Release 1 (snapshot): 3 product, 3 vuln and 5 range chunks.
	feed.publish(feed.root, v2Release{seq: o + 1, products: []v2Product{pa, pb, pc},
		vulns: []v2Vuln{vuln(X, "x"), vuln(Y, "y"), vuln(Z, "z")}, ranges: []v2Range{x1, x2, x3, y1, z1}}, nil)

	t.Run("crash mid-bundle then resume", func(t *testing.T) {
		store.failChunk = 8 // the second range chunk
		_, err := im.Run(ctx)
		require.Error(t, err)
		st := checkpoint()
		assert.Equal(t, uint64(0), st.Applied)
		assert.Equal(t, o+1, st.InProgress)
		assert.Equal(t, 7, st.NextChunk)
		assert.Equal(t, 7, store.applied)
		assert.Equal(t, "failed", status())

		res, err := im.Run(ctx)
		require.NoError(t, err)
		assert.True(t, res.Ran)
		assert.Equal(t, o+1, res.Sequence)
		assert.Equal(t, 11, store.applied, "the resumed run applies only the remaining chunks")
		st = checkpoint()
		assert.Equal(t, o+1, st.Applied)
		assert.Zero(t, st.InProgress)
		assert.Equal(t, keys(o+1, x1, x2, x3), rangesOf(X))
		assert.Equal(t, keys(o+1, y1), rangesOf(Y))
		assert.Equal(t, keys(o+1, z1), rangesOf(Z))
		assert.Equal(t, "success", status())
	})

	before := syncedAt()
	x4 := rg(X, pb, "2.5")
	rel2 := v2Release{seq: o + 2, products: []v2Product{pa, pb, pc},
		vulns: []v2Vuln{vuln(X, "x"), vuln(Y, "y")}, ranges: []v2Range{x1, x3, x4, y1}}
	chunks := feed.publish(feed.root, rel2, nil)

	t.Run("corrupted chunk refused", func(t *testing.T) {
		path := chunks[x4.id()]
		good, err := os.ReadFile(path)
		require.NoError(t, err)
		bad := append([]byte{}, good...)
		bad[len(bad)/2] ^= 0xff
		require.NoError(t, os.WriteFile(path, bad, 0o600))
		_, err = im.Run(ctx)
		require.Error(t, err)
		assert.Equal(t, o+1, checkpoint().Applied)
		assert.NotContains(t, rangesOf(X), keys(o+2, x4)[0], "nothing of the corrupted chunk is applied")
		require.NoError(t, os.WriteFile(path, good, 0o600))
	})

	t.Run("ranges spanning chunks are replaced only at finish", func(t *testing.T) {
		store.failFinish = true
		_, err := im.Run(ctx)
		require.Error(t, err)
		st := checkpoint()
		assert.Equal(t, o+1, st.Applied)
		assert.Equal(t, o+2, st.InProgress)
		// Every chunk is in: X holds its new ranges and still its old one;
		// Z (not in the snapshot) is untouched until the finish step.
		assert.Equal(t, sortedCopy(append(keys(o+1, x2), keys(o+2, x1, x3, x4)...)), rangesOf(X))
		assert.Equal(t, keys(o+1, z1), rangesOf(Z))

		res, err := im.Run(ctx)
		require.NoError(t, err)
		assert.Equal(t, o+2, res.Sequence)
		assert.Equal(t, keys(o+2, x1, x3, x4), rangesOf(X))
		assert.Equal(t, keys(o+2, y1), rangesOf(Y))
		assert.Empty(t, rangesOf(Z))
		var zStatus string
		require.NoError(t, db.QueryRow(`SELECT status FROM cve_records WHERE cve_id = $1`, Z).Scan(&zStatus))
		assert.Equal(t, "Withdrawn", zStatus)
	})

	t.Run("matcher re-evaluates the changed CVEs only", func(t *testing.T) {
		after := syncedAt()
		assert.True(t, after[X].After(before[X]), "X's ranges changed")
		assert.True(t, after[Z].After(before[Z]), "Z was withdrawn")
		assert.Equal(t, before[Y], after[Y], "Y did not change")
		// The matcher's feed cursor picks exactly the changed CVEs.
		cursor := before[X]
		for _, at := range before {
			if at.After(cursor) {
				cursor = at
			}
		}
		changed := queryStrings(t, db, `SELECT cve_id FROM cve_records WHERE cve_id = ANY($1) AND synced_at > $2 ORDER BY 1`,
			pq.Array([]string{X, Y, Z}), cursor)
		assert.Equal(t, []string{X, Z}, changed)
	})

	t.Run("removal guard at finish", func(t *testing.T) {
		// Delta 3 on 2: X loses every range (3 removed); the guard allows 1.
		feed.publish(feed.root, v2Release{seq: o + 3, products: []v2Product{pa}, vulns: []v2Vuln{vuln(X, "x"), vuln(Y, "y")},
			ranges: []v2Range{y1}}, &v2Release{base: o + 2, vulns: []v2Vuln{vuln(X, "x")}})
		vulnfeed.SetRemovalLimitForTest(im, 0, 1)
		_, err := im.Run(ctx)
		require.ErrorIs(t, err, cvecorpus.ErrRemovalLimit)
		assert.Equal(t, o+2, checkpoint().Applied)
		assert.Equal(t, keys(o+2, x1, x3, x4), rangesOf(X), "a refused finish removes nothing")

		vulnfeed.SetRemovalLimitForTest(im, 0, 3)
		res, err := im.Run(ctx)
		vulnfeed.SetRemovalLimitForTest(im, 0, 1<<30)
		require.NoError(t, err)
		assert.Equal(t, bundle.KindDelta, res.Kind)
		assert.Empty(t, rangesOf(X))
		assert.Equal(t, keys(o+2, y1), rangesOf(Y), "a delta leaves the CVEs it does not hold")
	})

	t.Run("replay and wrong root refused", func(t *testing.T) {
		feed.publish(feed.root, rel2, nil)
		_, err := im.Run(ctx)
		require.ErrorIs(t, err, bundle.ErrRollback)
		assert.Equal(t, o+3, checkpoint().Applied)

		_, other, _ := ed25519.GenerateKey(rand.Reader)
		feed.publish(other, v2Release{seq: o + 4, products: []v2Product{pa}, vulns: []v2Vuln{vuln(Y, "y")},
			ranges: []v2Range{y1}}, nil)
		_, err = im.Run(ctx)
		require.Error(t, err)
		assert.Equal(t, o+3, checkpoint().Applied)
		assert.Equal(t, uint64(0), checkpoint().InProgress)
	})

	t.Run("invalid record refused", func(t *testing.T) {
		feed.publish(feed.root, v2Release{seq: o + 4, products: []v2Product{pa}, vulns: []v2Vuln{vuln(Y, "y2")},
			ranges: []v2Range{y1}, badRange: true}, nil)
		_, err := im.Run(ctx)
		require.Error(t, err)
		assert.Equal(t, o+3, checkpoint().Applied)
		assert.Equal(t, keys(o+2, y1), rangesOf(Y))
	})

	t.Run("v1 fallback", func(t *testing.T) {
		golden := "../../pkg/vulnbundle/testdata/golden"
		root, err := os.ReadFile(filepath.Join(golden, "root-keyid.txt"))
		require.NoError(t, err)
		v1 := newImporter(golden, strings.TrimSpace(string(root)))
		var latest struct {
			Payload []byte `json:"payload"`
		}
		raw, err := os.ReadFile(filepath.Join(golden, vulnbundle.LatestFile))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &latest))
		var l vulnbundle.Latest
		require.NoError(t, json.Unmarshal(latest.Payload, &l))
		vulnfeed.SetClockForTest(v1, func() time.Time { return l.CreatedAt.Add(time.Hour) })

		// The golden v1 bundle (sequence 2) is older than the applied 3.
		res, err := v1.Run(ctx)
		require.NoError(t, err)
		assert.False(t, res.Ran)

		_, err = db.Exec(`DELETE FROM feed_checkpoints WHERE feed = 'vulnfeed';
			UPDATE threat_intel_sync_status SET metadata = '{}'::jsonb WHERE source_name = 'vulnfeed'`)
		require.NoError(t, err)
		res, err = v1.Run(ctx)
		require.NoError(t, err)
		assert.True(t, res.Ran)
		assert.Equal(t, uint64(2), checkpoint().Applied, "the next v2 bundle continues from the v1 sequence")
	})
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func queryStrings(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		out = append(out, v)
	}
	require.NoError(t, rows.Err())
	return out
}
