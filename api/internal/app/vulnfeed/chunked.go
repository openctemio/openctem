package vulnfeed

// Chunked bundles (bundle format v2, docs/architecture/feed-transfer.md):
// the SDK consumer verifies the key set against the pinned root (and the
// newest key-set version accepted before), the signed pointer and manifest
// (sequence newer than the applied one, a delta only on its base, expiry,
// caps) before the first chunk, then hands each hash-verified chunk to the
// applier below. The applier re-validates every record with the platform's
// parsers and writes the chunk stamped with the bundle sequence, together
// with the checkpoint, in one transaction. Finishing the bundle removes
// what it replaced, behind the removal guard. A crash resumes at the next
// chunk; a refused chunk leaves everything after it unapplied.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer"
	"github.com/openctemio/sdk-go/pkg/transfer/bundle"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// FeedV2 is the feed name of vulnerability v2 bundles (their payload
// types).
const FeedV2 = "vulnfeed"

// Streams of a vulnerability v2 manifest, in apply order.
const (
	streamProducts = "products"
	streamVulns    = "vulns"
	streamRanges   = "ranges"
)

// v2Limits are the vulnerability feed's caps.
var v2Limits = bundle.Limits{
	MaxChunkBytes:        32 << 20,
	MaxChunkUncompressed: 64 << 20,
	MaxChunkRecords:      20000,
	MaxRecordBytes:       vulnbundle.MaxRecordBytes,
	MaxTotalBytes:        vulnbundle.MaxDecompressedBytes,
	MaxValidity:          vulnbundle.MaxBundleValidity,
}

// ChunkStore applies chunked bundles to the corpus
// (*postgres.CVECorpusRepository).
type ChunkStore interface {
	// FeedCheckpoint is the feed's durable progress.
	FeedCheckpoint() bundle.Checkpoint
	// ApplyFeedChunk applies one chunk and advances the checkpoint to next
	// in the same transaction.
	ApplyFeedChunk(ctx context.Context, c cvecorpus.Chunk, next bundle.State) (cvecorpus.PageResult, error)
	// FinishFeedBundle removes what the bundle replaced and records the
	// applied sequence, in one transaction.
	FinishFeedBundle(ctx context.Context, f cvecorpus.Finish, done bundle.State) (cvecorpus.FinishResult, error)
}

// Transfer configures how v2 bundles are fetched.
type Transfer struct {
	// Mirrors are tried, in order, after the release URL (operator
	// configuration, never request input).
	Mirrors []string
	// CacheDir holds verified chunks between runs (0700).
	CacheDir string
	// Client sends every request (the SSRF-guarded client).
	Client *http.Client
	// Registerer receives the fetcher and consumer counters (nil: none).
	Registerer prometheus.Registerer
}

// WithChunks enables v2 bundles; without it only v1 bundles are read.
func (im *Importer) WithChunks(store ChunkStore, t Transfer) *Importer {
	im.chunks, im.transfer = store, t
	return im
}

// v2Meta is the part of a v2 manifest's meta block the importer reads.
type v2Meta struct {
	Sources []vulnbundle.Source `json:"sources"`
}

// checkLayout refuses a manifest that is not a vulnerability bundle: the
// streams products, vulns, ranges, each with chunks in strictly ascending
// id ranges (no record appears twice in a bundle).
func checkLayout(m *bundle.Manifest) error {
	if len(m.Streams) != 3 || m.Streams[0].Name != streamProducts || m.Streams[1].Name != streamVulns || m.Streams[2].Name != streamRanges {
		return errors.New("manifest streams must be products, vulns, ranges")
	}
	for _, s := range m.Streams {
		last := ""
		for _, c := range s.Chunks {
			if c.FirstID <= last {
				return fmt.Errorf("%s chunks overlap or are out of order", s.Name)
			}
			last = c.LastID
		}
	}
	return nil
}

// chunkApplier is the vulnerability feed's bundle.Applier.
type chunkApplier struct {
	im *Importer
	// keySetVersion is the key set the run verified.
	keySetVersion uint64
	curated       bool
	cves, ranges  int
	finish        cvecorpus.FinishResult
	createdAt     time.Time
	sources       []vulnbundle.Source
}

// parse validates every record of a chunk: the platform's per-record
// parser, then strictly ascending ids inside the chunk's declared range.
func (a *chunkApplier) parse(c *bundle.Chunk) (cvecorpus.Chunk, error) {
	out := cvecorpus.Chunk{Sequence: c.Manifest.Sequence}
	prev := ""
	order := func(id string) error {
		if id <= prev || id < c.Ref.FirstID || id > c.Ref.LastID {
			return fmt.Errorf("%s record %s is out of order or outside its chunk", c.Stream, id)
		}
		prev = id
		return nil
	}
	err := c.Records(func(line []byte) error {
		switch c.Stream {
		case streamProducts:
			key, cpe, err := vulnbundle.ParseProduct(line)
			if err != nil {
				return err
			}
			out.Products = append(out.Products, cvecorpus.Product{Key: key, CPE: cpe})
			return order(key)
		case streamVulns:
			cve, err := vulnbundle.ParseVuln(line)
			if err != nil {
				return err
			}
			out.CVEs = append(out.CVEs, cve)
			return order(cve.ID)
		default:
			r, err := vulnbundle.ParseRange(line)
			if err != nil {
				return err
			}
			out.Ranges = append(out.Ranges, r)
			return order(r.Key)
		}
	})
	return out, err
}

// ApplyChunk implements bundle.Applier.
func (a *chunkApplier) ApplyChunk(ctx context.Context, c *bundle.Chunk, next bundle.State) error {
	if err := checkLayout(c.Manifest); err != nil {
		return err
	}
	fc, err := a.parse(c)
	if err != nil {
		return fmt.Errorf("chunk %d (%s): %w", c.Index+1, c.Stream, err)
	}
	// Curated products exist before a bundle names products, so alternate
	// vendors resolve to them.
	if !a.curated && len(fc.Products) > 0 {
		if err := a.im.catalog.EnsureCurated(ctx, software.CuratedProducts()); err != nil {
			return fmt.Errorf("curated products: %w", err)
		}
		a.curated = true
	}
	res, err := a.im.chunks.ApplyFeedChunk(ctx, fc, next)
	if err != nil {
		return err
	}
	a.cves += res.Upserted
	a.ranges += res.RangesWritten
	return nil
}

// Complete implements bundle.Applier.
func (a *chunkApplier) Complete(ctx context.Context, m *bundle.Manifest, done bundle.State) error {
	if err := checkLayout(m); err != nil {
		return err
	}
	res, err := a.im.chunks.FinishFeedBundle(ctx, cvecorpus.Finish{Sequence: m.Sequence, Snapshot: m.Kind == bundle.KindSnapshot,
		MaxEmptiedShare: a.im.emptiedShare, MinEmptiedLimit: a.im.minEmptied}, done)
	if err != nil {
		return err
	}
	a.finish, a.createdAt = res, m.CreatedAt
	// The signed meta block names the sources and their attribution
	// (informational: shown in the feed status).
	var meta v2Meta
	if len(m.Meta) > 0 && json.Unmarshal(m.Meta, &meta) == nil {
		a.sources = meta.Sources
	}
	return nil
}

// trust verifies the release's key set against the pinned root and the
// newest key-set version accepted before, and trusts its keys.
func (im *Importer) trust(a *chunkApplier, minVersion uint64) func(context.Context, []byte) (bundle.Verifier, error) {
	return func(_ context.Context, raw []byte) (bundle.Verifier, error) {
		ks, err := vulnbundle.VerifyKeySet(raw, im.cfg.RootKeyID, minVersion, im.now())
		if err != nil {
			return nil, err
		}
		pubs := make([]ed25519.PublicKey, 0, len(ks.Keys))
		for _, k := range ks.Keys {
			pub, err := k.Decode()
			if err != nil {
				return nil, err
			}
			pubs = append(pubs, pub)
		}
		a.keySetVersion = ks.Version
		return bundle.NewEd25519Verifier(pubs...), nil
	}
}

// fetcherV2 returns the v2 fetcher (built once: its circuit breakers and
// counters persist across runs). The bundle directory, when configured,
// is the only origin (an air-gapped platform reads nothing else).
func (im *Importer) fetcherV2() (*transfer.Fetcher, error) {
	im.fetchMu.Lock()
	defer im.fetchMu.Unlock()
	if im.fetcher != nil {
		return im.fetcher, nil
	}
	var origins []transfer.Origin
	if im.cfg.BundleDir != "" {
		origins = []transfer.Origin{{Dir: im.cfg.BundleDir, Name: "local"}}
	} else {
		origins = append(origins, transfer.Origin{URL: im.cfg.BaseURL + "/latest/download"})
		for _, u := range im.transfer.Mirrors {
			origins = append(origins, transfer.Origin{URL: u})
		}
	}
	client := im.transfer.Client
	if client == nil {
		client = im.http
	}
	f, err := transfer.New(transfer.Config{Origins: origins, Client: client,
		CacheDir: filepath.Join(im.transfer.CacheDir, "vulnfeed"), Logger: im.logger.Logger, UserAgent: "openctem-vulnfeed/1"})
	if err != nil {
		return nil, err
	}
	if im.transfer.Registerer != nil {
		if err := f.Register(im.transfer.Registerer, "openctem", FeedV2); err != nil {
			im.logger.Warn("vulnfeed: fetcher metrics not registered", "error", err)
		}
	}
	im.fetcher = f
	return f, nil
}

// useV2 reports whether this run reads v2: the bundle directory holds a
// v2 pointer, or the release serves one. Otherwise the whole-bundle (v1)
// reader is used for this release.
func (im *Importer) useV2(ctx context.Context) bool {
	if im.chunks == nil {
		return false
	}
	if im.cfg.BundleDir != "" {
		st, err := os.Stat(filepath.Join(im.cfg.BundleDir, bundle.PointerFile))
		return err == nil && st.Mode().IsRegular()
	}
	f, err := im.fetcherV2()
	if err != nil {
		im.logger.Warn("vulnfeed: v2 fetcher", "error", err)
		return false
	}
	if _, err := f.Small(ctx, bundle.PointerFile, 64<<10); err != nil {
		im.logger.Debug("vulnfeed: no v2 pointer, reading v1", "error", err)
		return false
	}
	return true
}

// syncCheckpoint carries the sequence the v1 reader applied into the
// checkpoint, so a v2 bundle never re-applies or rolls back past it.
func (im *Importer) syncCheckpoint(ctx context.Context, applied uint64) (bundle.State, error) {
	cp := im.chunks.FeedCheckpoint()
	st, err := cp.Load(ctx)
	if err != nil || st.Applied >= applied {
		return st, err
	}
	st.Applied, st.UpdatedAt = applied, im.now()
	if st.InProgress <= applied {
		st.InProgress, st.Kind, st.Manifest, st.NextChunk = 0, "", "", 0
	}
	return st, cp.Save(ctx, st)
}

// runV2 imports the newest v2 bundle through the SDK consumer.
func (im *Importer) runV2(ctx context.Context, cur state) (Result, error) {
	var res Result
	if _, err := im.syncCheckpoint(ctx, cur.Applied); err != nil {
		return res, im.fail(ctx, err)
	}
	f, err := im.fetcherV2()
	if err != nil {
		return res, im.fail(ctx, err)
	}
	a := &chunkApplier{im: im}
	c, err := bundle.NewConsumer(bundle.Config{Feed: FeedV2, Fetcher: f, Trust: im.trust(a, cur.KeySetVersion),
		Checkpoint: im.chunks.FeedCheckpoint(), Applier: a, Limits: v2Limits, Logger: im.logger.Logger, Now: im.now})
	if err != nil {
		return res, im.fail(ctx, err)
	}
	im.registerConsumer(c)
	out, err := c.Run(ctx)
	if err != nil {
		return res, im.fail(ctx, fmt.Errorf("vulnerability bundle refused: %w", err))
	}
	res.Sequence = out.Sequence
	if out.UpToDate {
		return res, nil
	}
	res.Ran, res.Kind, res.CVEs, res.Ranges = true, out.Kind, a.cves, a.ranges
	m := summary{Sequence: out.Sequence, KeySetVersion: a.keySetVersion, CreatedAt: a.createdAt, Kind: out.Kind, Sources: a.sources}
	im.logger.Info("vulnerability bundle chunks applied", "format", "v2", "sequence", out.Sequence, "chunks", out.ChunksApplied,
		"resumed", out.Resumed, "ranges_removed", a.finish.RangesRemoved, "withdrawn", a.finish.Withdrawn, "cves_changed", a.finish.Changed)
	return res, im.finish(ctx, m, res)
}

// registerConsumer registers the consumer's counters once.
func (im *Importer) registerConsumer(c *bundle.Consumer) {
	if im.transfer.Registerer == nil || im.consumerRegistered {
		return
	}
	im.consumerRegistered = true
	if err := c.Register(im.transfer.Registerer, "openctem"); err != nil {
		im.logger.Warn("vulnfeed: consumer metrics not registered", "error", err)
	}
}

// summary is what the status row records about an applied bundle.
type summary struct {
	Sequence      uint64
	KeySetVersion uint64
	CreatedAt     time.Time
	Kind          string
	Sources       []vulnbundle.Source
}
