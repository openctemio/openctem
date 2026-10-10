package programfeed

// Chunked bundles (bundle format v2,
// docs/architecture/feed-transfer.md): the SDK consumer verifies the signed
// pointer and manifest (pinned root and key-set rules through feedsign,
// sequence newer than the applied one, a delta only on its base, expiry,
// caps) before the first chunk, then hands each hash-verified chunk to the
// applier below, which re-validates every record and writes it in one
// transaction together with the checkpoint. A crash resumes at the next
// chunk; a refused chunk leaves everything after it unapplied.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/openctemio/sdk-go/pkg/transfer"
	"github.com/openctemio/sdk-go/pkg/transfer/bundle"
	"github.com/prometheus/client_golang/prometheus"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	feed "github.com/openctemio/openctem/api/pkg/programfeed"
)

// FeedV2 is the feed name of program feed v2 bundles (their payload types).
const FeedV2 = "programfeed"

// Streams of a program feed v2 manifest, in apply order.
const (
	streamPrograms = "programs"
	streamChanges  = "changes"
)

// v2Limits are the program feed's caps (lower than the SDK defaults, and
// the validity of the whole-bundle format).
var v2Limits = bundle.Limits{
	MaxChunkBytes:        32 << 20,
	MaxChunkUncompressed: 64 << 20,
	MaxChunkRecords:      20000,
	MaxRecordBytes:       feed.MaxRecordBytes,
	MaxTotalBytes:        512 << 20,
	MaxValidity:          feed.MaxBundleValidity,
}

// ChunkStore applies chunked bundles to the catalog
// (*postgres.PublicProgramRepository).
type ChunkStore interface {
	// FeedCheckpoint is the durable progress of a stream.
	FeedCheckpoint(stream string) bundle.Checkpoint
	// ApplyFeedChunk applies one chunk and advances the checkpoint to
	// next in the same transaction.
	ApplyFeedChunk(ctx context.Context, c bp.FeedChunk, next bundle.State) (int, error)
	// CompleteFeedBundle finishes the bundle (snapshot sweep, applied
	// sequence) in one transaction.
	CompleteFeedBundle(ctx context.Context, c bp.FeedComplete, done bundle.State) error
}

// Transfer configures how v2 bundles are fetched.
type Transfer struct {
	// URLs are the release URL and its mirrors, tried in order before the
	// bundle directory (operator configuration, never request input).
	URLs []string
	// CacheDir holds verified chunks between runs (0700).
	CacheDir string
	// Client sends every request (the SSRF-guarded client).
	Client *http.Client
	// Registerer receives the fetcher and consumer counters (nil: none).
	Registerer prometheus.Registerer
}

// v2Meta is the part of a v2 manifest's meta block the importer reads.
type v2Meta struct {
	Collector feed.Collector `json:"collector"`
}

// checkLayout refuses a manifest that is not a program feed bundle: the
// streams programs then changes, record totals within the feed's bounds,
// program chunks in strictly ascending id ranges, and (on the signed
// stream) no local-only build.
func checkLayout(m *bundle.Manifest, stream string) error {
	if len(m.Streams) != 2 || m.Streams[0].Name != streamPrograms || m.Streams[1].Name != streamChanges {
		return errors.New("manifest streams must be programs, changes")
	}
	if m.Streams[0].Records > feed.MaxPrograms || m.Streams[1].Records > feed.MaxChanges {
		return errors.New("manifest holds more records than the feed allows")
	}
	last := ""
	for _, c := range m.Streams[0].Chunks {
		if c.FirstID <= last {
			return errors.New("program chunks overlap or are out of order")
		}
		last = c.LastID
	}
	if stream != bp.StreamLocal && len(m.Meta) > 0 {
		var meta v2Meta
		if err := json.Unmarshal(m.Meta, &meta); err != nil {
			return fmt.Errorf("manifest meta: %w", err)
		}
		if meta.Collector.LocalOnly {
			return errors.New("a local-only bundle is never accepted from the signed feed")
		}
	}
	return nil
}

// chunkApplier is the program feed's bundle.Applier.
type chunkApplier struct {
	store  ChunkStore
	parser feed.RecordParser
	stream string
	// keySetVersion is the key set the run verified (signed stream).
	keySetVersion uint64
	programs      int
	changes       int
}

func (a *chunkApplier) parse(c *bundle.Chunk) (bp.FeedChunk, error) {
	seq := c.Manifest.Sequence
	fc := bp.FeedChunk{Stream: a.stream, Sequence: seq}
	prev := ""
	err := c.Records(func(line []byte) error {
		if c.Stream == streamChanges {
			ch, err := a.parser.ParseChange(line)
			if err != nil {
				return err
			}
			if ch.Sequence != seq {
				return fmt.Errorf("change of %s has sequence %d, the bundle is %d", ch.Program, ch.Sequence, seq)
			}
			if ch.Kind == bp.FeedChangeDropped {
				fc.Dropped = append(fc.Dropped, ch.Program)
			} else {
				fc.Listed = append(fc.Listed, ch.Program)
			}
			return nil
		}
		prog, err := a.parser.Parse(line)
		if err != nil {
			return err
		}
		if err := prog.Validate(); err != nil {
			return err
		}
		// Strictly ascending inside the chunk's declared range: with the
		// ordered chunk ranges, no program appears twice in a bundle.
		if prog.FeedID <= prev || prog.FeedID < c.Ref.FirstID || prog.FeedID > c.Ref.LastID {
			return fmt.Errorf("program %s is out of order or outside its chunk", prog.FeedID)
		}
		prev = prog.FeedID
		prog.Sequence = seq
		fc.Programs = append(fc.Programs, prog)
		return nil
	})
	return fc, err
}

// ApplyChunk implements bundle.Applier.
func (a *chunkApplier) ApplyChunk(ctx context.Context, c *bundle.Chunk, next bundle.State) error {
	if err := checkLayout(c.Manifest, a.stream); err != nil {
		return err
	}
	fc, err := a.parse(c)
	if err != nil {
		return fmt.Errorf("chunk %d (%s): %w", c.Index+1, c.Stream, err)
	}
	n, err := a.store.ApplyFeedChunk(ctx, fc, next)
	if err != nil {
		return err
	}
	a.programs += n
	a.changes += len(fc.Listed) + len(fc.Dropped)
	return nil
}

// Complete implements bundle.Applier.
func (a *chunkApplier) Complete(ctx context.Context, m *bundle.Manifest, done bundle.State) error {
	if err := checkLayout(m, a.stream); err != nil {
		return err
	}
	return a.store.CompleteFeedBundle(ctx, bp.FeedComplete{Stream: a.stream, Snapshot: m.Kind == bundle.KindSnapshot,
		State: bp.FeedState{AppliedSequence: m.Sequence, KeySetVersion: a.keySetVersion}}, done)
}

// slogger adapts the importer's logger for the SDK.
func (i *Importer) slogger() *slog.Logger { return i.log.Logger }

// newConsumer builds the SDK consumer of one run.
func (i *Importer) newConsumer(f *transfer.Fetcher, a *chunkApplier, trust func(context.Context, []byte) (bundle.Verifier, error), v bundle.Verifier) (*bundle.Consumer, error) {
	return bundle.NewConsumer(bundle.Config{Feed: FeedV2, Fetcher: f, Trust: trust, Verifier: v,
		Checkpoint: i.chunks.FeedCheckpoint(i.stream), Applier: a, Limits: v2Limits, Logger: i.slogger(), Now: i.now})
}

// trust verifies the release's key set against the pinned root and the
// newest key-set version accepted before (feedsign), and trusts its keys.
func (i *Importer) trust(a *chunkApplier) func(context.Context, []byte) (bundle.Verifier, error) {
	return func(ctx context.Context, raw []byte) (bundle.Verifier, error) {
		state, err := i.catalog.FeedState(ctx, i.stream)
		if err != nil {
			return nil, err
		}
		ks, err := feedsign.VerifyKeySet(raw, feed.KeySetType, i.pinnedRoot, state.KeySetVersion, i.now())
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

// signedFetcher returns the fetcher of the signed stream (built once:
// its circuit breakers and counters persist across runs).
func (i *Importer) signedFetcher() (*transfer.Fetcher, error) {
	i.fetchMu.Lock()
	defer i.fetchMu.Unlock()
	if i.fetcher != nil {
		return i.fetcher, nil
	}
	origins := make([]transfer.Origin, 0, len(i.transfer.URLs)+1)
	for _, u := range i.transfer.URLs {
		origins = append(origins, transfer.Origin{URL: u})
	}
	if dir, ok := i.source.(DirSource); ok && dir != "" {
		origins = append(origins, transfer.Origin{Dir: string(dir), Name: "local"})
	}
	f, err := transfer.New(transfer.Config{Origins: origins, Client: i.transfer.Client,
		CacheDir: filepath.Join(i.transfer.CacheDir, "programfeed"), Logger: i.slogger(), UserAgent: "openctem-programfeed/1"})
	if err != nil {
		return nil, err
	}
	if i.transfer.Registerer != nil {
		if err := f.Register(i.transfer.Registerer, "openctem", FeedV2); err != nil {
			i.log.Warn("program feed: fetcher metrics not registered", "error", err)
		}
	}
	i.fetcher = f
	return f, nil
}

// useV2 reports whether the signed stream reads v2: always when release
// URLs are configured, otherwise when the bundle directory holds a v2
// pointer. Without either, the whole-bundle (v1) reader is used for this
// release.
func (i *Importer) useV2() bool {
	if i.chunks == nil {
		return false
	}
	if i.stream == bp.StreamLocal {
		dir, _ := i.source.(DirSource)
		return dir != "" && fileExists(filepath.Join(string(dir), localSnapshotV2))
	}
	if len(i.transfer.URLs) > 0 {
		return true
	}
	dir, _ := i.source.(DirSource)
	return dir != "" && fileExists(filepath.Join(string(dir), bundle.PointerFile))
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// importV2 runs the SDK consumer once.
func (i *Importer) importV2(ctx context.Context) (*Result, error) {
	a := &chunkApplier{store: i.chunks, parser: i.parser, stream: i.stream}
	var c *bundle.Consumer
	var err error
	if i.stream == bp.StreamLocal {
		var cleanup func()
		c, cleanup, err = i.localConsumer(a)
		if err != nil {
			return nil, fmt.Errorf("program feed refused: %w", err)
		}
		defer cleanup()
	} else {
		f, ferr := i.signedFetcher()
		if ferr != nil {
			return nil, ferr
		}
		if c, err = i.newConsumer(f, a, i.trust(a), nil); err != nil {
			return nil, err
		}
		i.registerConsumer(c)
	}
	res, err := c.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("program feed refused: %w", err)
	}
	out := &Result{Stream: i.stream, Sequence: res.Sequence, Delta: res.Kind == bundle.KindDelta,
		Programs: a.programs, Changes: a.changes, Chunks: res.ChunksApplied, Resumed: res.Resumed}
	if res.UpToDate {
		return out, nil
	}
	out.Subscribers = i.Reconcile(ctx)
	i.log.Info("program feed imported", "stream", i.stream, "format", "v2", "sequence", out.Sequence,
		"chunks", out.Chunks, "resumed", out.Resumed, "programs", out.Programs, "changes", out.Changes)
	return out, nil
}

// registerConsumer registers the signed consumer's counters once.
func (i *Importer) registerConsumer(c *bundle.Consumer) {
	if i.transfer.Registerer == nil || i.consumerRegistered {
		return
	}
	i.consumerRegistered = true
	if err := c.Register(i.transfer.Registerer, "openctem"); err != nil {
		i.log.Warn("program feed: consumer metrics not registered", "error", err)
	}
}

// Unsigned v2 manifests of a local bundle (`programfeed build
// --local-only` writes no pointer and signs nothing).
const (
	localSnapshotV2 = "snapshot.v2.manifest.json"
	localDeltaV2    = "delta.v2.manifest.json"
)

// readLocalManifest reads and checks an unsigned local v2 manifest.
func (i *Importer) readLocalManifest(dir, name, kind string) ([]byte, *bundle.Manifest, error) {
	f, err := os.Open(filepath.Join(dir, name)) //nolint:gosec // the configured directory plus a fixed name
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(io.LimitReader(f, 8<<20+1)); err != nil {
		return nil, nil, err
	}
	if buf.Len() > 8<<20 {
		return nil, nil, fmt.Errorf("%s is too large", name)
	}
	var m bundle.Manifest
	if err := feedsign.DecodeStrict(buf.Bytes(), &m); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := m.Validate(FeedV2, i.now(), v2Limits); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, err)
	}
	if m.Kind != kind {
		return nil, nil, fmt.Errorf("%s: kind %q", name, m.Kind)
	}
	if err := checkLayout(&m, bp.StreamLocal); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, err)
	}
	return buf.Bytes(), &m, nil
}

// localConsumer prepares the consumer of an unsigned local v2 bundle. The
// trust anchor of the local stream is the directory the server
// configuration names plus the administrator's switch, as for the
// whole-bundle reader: the manifests are checked here (strict decoding,
// structure, caps, validity), then wrapped in envelopes signed by a key
// that exists only for this run, in a private 0700 directory where every
// chunk the manifests name links to the operator's file. The SDK consumer
// then applies the bundle with the same pins, chunk hashes, checkpoint and
// resume as the signed feed.
//
//nolint:cyclop // one refusal per rule
func (i *Importer) localConsumer(a *chunkApplier) (*bundle.Consumer, func(), error) {
	dir, _ := i.source.(DirSource)
	src, err := filepath.Abs(string(dir))
	if err != nil {
		return nil, nil, err
	}
	snapRaw, snap, err := i.readLocalManifest(src, localSnapshotV2, bundle.KindSnapshot)
	if err != nil {
		return nil, nil, err
	}
	payloads := map[string][]byte{bundle.KindSnapshot: snapRaw}
	manifests := []*bundle.Manifest{snap}
	if fileExists(filepath.Join(src, localDeltaV2)) {
		deltaRaw, delta, err := i.readLocalManifest(src, localDeltaV2, bundle.KindDelta)
		if err != nil {
			return nil, nil, err
		}
		if delta.Sequence != snap.Sequence {
			return nil, nil, errors.New("local delta and snapshot sequences differ")
		}
		payloads[bundle.KindDelta] = deltaRaw
		manifests = append(manifests, delta)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	signer := bundle.Ed25519Signer{Key: priv}
	if err := os.MkdirAll(i.transfer.CacheDir, 0o700); err != nil {
		return nil, nil, err
	}
	overlay, err := os.MkdirTemp(i.transfer.CacheDir, "programfeed-local-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(overlay) }
	fail := func(err error) (*bundle.Consumer, func(), error) { cleanup(); return nil, nil, err }

	ptr := bundle.Pointer{Feed: FeedV2, Sequence: snap.Sequence, CreatedAt: snap.CreatedAt, ExpiresAt: snap.ExpiresAt}
	for _, m := range manifests {
		env, err := signer.Sign(bundle.ManifestPayloadType(FeedV2), payloads[m.Kind])
		if err != nil {
			return fail(err)
		}
		name := bundle.ManifestFile(m.Kind)
		if err := os.WriteFile(filepath.Join(overlay, name), env, 0o600); err != nil {
			return fail(err)
		}
		ref := bundle.FileRef{Name: name, SHA256: sha256Hex(env), Size: int64(len(env))}
		if m.Kind == bundle.KindSnapshot {
			ptr.Snapshot = ref
		} else {
			ptr.Delta, ptr.BaseSequence = &ref, m.BaseSequence
		}
		for _, c := range m.Chunks() {
			name := bundle.ChunkFile(c.Ref.SHA256)
			link := filepath.Join(overlay, name)
			if fileExists(link) {
				continue
			}
			if err := os.Symlink(filepath.Join(src, name), link); err != nil {
				return fail(err)
			}
		}
	}
	if err := bundle.WritePointer(overlay, ptr, signer); err != nil {
		return fail(err)
	}
	f, err := transfer.New(transfer.Config{Origins: []transfer.Origin{{Dir: overlay, Name: "local"}},
		CacheDir: filepath.Join(i.transfer.CacheDir, "programfeed-local"), Logger: i.slogger(),
		Policy: transfer.Policy{MaxAttempts: 1}})
	if err != nil {
		return fail(err)
	}
	c, err := i.newConsumer(f, a, nil, bundle.NewEd25519Verifier(pub))
	if err != nil {
		return fail(err)
	}
	return c, cleanup, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
