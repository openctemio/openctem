package programfeed

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer/bundle"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	feed "github.com/openctemio/openctem/api/pkg/programfeed"
)

// memStore is a ChunkStore with the transactional semantics of the
// Postgres one: a chunk and its checkpoint commit together or not at all.
type memStore struct {
	cp       bundle.State
	programs map[string]bp.PublicProgram
	stream   map[string]string
	removed  map[string]bool
	applied  bp.FeedState
	calls    int
	// failAt makes the chunk with this next index fail before commit (a
	// crash mid-bundle); 0: never.
	failAt int
}

func newMemStore() *memStore {
	return &memStore{programs: map[string]bp.PublicProgram{}, stream: map[string]string{}, removed: map[string]bool{}}
}

type memCheckpoint struct{ s *memStore }

func (c memCheckpoint) Load(context.Context) (bundle.State, error) { return c.s.cp, nil }
func (c memCheckpoint) Save(_ context.Context, st bundle.State) error {
	if st.Applied < c.s.cp.Applied {
		return errors.New("checkpoint rolled back")
	}
	c.s.cp = st
	return nil
}

func (s *memStore) FeedCheckpoint(string) bundle.Checkpoint { return memCheckpoint{s} }

func (s *memStore) ApplyFeedChunk(_ context.Context, c bp.FeedChunk, next bundle.State) (int, error) {
	s.calls++
	if s.failAt != 0 && next.NextChunk == s.failAt {
		return 0, errors.New("crash before commit")
	}
	if s.cp.InProgress != next.InProgress || s.cp.NextChunk != next.NextChunk-1 {
		return 0, fmt.Errorf("checkpoint moved: %+v vs %+v", s.cp, next)
	}
	for _, p := range c.Programs {
		s.programs[p.FeedID] = p
		s.stream[p.FeedID] = c.Stream
		delete(s.removed, p.FeedID)
	}
	for _, id := range c.Dropped {
		s.removed[id] = true
	}
	s.cp = next
	return len(c.Programs), nil
}

func (s *memStore) CompleteFeedBundle(_ context.Context, c bp.FeedComplete, done bundle.State) error {
	if done.Applied <= s.cp.Applied {
		return errors.New("not newer")
	}
	if c.Snapshot {
		for id, p := range s.programs {
			if s.stream[id] == c.Stream && p.Sequence < c.State.AppliedSequence {
				s.removed[id] = true
			}
		}
	}
	s.applied, s.cp = c.State, done
	return nil
}

// feedKeys are a test feed's offline root and online key.
type feedKeys struct {
	root, online ed25519.PrivateKey
	rootID       string
}

func newFeedKeys(t *testing.T) feedKeys {
	t.Helper()
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	_, online, _ := ed25519.GenerateKey(rand.Reader)
	return feedKeys{root: root, online: online, rootID: jobsign.KeyID(root.Public().(ed25519.PublicKey))}
}

func (k feedKeys) keySet(t *testing.T, at time.Time, version uint64) []byte {
	t.Helper()
	pub := k.online.Public().(ed25519.PublicKey)
	rootPub := k.root.Public().(ed25519.PublicKey)
	ks := feedsign.KeySet{Kind: feed.KeySetKind, Version: version, IssuedAt: at.Add(-time.Hour), NotAfter: at.Add(30 * 24 * time.Hour),
		Keys:      []jobsign.PublicKey{{KeyID: jobsign.KeyID(pub), Algorithm: jobsign.Algorithm, PublicKey: base64.StdEncoding.EncodeToString(pub)}},
		RootKeyID: k.rootID, RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	payload, _ := json.Marshal(ks)
	env, err := feedsign.Sign(k.root, feed.KeySetPayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// programLine is a valid programfeed/v1 record for id (from the
// collector's fixture record).
func programLine(t *testing.T, id string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join(collector, "seq2", "snapshot-programs.jsonl.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.NewDecoder(gz).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	rec["id"], rec["name"] = id, "Program "+id
	b, _ := json.Marshal(rec)
	return b
}

type v2Opts struct {
	seq, base    uint64
	programs     []string // ids
	changes      []bp.FeedChange
	localOnly    bool
	unsigned     bool // local bundle: no pointer, unsigned manifests
	deltaIDs     []string
	deltaChanges []bp.FeedChange
}

func writeKind(t *testing.T, dir, kind string, o v2Opts, ids []string, changes []bp.FeedChange, at time.Time, signer bundle.Signer) bundle.FileRef {
	t.Helper()
	base := uint64(0)
	if kind == bundle.KindDelta {
		base = o.base
	}
	w, err := bundle.NewWriter(dir, bundle.WriterOptions{Feed: FeedV2, Sequence: o.seq, Kind: kind, BaseSequence: base, TargetRecords: 4})
	if err != nil {
		t.Fatal(err)
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	if err := w.Stream(streamPrograms); err != nil {
		t.Fatal(err)
	}
	for _, id := range sorted {
		if err := w.Add(id, programLine(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Stream(streamChanges); err != nil {
		t.Fatal(err)
	}
	for n, c := range changes {
		line, _ := json.Marshal(map[string]any{"sequence": c.Sequence, "program": c.Program, "kind": c.Kind})
		if err := w.Add(fmt.Sprintf("%s#%06d", c.Program, n), line); err != nil {
			t.Fatal(err)
		}
	}
	meta, _ := json.Marshal(map[string]any{"collector": map[string]any{"version": "test", "commit": "x", "local_only": o.localOnly}})
	_, ref, err := w.Finish(meta, at, at.Add(24*time.Hour), signer)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

type rawSigner struct{}

func (rawSigner) Sign(_ string, payload []byte) ([]byte, error) { return payload, nil }

// writeV2 writes a v2 release (key set, pointer, manifests, chunks).
func writeV2(t *testing.T, k feedKeys, at time.Time, o v2Opts) string {
	t.Helper()
	dir := t.TempDir()
	var signer bundle.Signer = bundle.Ed25519Signer{Key: k.online}
	if o.unsigned {
		signer = rawSigner{}
	}
	snap := writeKind(t, dir, bundle.KindSnapshot, o, o.programs, o.changes, at, signer)
	ptr := bundle.Pointer{Feed: FeedV2, Sequence: o.seq, Snapshot: snap, CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour)}
	if o.base != 0 {
		d := writeKind(t, dir, bundle.KindDelta, o, o.deltaIDs, o.deltaChanges, at, signer)
		ptr.Delta, ptr.BaseSequence = &d, o.base
	}
	if o.unsigned {
		for _, kind := range []string{bundle.KindSnapshot, bundle.KindDelta} {
			from := filepath.Join(dir, bundle.ManifestFile(kind))
			if _, err := os.Stat(from); err == nil {
				if err := os.Rename(from, filepath.Join(dir, kind+".v2.manifest.json")); err != nil {
					t.Fatal(err)
				}
			}
		}
		return dir
	}
	if err := os.WriteFile(filepath.Join(dir, bundle.KeySetFile), k.keySet(t, at, 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bundle.WritePointer(dir, ptr, signer); err != nil {
		t.Fatal(err)
	}
	return dir
}

func ids(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("disclose:%s%03d", prefix, i)
	}
	return out
}

func added(seq uint64, programs ...string) []bp.FeedChange {
	out := make([]bp.FeedChange, 0, len(programs))
	for _, p := range programs {
		out = append(out, bp.FeedChange{Sequence: seq, Program: p, Kind: "program_added"})
	}
	return out
}

func newV2Importer(t *testing.T, dir string, k feedKeys, at time.Time) (*Importer, *memStore, *memCatalog) {
	t.Helper()
	cat, store := &memCatalog{}, newMemStore()
	imp := NewImporter(DirSource(dir), cat, &memSubs{}, k.rootID, nil).WithChunks(store, Transfer{CacheDir: t.TempDir()})
	imp.now = func() time.Time { return at.Add(time.Minute) }
	return imp, store, cat
}

func chunkCount(t *testing.T, dir string) int {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "sha256-*.jsonl.gz"))
	return len(m)
}

// A crash between chunks resumes at the next chunk; no chunk is applied
// twice and the bundle is reported applied only at the end.
func TestV2ResumeAfterCrash(t *testing.T) {
	ctx := context.Background()
	k, at := newFeedKeys(t), time.Now().UTC().Truncate(time.Second)
	progs := ids("p", 30)
	dir := writeV2(t, k, at, v2Opts{seq: 5, programs: progs, changes: added(5, progs[0])})
	if n := chunkCount(t, dir); n < 4 {
		t.Fatalf("want several chunks, got %d", n)
	}
	imp, store, _ := newV2Importer(t, dir, k, at)
	store.failAt = 3
	if _, err := imp.Import(ctx); err == nil {
		t.Fatal("crash not reported")
	}
	if store.cp.Applied != 0 || store.cp.InProgress != 5 || store.cp.NextChunk != 2 || store.applied.AppliedSequence != 0 {
		t.Fatalf("after crash: %+v %+v", store.cp, store.applied)
	}
	partial := len(store.programs)
	if partial == 0 || partial == len(progs) {
		t.Fatalf("partial apply holds %d programs", partial)
	}
	store.failAt, store.calls = 0, 0
	res, err := imp.Import(ctx)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !res.Resumed || res.Sequence != 5 || store.cp.Applied != 5 || store.cp.InProgress != 0 || len(store.programs) != len(progs) {
		t.Fatalf("resumed: %+v cp %+v programs %d", res, store.cp, len(store.programs))
	}
	if store.calls != res.Chunks || store.applied.KeySetVersion != 1 {
		t.Fatalf("chunks applied twice or key set not recorded: calls %d chunks %d %+v", store.calls, res.Chunks, store.applied)
	}
	// The same release again: up to date, nothing applied.
	store.calls = 0
	if res, err := imp.Import(ctx); err != nil || store.calls != 0 || res.Sequence != 5 {
		t.Fatalf("re-import: %+v %v (%d calls)", res, err, store.calls)
	}
}

// A corrupted chunk is refused before it is parsed; nothing after it is
// applied and the bundle is not marked applied.
func TestV2CorruptedChunkRefused(t *testing.T) {
	ctx := context.Background()
	k, at := newFeedKeys(t), time.Now().UTC().Truncate(time.Second)
	dir := writeV2(t, k, at, v2Opts{seq: 4, programs: ids("p", 30)})
	imp, store, _ := newV2Importer(t, dir, k, at)

	// Find the second chunk in apply order and flip a byte.
	var m bundle.Manifest
	raw, _ := os.ReadFile(filepath.Join(dir, bundle.ManifestFile(bundle.KindSnapshot)))
	payload, err := bundle.NewEd25519Verifier(k.online.Public().(ed25519.PublicKey)).Verify(raw, bundle.ManifestPayloadType(FeedV2))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(dir, bundle.ChunkFile(m.Chunks()[1].Ref.SHA256))
	b, _ := os.ReadFile(second)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(second, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := imp.Import(ctx); err == nil {
		t.Fatal("corrupted chunk accepted")
	}
	if store.cp.NextChunk != 1 || store.cp.Applied != 0 || store.applied.AppliedSequence != 0 {
		t.Fatalf("applied past the corrupted chunk: %+v", store.cp)
	}
	if len(store.programs) != m.Chunks()[0].Ref.Records {
		t.Fatalf("programs %d, first chunk holds %d", len(store.programs), m.Chunks()[0].Ref.Records)
	}

	// A tampered manifest is refused before any chunk.
	dir2 := writeV2(t, k, at, v2Opts{seq: 4, programs: ids("p", 10)})
	mf := filepath.Join(dir2, bundle.ManifestFile(bundle.KindSnapshot))
	b, _ = os.ReadFile(mf)
	if err := os.WriteFile(mf, []byte(strings.Replace(string(b), `"payloadType"`, ` "payloadType"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	imp2, store2, _ := newV2Importer(t, dir2, k, at)
	if _, err := imp2.Import(ctx); !errors.Is(err, bundle.ErrPinMismatch) || store2.calls != 0 {
		t.Fatalf("tampered manifest: %v (%d chunks applied)", err, store2.calls)
	}

	// A release signed by another feed's keys is refused.
	other := newFeedKeys(t)
	dir3 := writeV2(t, other, at, v2Opts{seq: 4, programs: ids("p", 3)})
	imp3, store3, _ := newV2Importer(t, dir3, k, at)
	if _, err := imp3.Import(ctx); err == nil || store3.calls != 0 {
		t.Fatalf("foreign root accepted: %v", err)
	}
}

// An older sequence is refused (rollback); a delta applies only on top of
// its base.
func TestV2ReplayAndDelta(t *testing.T) {
	ctx := context.Background()
	k, at := newFeedKeys(t), time.Now().UTC().Truncate(time.Second)
	progs := ids("p", 6)
	dir2 := writeV2(t, k, at, v2Opts{seq: 2, programs: progs})
	imp, store, _ := newV2Importer(t, dir2, k, at)
	if _, err := imp.Import(ctx); err != nil {
		t.Fatal(err)
	}
	// seq 3: snapshot without p000 plus the delta from 2 that drops it.
	dir3 := writeV2(t, k, at, v2Opts{seq: 3, base: 2, programs: progs[1:], deltaIDs: []string{progs[1]},
		deltaChanges: []bp.FeedChange{{Sequence: 3, Program: progs[0], Kind: bp.FeedChangeDropped}}})
	imp.source = DirSource(dir3)
	imp.fetcher = nil
	res, err := imp.Import(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Delta || store.cp.Applied != 3 || !store.removed[progs[0]] || store.programs[progs[1]].Sequence != 3 {
		t.Fatalf("delta: %+v cp %+v removed %v", res, store.cp, store.removed)
	}
	// Replaying seq 2 is refused and changes nothing.
	imp.source = DirSource(dir2)
	imp.fetcher = nil
	store.calls = 0
	if _, err := imp.Import(ctx); !errors.Is(err, bundle.ErrRollback) || store.calls != 0 || store.cp.Applied != 3 {
		t.Fatalf("replay: %v (%d calls, cp %+v)", err, store.calls, store.cp)
	}
}

// Without a v2 pointer the whole-bundle reader still imports (one release).
func TestV2FallbackToV1(t *testing.T) {
	ctx := context.Background()
	root := readFixture(t, "root-keyid.txt")
	at, _ := time.Parse(time.RFC3339, readFixture(t, "created-at.txt"))
	cat, store := &memCatalog{}, newMemStore()
	imp := NewImporter(DirSource(filepath.Join(collector, "seq2")), cat, &memSubs{}, root, nil).
		WithChunks(store, Transfer{CacheDir: t.TempDir()})
	imp.now = func() time.Time { return at.Add(time.Minute) }
	res, err := imp.Import(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.applied) != 1 || res.Sequence != 2 || store.calls != 0 {
		t.Fatalf("v1 fallback: %+v applies %d chunk calls %d", res, len(cat.applied), store.calls)
	}
}

// A local-only bundle is refused on the signed path even when signed; the
// unsigned local v2 bundle is accepted only through the local importer,
// with the same chunk verification.
func TestV2LocalOnly(t *testing.T) {
	ctx := context.Background()
	k, at := newFeedKeys(t), time.Now().UTC().Truncate(time.Second)
	progs := ids("l", 9)

	signedLocal := writeV2(t, k, at, v2Opts{seq: 7, programs: progs, localOnly: true})
	imp, store, _ := newV2Importer(t, signedLocal, k, at)
	if _, err := imp.Import(ctx); err == nil || !strings.Contains(err.Error(), "local-only") || len(store.programs) != 0 {
		t.Fatalf("signed path accepted a local-only bundle: %v", err)
	}

	unsigned := writeV2(t, k, at, v2Opts{seq: 7, programs: progs, localOnly: true, unsigned: true})
	// The signed importer does not read an unsigned bundle (no pointer).
	imp2, store2, cat2 := newV2Importer(t, unsigned, k, at)
	if _, err := imp2.Import(ctx); err == nil || store2.calls != 0 || len(cat2.applied) != 0 {
		t.Fatalf("signed path read an unsigned bundle: %v", err)
	}

	settings := &memSettings{st: bp.LocalBundleSetting{Enabled: true}}
	lstore := newMemStore()
	local := NewLocalImporter(unsigned, &memCatalog{}, &memSubs{}, settings, nil).WithChunks(lstore, Transfer{CacheDir: t.TempDir()})
	local.now = func() time.Time { return at.Add(time.Minute) }
	res, err := local.Import(ctx)
	if err != nil {
		t.Fatalf("local v2: %v", err)
	}
	if res.Stream != bp.StreamLocal || res.Sequence != 7 || len(lstore.programs) != len(progs) || lstore.stream[progs[0]] != bp.StreamLocal {
		t.Fatalf("local v2: %+v programs %d", res, len(lstore.programs))
	}
	// Switched off: nothing is read.
	settings.st.Enabled = false
	if _, err := local.Import(ctx); !errors.Is(err, ErrSourceDisabled) {
		t.Fatalf("disabled local source: %v", err)
	}

	// A corrupted local chunk is refused.
	// (other records: an unchanged chunk would be served, verified, from the cache)
	bad := writeV2(t, k, at, v2Opts{seq: 8, programs: ids("m", 9), unsigned: true})
	chunks, _ := filepath.Glob(filepath.Join(bad, "sha256-*.jsonl.gz"))
	b, _ := os.ReadFile(chunks[0])
	b[len(b)/2] ^= 0xff
	_ = os.WriteFile(chunks[0], b, 0o600)
	settings.st.Enabled = true
	local.source = DirSource(bad)
	if _, err := local.Import(ctx); err == nil || lstore.cp.Applied != 7 {
		t.Fatalf("corrupted local chunk: %v cp %+v", err, lstore.cp)
	}
}
