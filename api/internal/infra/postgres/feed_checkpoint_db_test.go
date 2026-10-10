package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer/bundle"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
)

// feed_checkpoints (migration feed_checkpoints) and the chunked program
// feed apply: exactly-once chunk + checkpoint, refusal of a moved
// checkpoint and of an older sequence, the newer-record guard, the
// signed/local precedence, the snapshot sweep, and no tenant data.
// Requires DATABASE_URL.
func TestFeedCheckpointAndChunks(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`DELETE FROM feed_checkpoints; DELETE FROM program_feed_state;
		UPDATE bounty_programs SET public_program_id = NULL; DELETE FROM public_programs`); err != nil {
		t.Fatal(err)
	}

	// Platform-wide by design: no tenant column, only the known feeds.
	var tenantCols int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'feed_checkpoints' AND column_name LIKE '%tenant%'`).Scan(&tenantCols); err != nil || tenantCols != 0 {
		t.Fatalf("feed_checkpoints has tenant columns: %d %v", tenantCols, err)
	}
	if _, err := db.Exec(`INSERT INTO feed_checkpoints (feed) VALUES ('tenant-1')`); err == nil {
		t.Fatal("an unknown feed row was accepted")
	}
	if _, err := NewFeedCheckpoint(pdb, "tenant-1"); err == nil {
		t.Fatal("NewFeedCheckpoint accepted an unknown feed")
	}

	cat := NewPublicProgramRepository(pdb)
	cp := cat.FeedCheckpoint(bountyprogram.StreamSigned)
	st, err := cp.Load(ctx)
	if err != nil || st.Applied != 0 || st.InProgress != 0 {
		t.Fatalf("empty checkpoint: %+v %v", st, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	manifest := strings.Repeat("a", 64)
	inProgress := bundle.State{InProgress: 2, Kind: bundle.KindSnapshot, Manifest: manifest, UpdatedAt: now}
	if err := cp.Save(ctx, inProgress); err != nil {
		t.Fatal(err)
	}
	mk := func(id string, seq uint64) bountyprogram.PublicProgram {
		it := bountyprogram.Classify(id + ".example")
		it.InScope, it.Confidence = true, bountyprogram.ConfidencePublished
		p := bountyprogram.PublicProgram{FeedID: "acme-bounty:" + id, Source: "acme-bounty", Platform: "self-hosted",
			Name: "P " + id, URL: "http://acme-bounty.example/" + id, Type: "bounty", Status: bountyprogram.FeedStatusOpen,
			Items: []bountyprogram.Item{it}, AsOf: now, Provenance: bountyprogram.FeedProvenance{Source: "acme-bounty", SourceURL: "https://acme-bounty.example/list.json",
				Dataset: "acme/programs", DatasetCommit: strings.Repeat("b", 40)}}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		p.Sequence = seq
		return p
	}
	next := func(n int) bundle.State { s := inProgress; s.NextChunk = n; return s }

	// Chunk 1 applies and advances the checkpoint in the same transaction.
	n, err := cat.ApplyFeedChunk(ctx, bountyprogram.FeedChunk{Stream: bountyprogram.StreamSigned, Sequence: 2,
		Programs: []bountyprogram.PublicProgram{mk("a", 2), mk("b", 2)}}, next(1))
	if err != nil || n != 2 {
		t.Fatalf("chunk 1: %d %v", n, err)
	}
	if st, _ := cp.Load(ctx); st.NextChunk != 1 || st.InProgress != 2 || st.Manifest != manifest {
		t.Fatalf("checkpoint after chunk 1: %+v", st)
	}
	// The same chunk again (a second run, or a replay): refused, nothing
	// written.
	if _, err := cat.ApplyFeedChunk(ctx, bountyprogram.FeedChunk{Stream: bountyprogram.StreamSigned, Sequence: 2,
		Programs: []bountyprogram.PublicProgram{mk("z", 2)}}, next(1)); !errors.Is(err, ErrCheckpointMoved) {
		t.Fatalf("replayed chunk: %v", err)
	}
	// A failed chunk (a change naming a program the bundle lacks) rolls
	// back its programs and leaves the checkpoint where it was.
	if _, err := cat.ApplyFeedChunk(ctx, bountyprogram.FeedChunk{Stream: bountyprogram.StreamSigned, Sequence: 2,
		Programs: []bountyprogram.PublicProgram{mk("c", 2)}, Listed: []string{"acme-bounty:missing"}}, next(2)); err == nil {
		t.Fatal("change of a missing program accepted")
	}
	var count int
	_ = db.QueryRow(`SELECT count(*) FROM public_programs WHERE feed_id IN ('acme-bounty:z', 'acme-bounty:c')`).Scan(&count)
	if st, _ := cp.Load(ctx); count != 0 || st.NextChunk != 1 {
		t.Fatalf("failed chunk left %d rows, checkpoint %+v", count, st)
	}
	// A dropped program held by the same bundle is refused.
	if _, err := cat.ApplyFeedChunk(ctx, bountyprogram.FeedChunk{Stream: bountyprogram.StreamSigned, Sequence: 2,
		Dropped: []string{"acme-bounty:a"}}, next(2)); err == nil {
		t.Fatal("dropped program held by the bundle accepted")
	}
	if _, err := cat.ApplyFeedChunk(ctx, bountyprogram.FeedChunk{Stream: bountyprogram.StreamSigned, Sequence: 2,
		Listed: []string{"acme-bounty:a"}}, next(2)); err != nil {
		t.Fatalf("chunk 2: %v", err)
	}
	// Complete records the applied sequence in both state tables.
	done := bundle.State{Applied: 2, UpdatedAt: now}
	if err := cat.CompleteFeedBundle(ctx, bountyprogram.FeedComplete{Stream: bountyprogram.StreamSigned, Snapshot: true,
		State: bountyprogram.FeedState{AppliedSequence: 2, KeySetVersion: 3}}, done); err != nil {
		t.Fatal(err)
	}
	fs, _ := cat.FeedState(ctx, bountyprogram.StreamSigned)
	if st, _ := cp.Load(ctx); st.Applied != 2 || st.InProgress != 0 || fs.AppliedSequence != 2 || fs.KeySetVersion != 3 {
		t.Fatalf("after complete: %+v %+v", st, fs)
	}
	// Completing it again, or an older sequence, is refused; the checkpoint
	// never moves back.
	if err := cat.CompleteFeedBundle(ctx, bountyprogram.FeedComplete{Stream: bountyprogram.StreamSigned,
		State: bountyprogram.FeedState{AppliedSequence: 2}}, done); !errors.Is(err, ErrCheckpointMoved) {
		t.Fatalf("second complete: %v", err)
	}
	if err := cp.Save(ctx, bundle.State{Applied: 1}); !errors.Is(err, ErrCheckpointMoved) {
		t.Fatalf("checkpoint rolled back: %v", err)
	}

	// Snapshot 3 holds only b: a is archived by the sweep; a stale record
	// of sequence 2 never replaces b's sequence-3 record.
	in3 := bundle.State{Applied: 2, InProgress: 3, Kind: bundle.KindSnapshot, Manifest: strings.Repeat("b", 64), UpdatedAt: now}
	if err := cp.Save(ctx, in3); err != nil {
		t.Fatal(err)
	}
	n3 := func(k int) bundle.State { s := in3; s.NextChunk = k; return s }
	b3 := mk("b", 3)
	b3.Name = "B three"
	if _, err := cat.ApplyFeedChunk(ctx, bountyprogram.FeedChunk{Stream: bountyprogram.StreamSigned, Sequence: 3,
		Programs: []bountyprogram.PublicProgram{b3}}, n3(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := cat.ApplyFeedChunk(ctx, bountyprogram.FeedChunk{Stream: bountyprogram.StreamSigned, Sequence: 3,
		Programs: []bountyprogram.PublicProgram{mk("b", 2)}}, n3(2)); err == nil {
		t.Fatal("a program of another sequence was accepted in the chunk")
	}
	if err := cat.CompleteFeedBundle(ctx, bountyprogram.FeedComplete{Stream: bountyprogram.StreamSigned, Snapshot: true,
		State: bountyprogram.FeedState{AppliedSequence: 3}}, bundle.State{Applied: 3, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var aRemoved bool
	var bName string
	_ = db.QueryRow(`SELECT removed_at IS NOT NULL FROM public_programs WHERE feed_id = 'acme-bounty:a'`).Scan(&aRemoved)
	_ = db.QueryRow(`SELECT name FROM public_programs WHERE feed_id = 'acme-bounty:b'`).Scan(&bName)
	if !aRemoved || bName != "B three" {
		t.Fatalf("sweep: a removed %v, b %q", aRemoved, bName)
	}
	if fs, _ := cat.FeedState(ctx, bountyprogram.StreamSigned); fs.KeySetVersion != 3 {
		t.Fatalf("key set version went down: %+v", fs)
	}

	// The local stream never replaces a live signed record; its checkpoint
	// is its own row.
	lcp := cat.FeedCheckpoint(bountyprogram.StreamLocal)
	lin := bundle.State{InProgress: 9, Kind: bundle.KindSnapshot, Manifest: strings.Repeat("c", 64), UpdatedAt: now}
	if err := lcp.Save(ctx, lin); err != nil {
		t.Fatal(err)
	}
	lb := mk("b", 9)
	lb.Name = "local b"
	lin.NextChunk = 1
	if n, err := cat.ApplyFeedChunk(ctx, bountyprogram.FeedChunk{Stream: bountyprogram.StreamLocal, Sequence: 9,
		Programs: []bountyprogram.PublicProgram{lb, mk("l", 9)}, Listed: []string{"acme-bounty:b"}}, lin); err != nil || n != 1 {
		t.Fatalf("local chunk: %d %v", n, err)
	}
	_ = db.QueryRow(`SELECT name FROM public_programs WHERE feed_id = 'acme-bounty:b'`).Scan(&bName)
	if bName != "B three" {
		t.Fatalf("local record replaced the signed one: %q", bName)
	}
	if st, _ := cp.Load(ctx); st.Applied != 3 || st.InProgress != 0 {
		t.Fatalf("signed checkpoint touched by the local stream: %+v", st)
	}

	// The whole-bundle importer keeps the checkpoint in step.
	if _, err := cat.Apply(ctx, bountyprogram.FeedApply{Stream: bountyprogram.StreamSigned,
		State: bountyprogram.FeedState{AppliedSequence: 4, KeySetVersion: 3}, Snapshot: false,
		Programs: []bountyprogram.PublicProgram{mk("b", 4)}}); err != nil {
		t.Fatal(err)
	}
	if st, _ := cp.Load(ctx); st.Applied != 4 || st.InProgress != 0 {
		t.Fatalf("v1 apply did not move the checkpoint: %+v", st)
	}
}
