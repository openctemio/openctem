package auditsink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type memStore struct {
	rows   []Row
	cursor Cursor
	saves  int
}

func newMemStore(n int, at time.Time) *memStore {
	s := &memStore{}
	for i := 1; i <= n; i++ {
		s.rows = append(s.rows, Row{Position: int64(i), Hash: fmt.Sprintf("h%d", i), PrevHash: fmt.Sprintf("h%d", i-1),
			Log: &admin.AuditLog{ID: shared.NewID(), CreatedAt: at, Action: "a", AdminEmail: "root@example.com", Severity: "info"}})
	}
	return s
}

func (s *memStore) ReadForwardRows(_ context.Context, after int64, limit int) ([]Row, error) {
	var out []Row
	for _, r := range s.rows {
		if r.Position > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *memStore) ChainHead(context.Context) (int64, string, error) {
	if len(s.rows) == 0 {
		return 0, "", nil
	}
	l := s.rows[len(s.rows)-1]
	return l.Position, l.Hash, nil
}
func (s *memStore) LoadForwardCursor(context.Context) (Cursor, error) { return s.cursor, nil }
func (s *memStore) SaveForwardCursor(_ context.Context, c Cursor) error {
	s.saves++
	if c.Position > s.cursor.Position {
		s.cursor = c
	}
	return nil
}

type fakeVerifier struct{ rep *admin.AuditChainReport }

func (v *fakeVerifier) VerifyChain(context.Context) (*admin.AuditChainReport, error) {
	return v.rep, nil
}

func okReport() *admin.AuditChainReport {
	return &admin.AuditChainReport{Breaks: []admin.AuditChainBreak{}, VerifiedAt: time.Now()}
}

type fakeSink struct {
	failures int // fail this many sends first
	batches  []Batch
}

func (s *fakeSink) Name() string { return "fake" }
func (s *fakeSink) Close() error { return nil }
func (s *fakeSink) Send(_ context.Context, b Batch) error {
	if s.failures > 0 {
		s.failures--
		return errors.New("sink unavailable")
	}
	s.batches = append(s.batches, b)
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newFwd(t *testing.T, st Store, v Verifier, sink Sink, cfg Config) (*Forwarder, *clock) {
	t.Helper()
	f, err := NewForwarder(st, v, sink, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Now()}
	f.now = c.now
	return f, c
}

func TestRetryBackoffKeepsCursorUntilAcknowledged(t *testing.T) {
	st := newMemStore(3, time.Now())
	sink := &fakeSink{failures: 2}
	f, c := newFwd(t, st, &fakeVerifier{okReport()}, sink, Config{Interval: 10 * time.Second, MaxBackoff: time.Minute})

	if _, err := f.Reconcile(context.Background()); err == nil {
		t.Fatal("first run must fail")
	}
	if st.cursor.Position != 0 {
		t.Fatalf("cursor moved on a failed delivery: %d", st.cursor.Position)
	}
	// Inside the backoff window nothing is attempted.
	c.t = c.t.Add(5 * time.Second)
	if _, err := f.Reconcile(context.Background()); err != nil || sink.failures != 1 {
		t.Fatalf("attempted inside backoff: err=%v failures left=%d", err, sink.failures)
	}
	c.t = c.t.Add(6 * time.Second) // past 10s
	if _, err := f.Reconcile(context.Background()); err == nil {
		t.Fatal("second run must fail")
	}
	// The second failure doubles the delay: 20s, not 10s.
	if got := f.nextAttempt.Sub(c.t); got != 20*time.Second {
		t.Fatalf("backoff = %s, want 20s", got)
	}
	c.t = c.t.Add(21 * time.Second)
	n, err := f.Reconcile(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("recovery: n=%d err=%v", n, err)
	}
	if st.cursor.Position != 3 || st.cursor.Hash != "h3" || len(sink.batches) != 1 {
		t.Fatalf("cursor=%+v batches=%d", st.cursor, len(sink.batches))
	}
	if f.failures != 0 || testutil.ToFloat64(metrics.AdminAuditForwardConsecutiveFailures) != 0 {
		t.Fatal("failure streak not cleared")
	}
}

func TestBatchesAreBounded(t *testing.T) {
	st := newMemStore(25, time.Now())
	sink := &fakeSink{}
	f, _ := newFwd(t, st, &fakeVerifier{okReport()}, sink, Config{BatchSize: 10, MaxBatchesRun: 2})
	n, err := f.Reconcile(context.Background())
	if err != nil || n != 20 || len(sink.batches) != 2 {
		t.Fatalf("n=%d batches=%d err=%v", n, len(sink.batches), err)
	}
	for _, b := range sink.batches {
		if len(b.Rows) > 10 {
			t.Fatalf("batch of %d rows", len(b.Rows))
		}
	}
	if sink.batches[0].ID() != "1-10" || sink.batches[1].ID() != "11-20" {
		t.Fatalf("ids %s %s", sink.batches[0].ID(), sink.batches[1].ID())
	}
	n, _ = f.Reconcile(context.Background())
	if n != 5 || st.cursor.Position != 25 {
		t.Fatalf("rest: n=%d cursor=%d", n, st.cursor.Position)
	}
	if got := testutil.ToFloat64(metrics.AdminAuditForwardLagRows); got != 0 {
		t.Fatalf("lag rows = %v", got)
	}
	// Over-large batch sizes are clamped.
	g, _ := NewForwarder(st, &fakeVerifier{okReport()}, sink, Config{BatchSize: 1 << 20})
	if g.cfg.BatchSize != maxBatchSize {
		t.Fatalf("batch size %d", g.cfg.BatchSize)
	}
}

func TestCursorSurvivesRestart(t *testing.T) {
	st := newMemStore(5, time.Now())
	sink := &fakeSink{}
	f, _ := newFwd(t, st, &fakeVerifier{okReport()}, sink, Config{})
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A new process: new forwarder, same store. Two more rows arrive.
	st.rows = append(st.rows, newMemStore(7, time.Now()).rows[5:]...)
	sink2 := &fakeSink{}
	f2, _ := newFwd(t, st, &fakeVerifier{okReport()}, sink2, Config{})
	n, err := f2.Reconcile(context.Background())
	if err != nil || n != 2 || sink2.batches[0].ID() != "6-7" {
		t.Fatalf("resume: n=%d err=%v", n, err)
	}
}

func TestSaveFailureResendsRows(t *testing.T) {
	st := newMemStore(2, time.Now())
	sink := &fakeSink{}
	f, c := newFwd(t, &failingSave{memStore: st}, &fakeVerifier{okReport()}, sink, Config{Interval: time.Second})
	if _, err := f.Reconcile(context.Background()); err == nil {
		t.Fatal("expected save failure")
	}
	c.t = c.t.Add(time.Minute)
	f.store = st
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.batches) != 2 || sink.batches[0].ID() != sink.batches[1].ID() {
		t.Fatalf("expected the same batch twice (at-least-once), got %d", len(sink.batches))
	}
}

type failingSave struct{ *memStore }

func (f *failingSave) SaveForwardCursor(context.Context, Cursor) error { return errors.New("db down") }

func TestHeadExportedWhenIdle(t *testing.T) {
	st := newMemStore(2, time.Now())
	sink := &fakeSink{}
	f, c := newFwd(t, st, &fakeVerifier{okReport()}, sink, Config{HeadInterval: time.Hour})
	_, _ = f.Reconcile(context.Background()) // rows
	c.t = c.t.Add(10 * time.Minute)
	_, _ = f.Reconcile(context.Background())
	if len(sink.batches) != 1 {
		t.Fatalf("head sent too early: %d batches", len(sink.batches))
	}
	c.t = c.t.Add(time.Hour)
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.batches) != 2 {
		t.Fatalf("no head export: %d batches", len(sink.batches))
	}
	b := sink.batches[1]
	if len(b.Rows) != 0 || b.Head.Position != 2 || b.Head.Hash != "h2" || b.ID() != "head-2" {
		t.Fatalf("head batch %+v", b)
	}
}

func TestChainBreakIsReportedInExportMetricAndLog(t *testing.T) {
	st := newMemStore(2, time.Now())
	sink := &fakeSink{}
	rep := okReport()
	rep.Breaks = []admin.AuditChainBreak{{Position: 2, ID: "x", Reason: admin.ChainBreakChanged}}
	f, c := newFwd(t, st, &fakeVerifier{rep}, sink, Config{VerifyInterval: time.Hour, HeadInterval: time.Minute})
	before := testutil.ToFloat64(metrics.AdminAuditChainBreaks)
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sink.batches[0].Chain; !got.Verified || got.OK || got.Breaks != 1 {
		t.Fatalf("export does not carry the break: %+v", got)
	}
	if testutil.ToFloat64(metrics.AdminAuditChainOK) != 0 {
		t.Fatal("chain_ok gauge not 0")
	}
	if testutil.ToFloat64(metrics.AdminAuditChainBreaks)-before != 1 {
		t.Fatal("break counter not raised")
	}
	// The head export keeps saying so, and a persisting break is counted once.
	c.t = c.t.Add(2 * time.Minute)
	_, _ = f.Reconcile(context.Background())
	if last := sink.batches[len(sink.batches)-1]; last.Chain.OK || len(last.Rows) != 0 {
		t.Fatalf("head export %+v", last)
	}
	// Repaired chain flips the gauge back at the next verification.
	f.verifier = &fakeVerifier{okReport()}
	c.t = c.t.Add(2 * time.Hour)
	_, _ = f.Reconcile(context.Background())
	if testutil.ToFloat64(metrics.AdminAuditChainOK) != 1 {
		t.Fatal("chain_ok gauge not back to 1")
	}
}

func TestLagIsMeasured(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	st := newMemStore(3, old)
	sink := &fakeSink{failures: 1}
	f, c := newFwd(t, st, &fakeVerifier{okReport()}, sink, Config{Interval: time.Second, LagAlert: time.Minute})
	_, _ = f.Reconcile(context.Background()) // fails
	if testutil.ToFloat64(metrics.AdminAuditForwardConsecutiveFailures) != 1 {
		t.Fatal("failure streak not exported")
	}
	c.t = c.t.Add(time.Minute)
	_, _ = f.Reconcile(context.Background())
	if testutil.ToFloat64(metrics.AdminAuditForwardLagRows) != 0 {
		t.Fatal("lag should be 0 after delivery")
	}
}

// slowSink moves the clock on every send, as a slow collector does.
type slowSink struct {
	fakeSink
	c *clock
}

func (s *slowSink) Send(ctx context.Context, b Batch) error {
	s.c.t = s.c.t.Add(time.Minute)
	return s.fakeSink.Send(ctx, b)
}

// The signed timestamp is taken when each batch is sent, not once per run: a
// run of many batches against a slow collector must not send stale stamps the
// receiver would refuse as replays.
func TestSentAtIsTakenPerBatch(t *testing.T) {
	st := newMemStore(25, time.Now())
	sink := &slowSink{}
	f, c := newFwd(t, st, &fakeVerifier{okReport()}, sink, Config{BatchSize: 10, MaxBatchesRun: 3})
	sink.c = c
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.batches) != 3 {
		t.Fatalf("batches = %d", len(sink.batches))
	}
	for i := 1; i < len(sink.batches); i++ {
		if !sink.batches[i].SentAt.After(sink.batches[i-1].SentAt) {
			t.Fatalf("batch %d SentAt %s not after batch %d SentAt %s", i, sink.batches[i].SentAt, i-1, sink.batches[i-1].SentAt)
		}
	}
}

type flakyVerifier struct {
	rep  *admin.AuditChainReport
	fail bool
}

func (v *flakyVerifier) VerifyChain(context.Context) (*admin.AuditChainReport, error) {
	if v.fail {
		return nil, errors.New("database unavailable")
	}
	return v.rep, nil
}

// When the verification cannot run, the export must not keep carrying the
// last good result: it says verified=false until a run succeeds, and the run
// is retried soon rather than after a whole interval.
func TestVerifyFailureExportsUnverified(t *testing.T) {
	st := newMemStore(1, time.Now())
	sink := &fakeSink{}
	v := &flakyVerifier{rep: okReport()}
	f, c := newFwd(t, st, v, sink, Config{VerifyInterval: time.Hour, HeadInterval: time.Minute})
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !sink.batches[0].Chain.Verified || !sink.batches[0].Chain.OK {
		t.Fatalf("first export %+v", sink.batches[0].Chain)
	}
	v.fail = true
	c.t = c.t.Add(time.Hour + time.Minute)
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := sink.batches[len(sink.batches)-1]
	if last.Chain.Verified || last.Chain.OK {
		t.Fatalf("export after a failed verification still vouches: %+v", last.Chain)
	}
	// Retried within minutes, and recovery restores the flag.
	v.fail = false
	c.t = c.t.Add(verifyRetry + time.Second)
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.chain.Verified || !f.chain.OK {
		t.Fatalf("chain status after recovery %+v", f.chain)
	}
}

func TestGapIsReportedButDeliveryContinues(t *testing.T) {
	for name, mutate := range map[string]func(*memStore){
		"missing row":   func(s *memStore) { s.rows = append(s.rows[:2], s.rows[3:]...) },
		"rewritten row": func(s *memStore) { s.rows[2].PrevHash = "forged" },
	} {
		t.Run(name, func(t *testing.T) {
			st := newMemStore(4, time.Now())
			st.cursor = Cursor{Position: 2, Hash: "h2"}
			mutate(st)
			sink := &fakeSink{}
			f, _ := newFwd(t, st, &fakeVerifier{okReport()}, sink, Config{VerifyInterval: time.Hour})
			before := testutil.ToFloat64(metrics.AdminAuditForwardGaps)
			n, err := f.Reconcile(context.Background())
			if err != nil || n == 0 {
				t.Fatalf("delivery stalled: n=%d err=%v", n, err)
			}
			if sink.batches[0].Gap == nil {
				t.Fatal("batch carries no gap")
			}
			if testutil.ToFloat64(metrics.AdminAuditForwardGaps)-before != 1 {
				t.Fatal("gap counter not raised")
			}
			body, _ := marshalBatch(sink.batches[0])
			if !strings.Contains(string(body), `"gap":`) {
				t.Fatalf("payload has no gap: %s", body)
			}
		})
	}
}

func TestContiguousBatchesHaveNoGap(t *testing.T) {
	st := newMemStore(4, time.Now())
	st.cursor = Cursor{Position: 2, Hash: "h2"}
	sink := &fakeSink{}
	f, _ := newFwd(t, st, &fakeVerifier{okReport()}, sink, Config{VerifyInterval: time.Hour})
	if _, err := f.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sink.batches[0].Gap != nil {
		t.Fatalf("false gap %+v", sink.batches[0].Gap)
	}
}
