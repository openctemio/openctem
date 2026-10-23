package cirun

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type slotRepo struct {
	cirun.Repository
	reserved int
	released int
}

func (r *slotRepo) ReserveRunReport(context.Context, shared.ID, shared.ID) error {
	r.reserved++
	return nil
}
func (r *slotRepo) ReleaseRunReports(_ context.Context, _, _ shared.ID, n int) error {
	r.released += n
	return nil
}
func (r *slotRepo) RecordRunReport(context.Context, shared.ID, shared.ID, []string) error { return nil }
func (r *slotRepo) RecordRunTools(context.Context, shared.ID, shared.ID, []cirun.ToolLabel) error {
	return nil
}
func (r *slotRepo) ClearCarriedCapabilities(context.Context, shared.ID, shared.ID, string) error {
	return nil
}

// failSecond ingests the first report and fails the second.
type failSecond struct{ calls int }

func (f *failSecond) IngestForCIRun(context.Context, shared.ID, shared.ID, string, *ctis.Report) (*ingest.Output, error) {
	f.calls++
	if f.calls == 2 {
		return nil, errors.New("database down")
	}
	return &ingest.Output{}, nil
}

func sarifZip(t *testing.T, files int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := range files {
		w, err := zw.Create(fmt.Sprintf("r%d.sarif", i))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(w, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[{"id":"r1"}]}},`+
			`"results":[{"ruleId":"r1","level":"error","message":{"text":"bad %d"},"locations":[{"physicalLocation":`+
			`{"artifactLocation":{"uri":"a%d.go"},"region":{"startLine":3}}}]}]}]}`, i, i)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A tool export of several reports takes one slot per further report. When
// the attempt fails and the job is retried, the slots it took are given back
// so the retry does not use the run's slots twice (the slot taken at accept
// stays).
func TestApplyExport_FailedAttemptGivesBackItsSlots(t *testing.T) {
	run := &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID(), Repository: "github.com/acme/api", Branch: "main", CommitSHA: "abc"}
	repo := &slotRepo{}
	s := &Service{repo: repo, ingester: &failSecond{}, log: logger.NewNop()}
	if _, err := s.applyExport(context.Background(), run, sarifZip(t, 3)); err == nil {
		t.Fatal("expected the second report to fail the attempt")
	}
	if repo.reserved != 1 || repo.released != 1 {
		t.Fatalf("reserved %d released %d, want 1/1 (the failed attempt gives its slot back)", repo.reserved, repo.released)
	}

	// A successful attempt keeps the slots it took.
	repo = &slotRepo{}
	s = &Service{repo: repo, ingester: &failSecond{calls: 5}, log: logger.NewNop()}
	if _, err := s.applyExport(context.Background(), run, sarifZip(t, 3)); err != nil {
		t.Fatal(err)
	}
	if repo.reserved != 2 || repo.released != 0 {
		t.Fatalf("reserved %d released %d, want 2/0", repo.reserved, repo.released)
	}
}
