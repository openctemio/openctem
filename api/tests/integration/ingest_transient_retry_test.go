package integration

// A transient store error during ingest (a dropped connection, a lock or
// statement timeout, a deadlock) is not a verdict on the report: the segment
// job fails, the worker retries it, and the report is not completed, so the
// sensor keeps its copy and keeps polling. Only a permanent error rejects
// the findings it kept out.

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// flakyFindings fails CreateBatchWithResult with err while fails > 0.
type flakyFindings struct {
	*postgres.FindingRepository
	fails atomic.Int32
	err   error
}

func (f *flakyFindings) CreateBatchWithResult(ctx context.Context, fs []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	if f.fails.Add(-1) >= 0 {
		return nil, f.err
	}
	return f.FindingRepository.CreateBatchWithResult(ctx, fs)
}

// flakyAssets fails UpsertBatch with err while fails > 0.
type flakyAssets struct {
	*postgres.AssetRepository
	fails atomic.Int32
	err   error
}

func (f *flakyAssets) UpsertBatch(ctx context.Context, as []*asset.Asset) (int, int, map[string]shared.ID, error) {
	if f.fails.Add(-1) >= 0 {
		return 0, 0, nil, f.err
	}
	return f.AssetRepository.UpsertBatch(ctx, as)
}

func newFaultV2Rig(t *testing.T, repos *v2RigRepos) *v2Rig {
	t.Helper()
	guard := ingest.DefaultBlindingGuard()
	return newV2RigRepos(t, guard, repos, func(svc *ingest.Service, db *postgres.DB) {
		svc.SetResultQuarantine(postgres.NewSensorResultRepository(db), sensorresult.DefaultLimits())
		svc.SetCommandReader(postgres.NewCommandRepository(db))
		svc.SetCoverageAutoResolve(ingest.CoverageAutoResolveDryRun, guard)
		svc.SetClosureSettings(autoClosing{})
	})
}

// processOnce runs the segment's job once and returns its error.
func (r *v2Rig) processOnce(reportRef shared.ID, seq int) error {
	r.t.Helper()
	job, err := r.jobs.GetV2Segment(context.Background(), reportRef, seq)
	if err != nil {
		r.t.Fatalf("get segment job: %v", err)
	}
	_, err = r.proc.Process(context.Background(), job)
	return err
}

// receiptsOf returns how many receipts the tenant has, and fails the test
// when one does not reconcile.
func (r *v2Rig) receiptsOf(tn v2Tenant) (n, received int) {
	r.t.Helper()
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT findings_received, findings_created, findings_updated, findings_reopened, findings_suppressed,
			findings_failed, skipped, outcomes
		FROM ingest_receipts WHERE tenant_id = $1`, tn.tenant.String())
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			got int
			c   ingestreceipt.Counts
			raw []byte
		)
		if err := rows.Scan(&got, &c.Created, &c.StillDetected, &c.Reopened, &c.Suppressed, &c.Failed, &c.Skipped, &raw); err != nil {
			r.t.Fatal(err)
		}
		outcomes := map[string]int{}
		if err := json.Unmarshal(raw, &outcomes); err != nil {
			r.t.Fatal(err)
		}
		if u := ingestreceipt.Unaccounted(got, c, outcomes); u != 0 {
			r.t.Fatalf("receipt does not reconcile (%d unaccounted): received %d, counts %+v, outcomes %v", u, got, c, outcomes)
		}
		n++
		received += got
	}
	if err := rows.Err(); err != nil {
		r.t.Fatal(err)
	}
	return n, received
}

func TestIngestV2_TransientFindingWriteErrorRetriesInsteadOfRejecting(t *testing.T) {
	ff := &flakyFindings{err: &pq.Error{Code: "40P01", Message: "deadlock detected"}}
	ff.fails.Store(1)
	r := newFaultV2Rig(t, &v2RigRepos{findings: func(p *postgres.FindingRepository) vulnerability.FindingRepository {
		ff.FindingRepository = p
		return ff
	}})
	tn := r.newTenant("semgrep")
	cmd := r.runCommand(tn, "semgrep", "", "completed", 0)
	rep := r.openAs(tn, "0192a3b4-0000-7000-8000-0000000000e1", "worker", &cmd, tn.segment("semgrep", true))
	r.put(tn, rep, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "b", assetRef: "repo"}))

	// First attempt: the batch write deadlocks. The job fails (the worker
	// retries it), nothing is rejected, no receipt is written, and the
	// report is not completed, so the sensor keeps its copy.
	err := r.processOnce(rep.ID, 0)
	if !errors.Is(err, ingest.ErrRetryLater) {
		t.Fatalf("first attempt: want ErrRetryLater, got %v", err)
	}
	if st := r.status(rep); st.State == protov2.StateCompleted || st.Rejected.Findings != 0 || st.Accepted.Findings != 0 {
		t.Fatalf("after the transient error: %+v", st)
	}
	if n, _ := r.receiptsOf(tn); n != 0 {
		t.Fatalf("a receipt was written for the failed attempt: %d", n)
	}

	// Second attempt succeeds; the report lands once and reconciles.
	if err := r.processOnce(rep.ID, 0); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if !r.commit(tn, rep, 1) {
		t.Fatal("commit")
	}
	st := r.status(rep)
	if st.State != protov2.StateCompleted || st.Accepted.Findings != 2 || st.Rejected.Findings != 0 {
		t.Fatalf("after the retry: %+v", st)
	}
	if got := r.countFindings(tn, ""); got != 2 {
		t.Fatalf("findings stored: %d, want 2", got)
	}
	if got := r.countAssets(tn); got != 1 {
		t.Fatalf("assets stored: %d, want 1", got)
	}
	if n, received := r.receiptsOf(tn); n != 1 || received != 2 {
		t.Fatalf("receipts: %d receiving %d findings, want 1 receiving 2", n, received)
	}
}

func TestIngestV2_TransientAssetWriteErrorRetries(t *testing.T) {
	fa := &flakyAssets{err: context.DeadlineExceeded}
	fa.fails.Store(1)
	r := newFaultV2Rig(t, &v2RigRepos{assets: func(p *postgres.AssetRepository) asset.Repository {
		fa.AssetRepository = p
		return fa
	}})
	tn := r.newTenant("semgrep")
	cmd := r.runCommand(tn, "semgrep", "", "completed", 0)
	rep := r.openAs(tn, "0192a3b4-0000-7000-8000-0000000000e2", "worker", &cmd, tn.segment("semgrep", true))
	r.put(tn, rep, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}))

	if err := r.processOnce(rep.ID, 0); !errors.Is(err, ingest.ErrRetryLater) {
		t.Fatalf("first attempt: want ErrRetryLater, got %v", err)
	}
	if st := r.status(rep); st.State == protov2.StateCompleted || st.Rejected.Findings != 0 {
		t.Fatalf("after the transient error: %+v", st)
	}
	if err := r.processOnce(rep.ID, 0); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if !r.commit(tn, rep, 1) {
		t.Fatal("commit")
	}
	if st := r.status(rep); st.State != protov2.StateCompleted || st.Accepted.Findings != 1 || st.Rejected.Findings != 0 {
		t.Fatalf("after the retry: %+v", st)
	}
	if n, received := r.receiptsOf(tn); n != 1 || received != 1 {
		t.Fatalf("receipts: %d receiving %d findings, want 1 receiving 1", n, received)
	}
}

func TestIngestV2_PermanentFindingWriteErrorStillRejects(t *testing.T) {
	// invalid_byte_sequence_for_encoding: the same bytes fail every time.
	ff := &flakyFindings{err: &pq.Error{Code: "22021", Message: "invalid byte sequence for encoding \"UTF8\""}}
	ff.fails.Store(1)
	r := newFaultV2Rig(t, &v2RigRepos{findings: func(p *postgres.FindingRepository) vulnerability.FindingRepository {
		ff.FindingRepository = p
		return ff
	}})
	tn := r.newTenant("semgrep")
	cmd := r.runCommand(tn, "semgrep", "", "completed", 0)
	rep := r.openAs(tn, "0192a3b4-0000-7000-8000-0000000000e3", "worker", &cmd, tn.segment("semgrep", true))
	r.put(tn, rep, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "b", assetRef: "repo"}))

	if err := r.processOnce(rep.ID, 0); err != nil {
		t.Fatalf("a permanent error is not retried: %v", err)
	}
	if !r.commit(tn, rep, 1) {
		t.Fatal("commit")
	}
	st := r.status(rep)
	if st.State != protov2.StateCompleted || st.Rejected.Findings != 2 || st.Accepted.Findings != 0 {
		t.Fatalf("status: %+v", st)
	}
	if got := r.countFindings(tn, ""); got != 0 {
		t.Fatalf("findings stored: %d, want 0", got)
	}
	if n, received := r.receiptsOf(tn); n != 1 || received != 2 {
		t.Fatalf("receipts: %d receiving %d findings, want 1 receiving 2", n, received)
	}
}
