package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type replayJobs struct {
	ingestjob.V2Repository
	requeued int
}

func (j *replayJobs) RequeueDeadV2(context.Context, shared.ID) (int, error) {
	j.requeued++
	return 1, nil
}

type replayReports struct {
	ingestreport.Repository
	reopened int
	rep      *ingestreport.Report
}

func (r *replayReports) Reopen(context.Context, shared.ID, time.Time) error {
	r.reopened++
	return nil
}

func (r *replayReports) GetByID(context.Context, shared.ID) (*ingestreport.Report, error) {
	return r.rep, nil
}

type fixedDepth int

func (d fixedDepth) TenantDepth(context.Context, shared.ID, time.Time) (int, int, error) {
	return int(d), 0, nil
}

// Replaying a segment of a failed report puts its jobs back on the queue, so
// it is admitted like any continuation: at the tenant's ceiling it is refused
// before anything is requeued or reopened.
func TestV2Replay_FailedReportIsAdmitted(t *testing.T) {
	digest := "sha-256=:AAAA:"
	existing := ingestjob.NewV2Job(shared.NewID(), nil, "r", ingestjob.V2Segment{ContentDigest: digest}, nil)
	body := V2Body{Digest: digest}
	rep := &ingestreport.Report{ID: shared.NewID(), TenantID: shared.NewID(), State: protov2.StateFailed}

	run := func(depth int) (*replayJobs, *replayReports, error) {
		jobs, reports := &replayJobs{}, &replayReports{rep: rep}
		v := &V2Receiver{reports: reports, jobs: jobs, queue: fixedDepth(depth), maxPending: 5,
			limits: protov2.DefaultLimits(), logger: logger.NewNop(), now: time.Now}
		_, err := v.replay(context.Background(), rep, existing, body, time.Now())
		return jobs, reports, err
	}

	// maxPending 5, continuation ceiling 10: at 10 unfinished it is refused.
	jobs, reports, err := run(10)
	var re *V2ReportError
	if !errors.As(err, &re) || re.Problem != protov2.ProblemQueueFull {
		t.Fatalf("at the ceiling: %v, want queue-full", err)
	}
	if jobs.requeued != 0 || reports.reopened != 0 {
		t.Fatalf("refused replay still requeued=%d reopened=%d", jobs.requeued, reports.reopened)
	}

	// Past the new-report limit but under the ceiling it is let through.
	jobs, reports, err = run(7)
	if err != nil || jobs.requeued != 1 || reports.reopened != 1 {
		t.Fatalf("under the ceiling: err=%v requeued=%d reopened=%d", err, jobs.requeued, reports.reopened)
	}
}
