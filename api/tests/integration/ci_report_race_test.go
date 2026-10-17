package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// lateReportRepo records a report the first time a verdict is saved, as if
// an upload of another job landed between the verdict's read of the run's
// findings and its save.
type lateReportRepo struct {
	*postgres.CIRunRepository
	saves int
}

func (l *lateReportRepo) SaveVerdict(ctx context.Context, tenantID, runID shared.ID, verdict string, detail []byte, at time.Time, expectFindings int, failedCapabilities []string) error {
	l.saves++
	if l.saves == 1 {
		if err := l.ReserveRunReport(ctx, tenantID, runID); err != nil {
			return err
		}
		if err := l.RecordRunReport(ctx, tenantID, runID, []string{"fp-landed-late"}); err != nil {
			return err
		}
	}
	return l.CIRunRepository.SaveVerdict(ctx, tenantID, runID, verdict, detail, at, expectFindings, failedCapabilities)
}

// A verdict computed before a concurrent report was recorded is not stored:
// the run is judged again with the report, and a report after the verdict
// is refused instead of silently missing it.
func TestCIRunner_VerdictSeesConcurrentReport(t *testing.T) {
	var late *lateReportRepo
	r := newCIRigWith(t, cirunapp.Config{WebBaseURL: "https://console.example"}, func(d *cirunapp.Deps) {
		late = &lateReportRepo{CIRunRepository: d.Repo.(*postgres.CIRunRepository)}
		d.Repo = late
	})
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	const sha = "4444444444444444444444444444444444444444"
	code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	token, _ := ex["token"].(string)
	runID, _ := ex["run_id"].(string)

	resp, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, map[string]int{"scan_failures": 0})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
	}
	if late.saves != 2 {
		t.Fatalf("verdict saved %d times, want a refused stale save and a second judgement", late.saves)
	}
	id, _ := shared.IDFromString(runID)
	run, err := r.repo.GetRun(context.Background(), r.tenant, id)
	if err != nil || run.Status != cirun.StatusEvaluated || run.FindingsCount != 1 {
		t.Fatalf("stored run: %+v %v", run, err)
	}

	// After the verdict an upload is refused (409), never recorded unseen.
	resp, body := r.post("/api/v1/ci/runs/"+runID+"/results", token, map[string]any{
		"version": "1.0", "metadata": map[string]any{"source_type": "scanner"},
		"tool": map[string]any{"name": "semgrep"},
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("upload after the verdict: %d %v", resp.StatusCode, body)
	}
}
