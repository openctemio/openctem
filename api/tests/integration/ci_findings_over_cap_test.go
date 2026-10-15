package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run that sights more findings than the gate records (MaxRunFindings) fails
// with a reason that says so; it is never judged on the first 100k only, where
// a blocking finding past the cap would be missed and the run would pass.
// Repeating sightings the run already recorded does not count as overflow.
func TestCIRunOverFindingsCapFailsClosed(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"
	const sha = "6666666666666666666666666666666666666666"

	open := func(job string) (string, string) {
		t.Helper()
		resp, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/api", "feature/big", sha, map[string]any{"job_id": job})})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("exchange: %d %v", resp.StatusCode, ex)
		}
		return ex["run_id"].(string), ex["token"].(string)
	}
	evaluate := func(run, tok string) map[string]any {
		t.Helper()
		resp, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", tok, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return v
	}
	// fill records n synthetic sightings, standing in for a huge report.
	fill := func(run string, n int, prefix string) {
		t.Helper()
		fps := make([]string, n)
		for i := range fps {
			fps[i] = fmt.Sprintf("%s-%06d", prefix, i)
		}
		if err := r.repo.RecordRunReport(ctx, r.tenant, shared.MustIDFromString(run), fps); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	// Exactly at the cap, and a repeat of what is recorded: judged normally.
	run, tok := open("1")
	if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok,
		ciReport(repoName, ciFinding("Low", "go.low", "low", ctis.FindingTypeVulnerability, "a.go", 1))); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", resp.StatusCode, out)
	}
	fill(run, cirun.MaxRunFindings-1, "fp")
	fill(run, 1000, "fp")
	if v := evaluate(run, tok); v["verdict"] != "pass" || hasReason(v, cirun.ReasonTooManyFindings) {
		t.Fatalf("run at the cap: %v", v)
	}

	// One sighting past the cap: the run fails, saying why.
	run, tok = open("2")
	fill(run, cirun.MaxRunFindings, "fp")
	fill(run, 1, "extra")
	v := evaluate(run, tok)
	if v["verdict"] != "fail" || !hasReason(v, cirun.ReasonTooManyFindings) {
		t.Fatalf("run over the cap: %v", v)
	}
	var over bool
	if err := r.db.QueryRowContext(ctx, `SELECT findings_over_cap FROM ci_runs WHERE id = $1`, run).Scan(&over); err != nil || !over {
		t.Fatalf("run not marked over the cap: %v %v", over, err)
	}

	// A passing verdict computed before the run went over the cap is
	// refused as changed (the job is judged again); one that names the cap
	// is stored.
	run, _ = open("3")
	id := shared.MustIDFromString(run)
	got, err := r.repo.GetRun(ctx, r.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	fill(run, cirun.MaxRunFindings+1, "fp")
	got.FindingsCount = cirun.MaxRunFindings // the count read with the stale verdict
	if err := r.repo.SaveVerdict(ctx, r.tenant, id, cirun.VerdictPass, []byte(`{"verdict":"pass","reasons":[]}`),
		time.Now(), got.FindingsCount); !errors.Is(err, cirun.ErrRunChanged) {
		t.Fatalf("stale pass stored on a run over the cap: %v", err)
	}
	if err := r.repo.SaveVerdict(ctx, r.tenant, id, cirun.VerdictPass,
		[]byte(`{"verdict":"pass","would_fail":true,"reasons":[{"code":"`+cirun.ReasonTooManyFindings+`"}]}`),
		time.Now(), got.FindingsCount); err != nil {
		t.Fatalf("verdict naming the cap refused: %v", err)
	}
}
