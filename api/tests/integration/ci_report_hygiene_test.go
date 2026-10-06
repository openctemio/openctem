package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// TestCIReportHygiene: a secret a CI run uploads unmasked is stored nowhere
// in clear; a run cannot upload more than MaxRunReports reports; a pipeline
// cannot start more than MaxPipelineRunsPerHour runs (refused, audited).
func TestCIReportHygiene(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "4444444444444444444444444444444444444444"
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"

	code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	token, runID := ex["token"].(string), ex["run_id"].(string)

	// A converter that sends the raw secret as the "masked" value and in the
	// snippet: nothing of it is stored in clear.
	const raw = "AKIAZQ7TESTRAWSECRETVALUE9876"
	leak := ciFinding("AWS key", "aws-access-key", "high", ctis.FindingTypeSecret, "config.go", 3)
	leak.Secret = &ctis.SecretDetails{SecretType: "aws_access_key", MaskedValue: raw}
	leak.Location.Snippet = `aws_key = "` + raw + `"`
	if resp, out := r.post("/api/v1/ci/runs/"+runID+"/results", token, ciReport(repoName, leak)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", resp.StatusCode, out)
	}
	var stored int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings f WHERE f.tenant_id = $1 AND f.title = 'AWS key'`,
		r.tenant.String()).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("secret finding stored: %d %v", stored, err)
	}
	var clear int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings f WHERE f.tenant_id = $1 AND to_jsonb(f)::text LIKE '%' || $2 || '%'`,
		r.tenant.String(), raw).Scan(&clear)
	if clear != 0 {
		t.Fatal("the raw secret is stored in a finding")
	}
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND (metadata::text LIKE '%' || $2 || '%' OR message LIKE '%' || $2 || '%')`,
		r.tenant.String(), raw).Scan(&clear)
	if clear != 0 {
		t.Fatal("the raw secret is in the audit log")
	}

	// Report cap.
	if _, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET reports_count = $3 WHERE tenant_id = $1 AND id = $2`,
		r.tenant.String(), runID, cirun.MaxRunReports); err != nil {
		t.Fatal(err)
	}
	medium := ciFinding("Weak hash", "go.weak-hash", "medium", ctis.FindingTypeVulnerability, "hash.go", 10)
	if resp, _ := r.post("/api/v1/ci/runs/"+runID+"/results", token, ciReport(repoName, medium)); resp.StatusCode != http.StatusConflict {
		t.Fatalf("report beyond the cap: %d", resp.StatusCode)
	}

	// Per-pipeline rate: the pipeline already started the most runs it may
	// in the last hour.
	if _, err := r.db.ExecContext(ctx, `INSERT INTO ci_runs (id, tenant_id, trust_config_id, repository_asset_id, provider,
		issuer, repository, ref, branch, commit_sha, status, pipeline_id, created_at, updated_at)
		SELECT gen_random_uuid(), tenant_id, trust_config_id, repository_asset_id, provider, issuer, repository, ref, branch,
			commit_sha, 'evaluated', pipeline_id, now(), now()
		FROM ci_runs, generate_series(1, $3) WHERE tenant_id = $1 AND id = $2`,
		r.tenant.String(), runID, cirun.MaxPipelineRunsPerHour); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil)); code != http.StatusUnauthorized {
		t.Fatalf("exchange over the pipeline rate: %d", code)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", "pipeline_rate") != 1 {
		t.Fatal("pipeline rate refusal not audited")
	}
	// Another pipeline (another workflow file) is not affected.
	other := r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{
		"ci_config_ref_uri": host + "/acme/api//.gitlab/other.yml@refs/heads/main"})
	if code, ex := r.exchange(r.tenant, other); code != http.StatusCreated {
		t.Fatalf("another pipeline: %d %v", code, ex)
	}
}
