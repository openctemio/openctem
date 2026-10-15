package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// The upload response stays small whatever the report's size: known lists at
// most the limit of decided results (lowest indexes first), known_total counts
// them all and known_truncated says some were left out. A response that grew
// with the report (about 85 bytes per decided result) passed what a client
// reads, so a stored report was taken for a failed upload. The response keeps
// its shape for older clients: known is still the list they read.
func TestCIUploadResponseIsBounded(t *testing.T) {
	r := newCIRigWith(t, cirunapp.Config{WebBaseURL: "https://console.example", KnownLimit: 2})
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"

	findings := make([]ctis.Finding, 5)
	for i := range findings {
		findings[i] = sastWithCode(fmt.Sprintf("Issue %d", i), fmt.Sprintf("py.r%d", i), "app/x.py", 10+i, fmt.Sprintf("call%d(x)", i))
	}
	upload := func(sha, job string) map[string]any {
		t.Helper()
		resp0, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{"job_id": job})})
		if resp0.StatusCode != http.StatusCreated {
			t.Fatalf("exchange: %d %v", resp0.StatusCode, ex)
		}
		id, tok := ex["run_id"].(string), ex["token"].(string)
		resp, up := r.post("/api/v1/ci/runs/"+id+"/results", tok, ciReport(repoName, findings...))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, up)
		}
		return up
	}

	// Nothing decided yet: an empty list, a zero total, not truncated.
	up := upload(strings.Repeat("1", 40), "1")
	if knownCount(t, up) != 0 || up["known_total"] != float64(0) || up["known_truncated"] != nil {
		t.Fatalf("first upload: %v", up)
	}
	// Four of the five are marked false positives on the platform.
	if _, err := r.db.ExecContext(ctx, `UPDATE findings SET status = 'false_positive', resolution = 'false_positive'
		WHERE tenant_id = $1 AND rule_id IN ('py.r0', 'py.r1', 'py.r3', 'py.r4')`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	up = upload(strings.Repeat("2", 40), "2")
	got := knownIndexes(t, up)
	if len(got) != 2 || got[0] == "" || got[1] == "" || up["known_total"] != float64(4) || up["known_truncated"] != true {
		t.Fatalf("bounded upload: known=%v total=%v truncated=%v", got, up["known_total"], up["known_truncated"])
	}
}
