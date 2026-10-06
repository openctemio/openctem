package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// TestCIRunnerMinimumVersion: a runner that reports a version below
// SENSOR_MIN_VERSION is refused at the exchange with RUNNER_OUTDATED
// (audited); a supported one, and a client that reports no sensor version,
// are admitted.
func TestCIRunnerMinimumVersion(t *testing.T) {
	r := newCIRigWith(t, cirunapp.Config{Versions: cirun.StatusPolicy{MinVersion: "v0.9.0", LatestVersion: "v1.2.0"}})
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "5555555555555555555555555555555555555555"
	exchange := func(userAgent string) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil)})
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, r.srv.URL+"/api/v1/ci/oidc/exchange", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, out := exchange("openctemio-sensor/0.8.2 openctem-sdk-go/0.16.0")
	if code != http.StatusForbidden || out["code"] != "RUNNER_OUTDATED" {
		t.Fatalf("outdated runner: %d %v", code, out)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", "runner_outdated") != 1 {
		t.Fatal("outdated runner refusal not audited")
	}
	if code, out := exchange("openctemio-sensor/0.9.0 openctem-sdk-go/0.17.0"); code != http.StatusCreated {
		t.Fatalf("supported runner: %d %v", code, out)
	}
	if code, out := exchange("curl/8.5.0"); code != http.StatusCreated {
		t.Fatalf("client without a sensor version: %d %v", code, out)
	}
}
