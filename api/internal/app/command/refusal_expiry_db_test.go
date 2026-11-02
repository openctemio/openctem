package command

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A job that waited for an eligible sensor after sensors refused it expires
// with the refusals as its reason, under the policy-refusal code: the run
// says which target no sensor's policy allows and which file to edit,
// instead of a bare "expired".
func TestExpirationChecker_RefusedJobExpiresWithTheRefusals(t *testing.T) {
	ctx := context.Background()
	db := openCommandDB(t)
	repo := postgres.NewCommandRepository(db)
	tenantID := seedExpiryTenant(ctx, t, db)

	runID := shared.NewID().String()
	payload, _ := json.Marshal(map[string]any{"scan_run_id": runID, "step_key": "subdomains",
		"scanner": "subfinder", "targets": []string{"example.com"}})
	created, err := NewService(repo, logger.NewNop()).Create(ctx, CreateInput{
		TenantID: tenantID.String(), Type: string(commanddom.CommandTypeScan), Payload: payload,
	})
	if err != nil {
		t.Fatalf("create command: %v", err)
	}
	rec, _ := json.Marshal([]commanddom.RefusalRecord{{SensorID: shared.NewID().String(), SensorName: "vn-office",
		Layer: "local", Rule: "targets.allow", Detail: "example.com is outside the allowed ranges", At: time.Now()}})
	if _, err := db.ExecContext(ctx,
		`UPDATE commands SET refusals = $2::jsonb, expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`,
		created.ID.String(), string(rec)); err != nil {
		t.Fatalf("seed refusals: %v", err)
	}

	failer := &stubStepFailer{}
	checker := NewExpirationChecker(repo, nil, ExpirationCheckerConfig{}, logger.NewNop())
	checker.scanRunService = failer
	checker.checkAndExpire()

	var got *recordedStepFailure
	for i := range failer.calls {
		if failer.calls[i].runID == runID {
			got = &failer.calls[i]
		}
	}
	if got == nil {
		t.Fatal("the run was not told the job expired")
	}
	if got.code != scanrundom.FailurePolicyRefused {
		t.Fatalf("code %q, want %q", got.code, scanrundom.FailurePolicyRefused)
	}
	for _, want := range []string{"example.com", "vn-office", "sensors/vn-office/policy/sensor-policy.yaml", "targets.allow"} {
		if !strings.Contains(got.message, want) {
			t.Fatalf("reason %q lacks %q", got.message, want)
		}
	}
	var msg string
	if err := db.QueryRowContext(ctx, `SELECT error_message FROM commands WHERE id = $1`, created.ID.String()).Scan(&msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "vn-office") {
		t.Fatalf("stored reason %q does not name the refusing sensor", msg)
	}
}
