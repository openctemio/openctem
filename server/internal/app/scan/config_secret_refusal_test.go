package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func isConfigSecretRefusal(err error) bool {
	var de *shared.DomainError
	return errors.As(err, &de) && de.Code == scan.CodeScannerConfigSecret
}

// SECURITY: a quick scan with a credential in its settings is refused
// before anything is stored (the service holds no repository here: a
// store attempt would fail on it).
func TestQuickScanRefusesCredentialBeforeStoring(t *testing.T) {
	svc := &Service{logger: logger.NewNop()}
	_, err := svc.QuickScan(context.Background(), QuickScanInput{
		TenantID: shared.NewID().String(), ScannerName: "nuclei", Targets: []string{"example.com"},
		Config: map[string]any{"headers": map[string]any{"authorization": "Bearer abcdefghijkl"}},
	})
	if !isConfigSecretRefusal(err) {
		t.Fatalf("want the credential refusal, got %v", err)
	}
}

// SECURITY: a workflow step whose stored config holds a credential never
// becomes a command payload.
func TestStepCommandPayloadRefusesCredentialInStepConfig(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "s", Tool: "nuclei",
		Config: map[string]any{"password": "hunter2hunter2"}}
	if _, err := StepCommandPayload(run, step, "nuclei", "sr", nil); !isConfigSecretRefusal(err) {
		t.Fatalf("want the credential refusal, got %v", err)
	}
}
