package handler

import (
	"testing"

	"github.com/openctemio/openctem/server/pkg/validator"
)

// Only the platform creates analysis jobs (for runs of AI agents on AI
// workers, docs/architecture/ai-analysis.md): the commands API refuses the
// `analyze` type, so nobody can hand an AI worker a job of their own making.
func TestCreateCommandRequest_RefusesAnalyze(t *testing.T) {
	v := validator.New()
	if err := v.Validate(CreateCommandRequest{Type: "analyze"}); err == nil {
		t.Fatal("the commands API accepted an analyze command")
	}
	if err := v.Validate(CreateCommandRequest{Type: "scan"}); err != nil {
		t.Fatalf("the commands API refused a scan: %v", err)
	}
}
