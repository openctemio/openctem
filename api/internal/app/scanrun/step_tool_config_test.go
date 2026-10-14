package scanrun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeToolConfig struct {
	calls int
	err   error
}

func (f *fakeToolConfig) CheckScanToolConfig(context.Context, shared.ID, string, map[string]any) error {
	f.calls++
	return f.err
}

// Only a step pinned to a tool, with options, is checked; a refusal names
// the step.
func TestCheckStepToolConfig(t *testing.T) {
	refuse := &fakeToolConfig{err: shared.ErrValidation}
	s := &Service{tools: testTools, toolConfig: refuse}
	tid := shared.NewID()
	if err := s.checkStepToolConfig(context.Background(), tid, AddStepInput{Name: "probe", Capabilities: []string{"http"}, Config: map[string]any{"retries": 9}}); err != nil || refuse.calls != 0 {
		t.Fatalf("unpinned step checked: %v (%d calls)", err, refuse.calls)
	}
	if err := s.checkStepToolConfig(context.Background(), tid, AddStepInput{Name: "probe", Tool: "httpx"}); err != nil || refuse.calls != 0 {
		t.Fatalf("step without options checked: %v", err)
	}
	err := s.checkStepToolConfig(context.Background(), tid, AddStepInput{Name: "probe", Tool: "httpx", Config: map[string]any{"retries": 9}})
	if !errors.Is(err, shared.ErrValidation) || refuse.calls != 1 {
		t.Fatalf("pinned step: err = %v (%d calls)", err, refuse.calls)
	}
	if (&Service{tools: testTools}).checkStepToolConfig(context.Background(), tid, AddStepInput{Tool: "httpx", Config: map[string]any{"x": 1}}) != nil {
		t.Fatal("no checker wired: refused")
	}
}
