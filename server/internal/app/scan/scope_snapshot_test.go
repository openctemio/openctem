package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeSnapshots struct {
	got []string
	err error
}

func (f *fakeSnapshots) RecordRunSnapshot(_ context.Context, _, _ shared.ID, targets []string) (string, error) {
	f.got = targets
	return "abc", f.err
}

// A run records the snapshot of its targets; a failed snapshot is a
// warning on the run, never a refusal (RFC-065 §9).
func TestRecordScopeSnapshot(t *testing.T) {
	ctx := context.Background()
	rec := &fakeSnapshots{}
	svc := &Service{scopeSnapshots: rec, logger: logger.NewNop()}
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), Context: map[string]any{}}
	svc.recordScopeSnapshot(ctx, run, []string{"a.example"})
	if run.Context[runContextScopeSnapshot] != "abc" || len(rec.got) != 1 {
		t.Fatalf("snapshot not recorded: %v %v", run.Context, rec.got)
	}

	rec.err = errors.New("db down")
	run = &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), Context: map[string]any{}}
	svc.recordScopeSnapshot(ctx, run, []string{"a.example"})
	if _, ok := run.Context[runContextScopeSnapshot]; ok {
		t.Fatal("a failed snapshot must not name a hash")
	}
	if w, _ := run.Context["dispatch_warnings"].([]string); len(w) != 1 {
		t.Fatalf("a failed snapshot must be a run warning: %v", run.Context)
	}

	// Not wired: nothing happens.
	(&Service{logger: logger.NewNop()}).recordScopeSnapshot(ctx, run, nil)
}
