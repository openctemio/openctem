package automation

import (
	"context"
	"testing"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func mkFinding(t *testing.T, tenant shared.ID, sev vulnerability.Severity) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSAST, "semgrep", sev, "f")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// 40 new critical findings and one "critical" automation give 40 runs, one
// per finding, each with the finding as subject and its own idempotency key;
// a finding outside the trigger filter and another tenant's finding start
// nothing.
func TestDispatchFindingsCreated_OneRunPerFinding(t *testing.T) {
	tenant := shared.NewID()
	wf := newWorkflow(tenant, automationdom.TriggerTypeFindingCreated, map[string]any{"severity_filter": []any{"critical"}})
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*automationdom.Workflow{tenant: {wf}}}
	rec := &triggerRecorder{}
	d := newTestDispatcher(repo, rec)

	var batch []*vulnerability.Finding
	for range 40 {
		batch = append(batch, mkFinding(t, tenant, vulnerability.SeverityCritical))
	}
	batch = append(batch, mkFinding(t, tenant, vulnerability.SeverityLow), mkFinding(t, shared.NewID(), vulnerability.SeverityCritical))

	if n := d.dispatchFindingsCreated(context.Background(), tenant, batch); n != 40 {
		t.Fatalf("runs started = %d, want 40", n)
	}
	keys := map[string]bool{}
	for i, c := range rec.calls {
		f := batch[i]
		if c.SubjectID == nil || *c.SubjectID != f.ID() {
			t.Fatalf("run %d subject = %v, want finding %s", i, c.SubjectID, f.ID())
		}
		if c.IdempotencyKey != "finding_created:"+f.ID().String() || keys[c.IdempotencyKey] {
			t.Fatalf("run %d key = %q (duplicate=%v)", i, c.IdempotencyKey, keys[c.IdempotencyKey])
		}
		keys[c.IdempotencyKey] = true
		if got := c.TriggerData["finding"].(map[string]any)["id"]; got != f.ID().String() {
			t.Fatalf("run %d trigger data names %v, want its own finding", i, got)
		}
	}
}

// A finding delivered twice starts the automation once; a quota refusal stops
// the batch for that automation (it would refuse the rest too).
func TestDispatchFindingsCreated_DuplicateAndThrottled(t *testing.T) {
	tenant := shared.NewID()
	wf := newWorkflow(tenant, automationdom.TriggerTypeFindingCreated, nil)
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*automationdom.Workflow{tenant: {wf}}}

	seen := map[string]bool{}
	calls := 0
	d := &WorkflowEventDispatcher{workflowRepo: repo, logger: newTestDispatcher(repo, &triggerRecorder{}).logger,
		triggerFn: func(_ context.Context, in TriggerWorkflowInput) error {
			calls++
			if seen[in.IdempotencyKey] {
				return automationdom.ErrRunDuplicate
			}
			seen[in.IdempotencyKey] = true
			if len(seen) > 3 {
				return automationdom.NewRunThrottledError("over quota")
			}
			return nil
		}}

	f := mkFinding(t, tenant, vulnerability.SeverityHigh)
	if n := d.dispatchFindingsCreated(context.Background(), tenant, []*vulnerability.Finding{f, f}); n != 1 {
		t.Fatalf("a finding delivered twice started %d runs, want 1", n)
	}

	calls = 0
	var batch []*vulnerability.Finding
	for range 10 {
		batch = append(batch, mkFinding(t, tenant, vulnerability.SeverityHigh))
	}
	if n := d.dispatchFindingsCreated(context.Background(), tenant, batch); n != 2 {
		t.Fatalf("runs started = %d, want 2 before the quota", n)
	}
	if calls != 3 {
		t.Fatalf("asked %d times, want 3 (stop at the first throttled refusal)", calls)
	}
}
