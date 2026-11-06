package unit

// Simulate never reaches the network or changes data (RFC-125 D5): a
// simulate run of an automation whose live handlers call an outside server
// sends that server nothing, records what it would send (deliveries in mode
// simulate, status simulated) and a per-step trace. The same automation in
// live sends, which proves the fake server would have seen a request.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// egressHandler is a live handler that posts to an outside server.
type egressHandler struct{ url string }

func (h egressHandler) Execute(ctx context.Context, _ *automationsvc.ActionInput) (map[string]any, error) {
	return h.post(ctx)
}

func (h egressHandler) Send(ctx context.Context, _ *automationsvc.NotificationInput) (map[string]any, error) {
	return h.post(ctx)
}

func (h egressHandler) post(ctx context.Context) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	return map[string]any{"sent": true, "ticket_key": "EX-1"}, nil
}

type memDeliveries struct {
	mu   sync.Mutex
	list []*automation.Delivery
}

func (m *memDeliveries) Record(_ context.Context, d *automation.Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.list = append(m.list, d)
	return nil
}

func (m *memDeliveries) ListByRun(context.Context, shared.ID, shared.ID) ([]*automation.Delivery, error) {
	return m.list, nil
}

type memFindings map[shared.ID]*vulnerability.Finding

func (m memFindings) GetByID(_ context.Context, _, id shared.ID) (*vulnerability.Finding, error) {
	if f, ok := m[id]; ok {
		return f, nil
	}
	return nil, shared.ErrNotFound
}

func simulateWorkflow(tenantID shared.ID) *automation.Workflow {
	wf, _ := automation.NewWorkflow(tenantID, "egress", "")
	trig, _ := automation.NewNode(wf.ID, "t", automation.NodeTypeTrigger, "t")
	_ = trig.SetTriggerConfig(automation.TriggerTypeFindingCreated, nil)
	ticket, _ := automation.NewNode(wf.ID, "ticket", automation.NodeTypeAction, "ticket")
	_ = ticket.SetActionConfig(automation.ActionTypeCreateTicket, map[string]any{"project_key": "EX"})
	notify, _ := automation.NewNode(wf.ID, "slack", automation.NodeTypeNotification, "slack")
	_ = notify.SetNotificationConfig(automation.NotificationTypeSlack, map[string]any{
		"integration_id": shared.NewID().String(), "title": "New finding", "body": "secret body text",
		"headers": map[string]any{"Authorization": "Bearer x"},
	})
	for _, n := range []*automation.Node{trig, ticket, notify} {
		wf.AddNode(n)
	}
	e1, _ := automation.NewEdge(wf.ID, "t", "ticket")
	e2, _ := automation.NewEdge(wf.ID, "t", "slack")
	wf.AddEdge(e1)
	wf.AddEdge(e2)
	return wf
}

func TestWorkflowSimulate_NoEgressAndRecordsWouldSend(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tenantID := shared.NewID()
	f, err := vulnerability.NewFinding(tenantID, shared.NewID(), vulnerability.FindingSourceManual, "manual", vulnerability.SeverityHigh, "SQL injection")
	if err != nil {
		t.Fatal(err)
	}
	f.SetTitle("SQL injection")
	run := func(mode automation.Mode) (*memDeliveries, *wfExecMockNodeRunRepo, *automation.Run) {
		wfRepo, runRepo, nrRepo := newWfExecMockWorkflowRepo(), newWfExecMockRunRepo(), newWfExecMockNodeRunRepo()
		deliveries := &memDeliveries{}
		egress := egressHandler{url: srv.URL}
		ex := automationsvc.NewWorkflowExecutor(wfRepo, runRepo, nrRepo, logger.NewNop(),
			automationsvc.WithExecutorStepAuthorizer(wfExecAllowAll{}),
			automationsvc.WithExecutorNotificationHandler(egress),
			automationsvc.WithExecutorDeliveries(deliveries),
			automationsvc.WithExecutorEvaluator(automationsvc.NewSimulateEvaluator(memFindings{f.ID(): f})))
		ex.RegisterActionHandler(automation.ActionTypeCreateTicket, egress)
		wf := simulateWorkflow(tenantID)
		_ = wfRepo.Create(context.Background(), wf)
		r := wfExecBuildRun(wf, tenantID)
		r.Mode = mode
		r.TriggerData = map[string]any{"finding": map[string]any{"id": f.ID().String()}}
		_ = runRepo.Create(context.Background(), r)
		for _, nr := range r.NodeRuns {
			_ = nrRepo.Create(context.Background(), nr)
		}
		if err := ex.ExecuteWithTenant(context.Background(), r.ID, tenantID); err != nil {
			t.Fatalf("%s run: %v", mode, err)
		}
		return deliveries, nrRepo, r
	}

	deliveries, nrRepo, r := run(automation.ModeSimulate)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the outside server received %d request(s) from a simulate run", n)
	}
	if len(deliveries.list) != 2 {
		t.Fatalf("simulate deliveries = %d, want 2 (ticket and slack)", len(deliveries.list))
	}
	for _, d := range deliveries.list {
		if d.Mode != automation.ModeSimulate || d.Status != automation.DeliverySimulated || d.Attempts != 0 {
			t.Errorf("delivery %s = mode %s status %s attempts %d, want simulate/simulated/0", d.NodeKey, d.Mode, d.Status, d.Attempts)
		}
		if d.RunID != r.ID || d.IdempotencyKey != r.ID.String()+":"+d.NodeKey {
			t.Errorf("delivery %s not bound to its run", d.NodeKey)
		}
		stored := automation.DeliveryPayload(d.Payload)
		if _, ok := stored["body"]; ok {
			t.Errorf("delivery %s keeps the body", d.NodeKey)
		}
		if _, ok := stored["headers"]; ok {
			t.Errorf("delivery %s keeps headers", d.NodeKey)
		}
		if d.NodeKey == "ticket" && (d.Channel != "jira" || d.Target != "EX" || stored["title"] != "SQL injection") {
			t.Errorf("ticket delivery = %+v", d)
		}
		if d.NodeKey == "slack" && (d.Channel != "slack" || stored["title"] != "New finding" || stored["body_chars"] != len("secret body text")) {
			t.Errorf("slack delivery = %+v", stored)
		}
	}
	for _, nr := range nrRepo.nodeRuns {
		if nr.NodeKey != "t" && (nr.InCount != 1 || nr.OutCount != 1 || nr.Status != automation.NodeRunStatusCompleted) {
			t.Errorf("step %s trace in=%d out=%d status=%s", nr.NodeKey, nr.InCount, nr.OutCount, nr.Status)
		}
	}

	deliveries, _, _ = run(automation.ModeLive)
	if n := hits.Load(); n != 2 {
		t.Fatalf("live run: the outside server received %d request(s), want 2", n)
	}
	for _, d := range deliveries.list {
		if d.Mode != automation.ModeLive || d.Status != automation.DeliverySent {
			t.Errorf("live delivery %s = %s/%s", d.NodeKey, d.Mode, d.Status)
		}
	}
}

// A step that would change nothing says why.
func TestWorkflowSimulate_NoChangeIsSkippedWithReason(t *testing.T) {
	tenantID := shared.NewID()
	f, _ := vulnerability.NewFinding(tenantID, shared.NewID(), vulnerability.FindingSourceManual, "manual", vulnerability.SeverityHigh, "x")
	f.SetTags([]string{"auto"})
	ev := automationsvc.NewSimulateEvaluator(memFindings{f.ID(): f})
	eff, err := ev.Evaluate(context.Background(), &automationsvc.EvalInput{
		TenantID: tenantID,
		Config: automation.NodeConfig{ActionType: automation.ActionTypeAddTags,
			ActionConfig: map[string]any{"tags": []any{"auto"}}},
		TriggerData: map[string]any{"finding": map[string]any{"id": f.ID().String()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if eff.Trace.In != 1 || eff.Trace.Out != 0 || eff.Trace.Skipped[automation.SkipNoChange] != 1 || eff.Changes != 0 {
		t.Fatalf("effect = %+v", eff)
	}
	eff, _ = ev.Evaluate(context.Background(), &automationsvc.EvalInput{TenantID: tenantID,
		Config: automation.NodeConfig{ActionType: automation.ActionTypeAddTags, ActionConfig: map[string]any{"tags": []any{"x"}}}})
	if eff.Trace.Skipped[automation.SkipNoSubject] != 1 {
		t.Fatalf("no subject effect = %+v", eff)
	}
}

// The evaluator a simulate run uses holds no outbound client and no service
// that writes: only read-only interfaces. Adding a field of another kind
// fails this test.
func TestWorkflowSimulate_EvaluatorHasNoEgressDependency(t *testing.T) {
	allowed := map[reflect.Type]bool{
		reflect.TypeOf((*automationsvc.FindingReader)(nil)).Elem(): true,
	}
	typ := reflect.TypeOf(automationsvc.SimulateEvaluator{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !allowed[f.Type] {
			t.Errorf("SimulateEvaluator.%s has type %s: a simulate run may only hold read-only dependencies", f.Name, f.Type)
		}
	}
}
