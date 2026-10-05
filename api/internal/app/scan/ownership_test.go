package scan

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A refusal names the targets with one generic reason: it never says which
// rule (rejected, needs review, unattributed) refused it.
func TestRefuseUnownedTargets(t *testing.T) {
	gate := &stubGate{blockedTyped: map[string]attribution.State{
		"www.rejected.com": attribution.StateRejected,
		"dev.review.com":   attribution.StateNeedsReview,
		"manual.net":       attribution.StateUnattributed,
	}}
	svc := &Service{attributionGate: gate, logger: logger.NewNop()}
	tenant := shared.NewID()

	err := svc.refuseUnownedTargets(context.Background(), tenant, "quick_scan",
		[]string{"ok.example.com", "www.rejected.com", "dev.review.com", "manual.net"}, false)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "TARGET_OUT_OF_SCOPE" || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want TARGET_OUT_OF_SCOPE", err)
	}
	msg := err.Error()
	for _, name := range []string{"www.rejected.com", "dev.review.com", "manual.net"} {
		if !strings.Contains(msg, name) {
			t.Fatalf("refusal does not name %s: %s", name, msg)
		}
	}
	for _, leak := range []string{"rejected)", "needs_review", "unattributed", "ok.example.com"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("refusal says %q: %s", leak, msg)
		}
	}
	if err := svc.refuseUnownedTargets(context.Background(), tenant, "quick_scan", []string{"ok.example.com"}, false); err != nil {
		t.Fatalf("allowed target refused: %v", err)
	}
	svc.attributionGate = &stubGate{err: errors.New("db down")}
	if err := svc.refuseUnownedTargets(context.Background(), tenant, "quick_scan", []string{"ok.example.com"}, false); err == nil {
		t.Fatal("a failed ownership check must refuse")
	}
}

// 22c B1: a scan run skips a direct target the tenant typed when it names a
// rejected (or otherwise unauthorized) asset; group members are decided by
// asset id. A run left with nothing is refused.
func TestResolveScanTargets_SkipsUnownedDirectTargets(t *testing.T) {
	gate := &stubGate{blockedTyped: map[string]attribution.State{"www.rejected.com": attribution.StateRejected}}
	svc := &Service{attributionGate: gate, logger: logger.NewNop()}
	sc := testScan("nuclei", "www.rejected.com", "ok.example.com")
	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Targets, []string{"ok.example.com"}) || got.Unconfirmed != 1 {
		t.Fatalf("targets=%v unconfirmed=%d", got.Targets, got.Unconfirmed)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "ownership is not confirmed") {
		t.Fatalf("warnings = %v", got.Warnings)
	}

	only := testScan("nuclei", "www.rejected.com")
	r, err := svc.resolveScanTargets(context.Background(), only)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordResolvedTargets(only, r, map[string]any{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("all-refused run not refused: %v", err)
	}
	svc.attributionGate = &stubGate{err: errors.New("db down")}
	if _, err := svc.resolveScanTargets(context.Background(), only); err == nil {
		t.Fatal("a failed ownership check must stop the run")
	}
}

// The dispatch gate (pipelines, coverage, validation, retests, simulations,
// connector scans) refuses typed targets the ownership gate refuses.
func TestResolveDispatchTargets_TypedOwnership(t *testing.T) {
	gate := &stubGate{blockedTyped: map[string]attribution.State{"www.rejected.com": attribution.StateRejected}}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: gate, logger: logger.NewNop()}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: shared.NewID(), Targets: []string{"www.rejected.com", "ok.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Allowed, []string{"ok.example.com"}) {
		t.Fatalf("allowed = %v", got.Allowed)
	}
	if len(got.Refused) != 1 || got.Refused[0].Target != "www.rejected.com" || got.Refused[0].Reason != ReasonOwnershipNotConfirmed {
		t.Fatalf("refused = %+v", got.Refused)
	}
}

// POST /commands names its targets explicitly: an unowned one refuses the
// command as a whole.
func TestGateCommandPayload_Ownership(t *testing.T) {
	gate := &stubGate{blockedTyped: map[string]attribution.State{"dev.review.com": attribution.StateNeedsReview}}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: gate, logger: logger.NewNop()}
	payload, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{"ok.example.com", "dev.review.com"}})
	if _, err := svc.GateCommandPayload(context.Background(), shared.NewID(), nil, payload); !errors.Is(err, ErrCommandTargetRefused) {
		t.Fatalf("err = %v, want ErrCommandTargetRefused", err)
	}
	ok, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{"ok.example.com"}})
	if _, err := svc.GateCommandPayload(context.Background(), shared.NewID(), nil, ok); err != nil {
		t.Fatalf("allowed command refused: %v", err)
	}
}

type recordingAudit struct {
	events []AuditEvent
	ctxs   []AuditContext
}

func (r *recordingAudit) LogEvent(_ context.Context, actx AuditContext, e AuditEvent) error {
	r.events = append(r.events, e)
	r.ctxs = append(r.ctxs, actx)
	return nil
}

// research/22 §4.0: a refused request is audited in the caller's tenant,
// with the refusing state per target (the caller's error stays generic).
// An allowed request and a failed check write nothing.
func TestRefuseUnownedTargets_Audited(t *testing.T) {
	gate := &stubGate{blockedTyped: map[string]attribution.State{
		"www.rejected.com": attribution.StateRejected,
		"dev.review.com":   attribution.StateNeedsReview,
	}}
	rec := &recordingAudit{}
	svc := &Service{attributionGate: gate, logger: logger.NewNop(), auditService: rec}
	tenant := shared.NewID()
	ctx := WithAuditActor(context.Background(), "actor-1")

	if err := svc.refuseUnownedTargets(ctx, tenant, "quick_scan", []string{"ok.example.com"}, false); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 0 {
		t.Fatalf("allowed request audited: %+v", rec.events)
	}

	if err := svc.refuseUnownedTargets(ctx, tenant, "quick_scan",
		[]string{"ok.example.com", "www.rejected.com", "dev.review.com"}, false); err == nil {
		t.Fatal("refused targets passed")
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	e := rec.events[0]
	if e.Action != audit.ActionScanTargetRefused || e.Success || e.ResourceType != audit.ResourceTypeScan {
		t.Fatalf("event = %+v", e)
	}
	if rec.ctxs[0].TenantID != tenant.String() || rec.ctxs[0].ActorID != "actor-1" {
		t.Fatalf("audit context = %+v", rec.ctxs[0])
	}
	if e.Metadata["path"] != "quick_scan" || e.Metadata["refused_count"] != 2 {
		t.Fatalf("metadata = %+v", e.Metadata)
	}
	listed, _ := e.Metadata["refused"].([]map[string]string)
	want := []map[string]string{
		{"target": "dev.review.com", "attribution": "needs_review"},
		{"target": "www.rejected.com", "attribution": "rejected"},
	}
	if !reflect.DeepEqual(listed, want) {
		t.Fatalf("refused = %v, want %v", listed, want)
	}
	if !audit.ActionScanTargetRefused.IsValid() || audit.SeverityForAction(audit.ActionScanTargetRefused) != audit.SeverityMedium {
		t.Fatal("scan.target_refused must be a valid, medium-severity action")
	}

	svc.attributionGate = &stubGate{err: errors.New("db down")}
	_ = svc.refuseUnownedTargets(ctx, tenant, "quick_scan", []string{"ok.example.com"}, false)
	if len(rec.events) != 1 {
		t.Fatal("a failed check is not a refusal by ownership and is not audited as one")
	}
}

// The audit entry lists at most maxAuditedRefusals targets; the count is exact.
func TestRefuseUnownedTargets_AuditBounded(t *testing.T) {
	blocked := map[string]attribution.State{}
	targets := make([]string, 0, 120)
	for i := range 120 {
		name := "h" + strings.Repeat("x", i%7) + "-" + string(rune('a'+i%26)) + shared.NewID().String()[:8] + ".example.com"
		blocked[name] = attribution.StateUnattributed
		targets = append(targets, name)
	}
	rec := &recordingAudit{}
	svc := &Service{attributionGate: &stubGate{blockedTyped: blocked}, logger: logger.NewNop(), auditService: rec}
	_ = svc.refuseUnownedTargets(context.Background(), shared.NewID(), "scan_create", targets, false)
	e := rec.events[0]
	if e.Metadata["refused_count"] != 120 {
		t.Fatalf("count = %v", e.Metadata["refused_count"])
	}
	if listed, _ := e.Metadata["refused"].([]map[string]string); len(listed) != maxAuditedRefusals {
		t.Fatalf("listed = %d, want %d", len(listed), maxAuditedRefusals)
	}
}
