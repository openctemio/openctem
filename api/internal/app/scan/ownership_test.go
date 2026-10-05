package scan

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
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
		[]string{"ok.example.com", "www.rejected.com", "dev.review.com", "manual.net"})
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
	if err := svc.refuseUnownedTargets(context.Background(), tenant, "quick_scan", []string{"ok.example.com"}); err != nil {
		t.Fatalf("allowed target refused: %v", err)
	}
	svc.attributionGate = &stubGate{err: errors.New("db down")}
	if err := svc.refuseUnownedTargets(context.Background(), tenant, "quick_scan", []string{"ok.example.com"}); err == nil {
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
