package controller

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// captureController wires an AuditChainVerifyController whose logger writes JSON
// into buf, so a test can assert which breaks paged (the "audit_chain_break"
// alert keyword) versus which were logged as already-known.
func captureController(verifier chainVerifier, tenants *tenantListerMock, buf *bytes.Buffer) *AuditChainVerifyController {
	log := &logger.Logger{Logger: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	return &AuditChainVerifyController{
		audit:         verifier,
		tenants:       tenants,
		config:        &AuditChainVerifyControllerConfig{PerTenantLimit: 1000},
		logger:        log,
		alertedBreaks: make(map[string]struct{}),
	}
}

// A break that persists across runs must page exactly once, not every interval.
func TestAuditChainVerify_PersistingBreakAlertsOnce(t *testing.T) {
	id := shared.NewID()
	tenants := &tenantListerMock{ids: []shared.ID{id}}
	verifier := &chainVerifierMock{
		results: map[string]*audit.ChainVerifyResult{
			id.String(): {
				TenantID: id.String(),
				OK:       false,
				Breaks:   []audit.ChainBreak{{AuditLogID: "log-1", ChainPosition: 7, Reason: "hash_mismatch"}},
			},
		},
	}

	var buf bytes.Buffer
	c := captureController(verifier, tenants, &buf)

	// Run 1: first sighting → pages.
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if strings.Count(buf.String(), "audit_chain_break") != 1 {
		t.Fatalf("first sighting must page exactly once; log:\n%s", buf.String())
	}

	// Run 2: same break, already alerted → must NOT re-page.
	buf.Reset()
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	run2 := buf.String()
	if strings.Contains(run2, "audit_chain_break") {
		t.Errorf("a persisting, already-alerted break must not re-page; log:\n%s", run2)
	}
	if !strings.Contains(run2, "still present") {
		t.Errorf("persisting break should still be logged (as still-present); log:\n%s", run2)
	}
}

// A genuinely new break appearing later must page even while another break is
// already known — the dedup must never suppress a fresh tamper signal.
func TestAuditChainVerify_NewBreakStillPagesWhenAnotherKnown(t *testing.T) {
	id := shared.NewID()
	tenants := &tenantListerMock{ids: []shared.ID{id}}
	res := &audit.ChainVerifyResult{
		TenantID: id.String(),
		OK:       false,
		Breaks:   []audit.ChainBreak{{AuditLogID: "log-1", ChainPosition: 7, Reason: "hash_mismatch"}},
	}
	verifier := &chainVerifierMock{results: map[string]*audit.ChainVerifyResult{id.String(): res}}

	var buf bytes.Buffer
	c := captureController(verifier, tenants, &buf)

	if _, err := c.Reconcile(context.Background()); err != nil { // run 1: log-1 pages
		t.Fatalf("run 1: %v", err)
	}

	// A second, distinct break appears.
	res.Breaks = append(res.Breaks, audit.ChainBreak{AuditLogID: "log-2", ChainPosition: 9, Reason: "hash_mismatch"})
	buf.Reset()
	if _, err := c.Reconcile(context.Background()); err != nil { // run 2: log-1 known, log-2 new
		t.Fatalf("run 2: %v", err)
	}

	run2 := buf.String()
	if strings.Count(run2, "audit_chain_break") != 1 {
		t.Fatalf("exactly the one NEW break should page in run 2; log:\n%s", run2)
	}
	if !strings.Contains(run2, "log-2") {
		t.Errorf("the new break (log-2) must be the one that pages; log:\n%s", run2)
	}
}
