package controller

import (
	"context"
	"time"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
)

// ScopeAttestationReconciler runs the t2 attestation job (*scope.Service).
type ScopeAttestationReconciler interface {
	ReconcileAttestations(ctx context.Context, now time.Time) (scopeapp.AttestationResult, error)
}

// ScopeAttestationController asks for the attestations of long intrusive
// (t2) scope entries that fell due and downgrades to t1 the entries whose
// request went unanswered for 14 days (RFC-054 §12.5). Idempotent: every
// write is conditional, so a rerun or a second replica changes nothing.
type ScopeAttestationController struct {
	svc      ScopeAttestationReconciler
	interval time.Duration
}

// NewScopeAttestationController creates the controller. interval 0 = 1 h.
func NewScopeAttestationController(svc ScopeAttestationReconciler, interval time.Duration) *ScopeAttestationController {
	if interval <= 0 {
		interval = time.Hour
	}
	return &ScopeAttestationController{svc: svc, interval: interval}
}

// Name implements Controller.
func (c *ScopeAttestationController) Name() string { return "scope-attestation" }

// Interval implements Controller.
func (c *ScopeAttestationController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller: requests opened plus entries downgraded.
func (c *ScopeAttestationController) Reconcile(ctx context.Context) (int, error) {
	if c.svc == nil {
		return 0, nil
	}
	res, err := c.svc.ReconcileAttestations(ctx, time.Now().UTC())
	return res.Requested + res.Downgraded, err
}
