package main

import (
	"context"
	"sync/atomic"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/validation"
)

// lateTargetGate is the active-probe gate handed to the validate-command
// dispatchers, which are wired before the scan service exists. Until set is
// called it refuses every probe (fail closed), so a wiring mistake shows up
// as refused probes, never as unchecked ones.
type lateTargetGate struct {
	gate atomic.Pointer[scanapp.Service]
}

func (g *lateTargetGate) set(s *scanapp.Service) { g.gate.Store(s) }

// ResolveDispatchTargets implements validation.TargetGate.
func (g *lateTargetGate) ResolveDispatchTargets(ctx context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	s := g.gate.Load()
	if s == nil {
		return nil, validation.ErrProbeGateUnavailable
	}
	return s.ResolveDispatchTargets(ctx, in)
}
