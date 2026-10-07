package scanrun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A zone-routed scan (RFC-023) runs one command per batch under one step run.
// The step must settle exactly once, after the last batch.

type gateRepo struct {
	command.Repository // unused methods panic
	state              command.StepBatch
	stateErr           error
	claimed            bool
	claims             int
}

func (g *gateRepo) StepBatchState(context.Context, shared.ID, shared.ID) (command.StepBatch, error) {
	return g.state, g.stateErr
}

func (g *gateRepo) ClaimStepFinalization(context.Context, shared.ID) (bool, error) {
	g.claims++
	return g.claimed, nil
}

// plainRepo is a command repository without the batch gate.
type plainRepo struct{ command.Repository }

func TestCheckStepBatches(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID()}
	step := &scanrun.StepRun{ID: shared.NewID(), StepKey: "scan"}

	cases := []struct {
		name        string
		repo        command.Repository
		step        *scanrun.StepRun
		wantBatched bool
		wantWait    bool
		wantClaims  int
	}{
		{"single command keeps the old behavior", &gateRepo{state: command.StepBatch{Total: 1}}, step, false, false, 0},
		{"no step run", &gateRepo{state: command.StepBatch{Total: 3}}, nil, false, false, 0},
		{"repository without the gate", &plainRepo{}, step, false, false, 0},
		{"state error falls back", &gateRepo{stateErr: errors.New("db")}, step, false, false, 0},
		{"another batch still active", &gateRepo{state: command.StepBatch{Total: 3, Active: 1}, claimed: true}, step, true, true, 0},
		{"last batch claims the outcome", &gateRepo{state: command.StepBatch{Total: 3}, claimed: true}, step, true, false, 1},
		{"a concurrent last batch already claimed it", &gateRepo{state: command.StepBatch{Total: 3}, claimed: false}, step, true, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{commandRepo: tc.repo, logger: logger.NewNop()}
			got := s.checkStepBatches(context.Background(), run, tc.step)
			if got.batched != tc.wantBatched || got.wait != tc.wantWait {
				t.Errorf("batched=%v wait=%v, want %v %v", got.batched, got.wait, tc.wantBatched, tc.wantWait)
			}
			if g, ok := tc.repo.(*gateRepo); ok && g.claims != tc.wantClaims {
				t.Errorf("claims = %d, want %d", g.claims, tc.wantClaims)
			}
		})
	}
}

func TestStepBatchesSummary(t *testing.T) {
	b := stepBatches{total: 4, failed: 1, firstError: "scanner not found: nuclei"}
	if got := b.summary(); got != "1 of 4 scan batches failed: scanner not found: nuclei" {
		t.Errorf("summary = %q", got)
	}
}
