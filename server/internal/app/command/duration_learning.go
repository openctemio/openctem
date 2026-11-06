package command

// The data loop of research/122: each completed scan command is one sample
// of its tool's time per target in its tenant. Only completions count: a
// failed, canceled or re-queued attempt must not teach "slow is normal".

import (
	"context"
	"encoding/json"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
)

// WithDurationStats makes every completed scan command feed the learned
// per-target durations. Without it nothing is learned.
func WithDurationStats(store toolbudget.StatsStore) Option {
	return func(s *Service) { s.durations = store }
}

// learnDuration records cmd's time per target. Best effort: a failure is
// logged and never fails the completion.
func (s *Service) learnDuration(ctx context.Context, cmd *commanddom.Command) {
	if s.durations == nil || cmd == nil || cmd.Type != commanddom.CommandTypeScan ||
		cmd.StartedAt == nil || cmd.CompletedAt == nil {
		return
	}
	var p struct {
		Scanner string          `json:"scanner"`
		Target  string          `json:"target"`
		Targets json.RawMessage `json:"targets"`
	}
	if json.Unmarshal(cmd.Payload, &p) != nil || p.Scanner == "" {
		return
	}
	n := 0
	var list []json.RawMessage
	if json.Unmarshal(p.Targets, &list) == nil {
		n = len(list)
	}
	if n == 0 && p.Target != "" {
		n = 1
	}
	b := toolbudget.For(p.Scanner)
	sample, ok := b.Sample(cmd.CompletedAt.Sub(*cmd.StartedAt), n)
	if !ok {
		return
	}
	if err := s.durations.ObservePerTarget(ctx, cmd.TenantID, p.Scanner, sample, b.Floor, b.Ceiling); err != nil {
		s.logger.Warn("tool duration not learned", "command_id", cmd.ID.String(), "error", err)
	}
}
