package command

import (
	"context"
	"fmt"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// deliverStored builds, for a command a sensor holds, the payload that its
// first delivery (Poll, Claim, shared claim) handed out: the tenant's HTTP
// policy, the program rules and window rate cap, the sensor's tool settings
// and the template signatures. The transition claim (the claim by id, and a
// repeat of a claim the sensor already holds) hands out and signs this
// payload and never the stored one, which lacks all of it: a job must not
// run without its program rules or HTTP policy because it was delivered a
// second time. The decisions are read-only: nothing is reserved or deferred
// here. A rule or setting that cannot be read or applied is an error (fail
// closed).
func (s *Service) deliverStored(ctx context.Context, sensorID string, cmd *commanddom.Command) (*commanddom.Command, error) {
	sid, err := shared.IDFromString(sensorID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid sensor id", shared.ErrValidation)
	}
	rules, err := s.programHoldOne(ctx, sid, cmd)
	if err != nil {
		return nil, err
	}
	layer, err := s.settingsHoldOne(ctx, sid, cmd)
	if err != nil {
		return nil, err
	}
	rate, err := s.windowRateOne(ctx, cmd)
	if err != nil {
		return nil, err
	}
	rm := map[shared.ID]*bp.JobRules{}
	if rules != nil {
		rm[cmd.ID] = rules
	}
	if rate > 0 {
		rm = withWindowRates(rm, map[shared.ID]int{cmd.ID: rate})
	}
	out, err := s.deliver(ctx, sensorID, []*commanddom.Command{cmd}, rm, map[shared.ID]settingsLayers{cmd.ID: layer})
	if err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, ErrScopeRecheckUnavailable
	}
	return out[0], nil
}

// windowRateOne is the rate cap the job's scan windows give it now, without
// reserving a concurrency slot or deferring the job (the sensor already
// holds it). A closed window or unreadable windows refuse the repeat.
func (s *Service) windowRateOne(ctx context.Context, cmd *commanddom.Command) (int, error) {
	if s.windows == nil || !probingCommand(cmd) {
		return 0, nil
	}
	snap, err := s.windows.Load(ctx, cmd.TenantID, windowTargets(cmd), s.clock())
	if err != nil {
		s.logger.Warn("scan windows could not be read; withholding the job", "command_id", cmd.ID.String(), "error", err)
		return 0, ErrScopeRecheckUnavailable
	}
	if snap.Empty() {
		return 0, nil
	}
	var all []swdom.Source
	for _, t := range windowTargets(cmd) {
		all = append(all, snap.SourcesFor(t, cmd.ScanZoneID)...)
	}
	d := swdom.Decide(all, commandTier(cmd), snap.Now())
	if !d.Open {
		return 0, ErrOutsideWindow
	}
	return d.RateLimitRPS, nil
}
