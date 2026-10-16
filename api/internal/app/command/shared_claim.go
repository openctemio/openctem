package command

// The shared claim path: a shared sensor (scope instance, no tenant) takes
// shared jobs (is_platform_job) of every organization. Design:
// docs/rfcs/RFC-100-shared-sensors.md §8 and §10.

import (
	"context"
	"fmt"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SharedClaimer is the repository side of the shared claim path
// (CommandRepository).
type SharedClaimer interface {
	GetSharedPendingForSensor(ctx context.Context, sensorID shared.ID, capabilities []string, limit int) ([]*commanddom.Command, error)
	ClaimManyShared(ctx context.Context, sensorID shared.ID, capabilities []string, ids []shared.ID, limits map[shared.ID]int) ([]shared.ID, error)
	CountHeldSharedScans(ctx context.Context, sensorID shared.ID) (int, error)
	GetHeldSharedJob(ctx context.Context, sensorID, commandID shared.ID) (*commanddom.Command, error)
}

// SharedLimitSource reads an organization's limit of a key through the
// entitlement service, by key and never by plan (*entitlement.Service).
// plan.Unlimited: no limit.
type SharedLimitSource interface {
	Limit(ctx context.Context, tenantID shared.ID, key plan.Key) (int, error)
}

// SharedGrantReader reads a shared sensor's grant (it has no tenant).
type SharedGrantReader interface {
	GetShared(ctx context.Context, sensorID shared.ID) (*sensordom.Grant, error)
}

// WithSharedLimits wires the per-organization limit of shared jobs in
// flight (platform_scans_concurrent). Without it the shared claim hands out
// nothing (fail closed).
func WithSharedLimits(l SharedLimitSource) Option {
	return func(s *Service) { s.sharedLimits = l }
}

// ErrNotSharedSensor: the shared claim path was asked for by a sensor that
// is not a shared one.
var ErrNotSharedSensor = fmt.Errorf("%w: not a shared sensor", shared.ErrForbidden)

// SharedClaimInput is a shared sensor's claim-N poll.
type SharedClaimInput struct {
	// Sensor is the authenticated shared sensor, as stored. Its identity
	// decides everything; nothing in the request does.
	Sensor *sensordom.Sensor
	// Limit caps the commands returned (1..100, default 10).
	Limit int
	// ReportedFree, when set, is the free slots the sensor last reported.
	ReportedFree *int
}

// ClaimShared is the shared sensor's claim-N poll. Candidates come in the
// shared dispatch order (priority class with aging, the organization with
// the fewest shared jobs in flight first). Each organization's candidates
// pass the same gates as an organization sensor's claim, in that
// organization (the sensor's grant and local policy, scope re-check, scan
// windows, program rules, tool settings); scans are capped at the sensor's
// free slots; an organization gets no more shared jobs in flight than its
// platform_scans_concurrent limit (an organization at its limit is skipped
// and its jobs wait). The claim sets the sensor as the holder with a lease,
// and every command handed out is signed for this sensor in the command's
// organization.
func (s *Service) ClaimShared(ctx context.Context, in SharedClaimInput) ([]*commanddom.Command, error) {
	if in.Sensor == nil || !in.Sensor.IsShared() || in.Sensor.TenantID != nil {
		return nil, ErrNotSharedSensor
	}
	claimer, ok := s.repo.(SharedClaimer)
	if !ok || s.sharedLimits == nil {
		return nil, nil
	}
	defer observeClaimDuration(claimModeShared, time.Now())
	sensorID := in.Sensor.ID
	caps := in.Sensor.EffectiveCapabilities()

	held, err := claimer.CountHeldSharedScans(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	slots := freeScanSlots(in.Sensor.EffectiveMaxConcurrentJobs(), held, in.ReportedFree)
	limit := in.Limit
	if limit <= 0 {
		limit = 10
	}
	limit = min(limit, 100)
	cands, err := claimer.GetSharedPendingForSensor(ctx, sensorID, caps, candidateLimit(limit))
	if err != nil {
		return nil, err
	}
	if len(cands) == 0 {
		return nil, nil
	}

	subj := s.sharedSubject(ctx, in.Sensor)
	order, groups := byTenant(cands)
	rules := map[shared.ID]*bp.JobRules{}
	layers := map[shared.ID]settingsLayers{}
	kept := map[shared.ID]bool{}
	for _, tenantID := range order {
		group := groups[tenantID]
		group = s.gateWith(ctx, tenantID, subj, group).accepted(group)
		group = s.recheckScope(ctx, tenantID, &sensorID, group)
		group, rates := s.windowHold(ctx, tenantID, group)
		group, r := s.programHold(ctx, tenantID, &sensorID, group)
		group, l := s.settingsHold(ctx, tenantID, &sensorID, group)
		for id, v := range withWindowRates(r, rates) {
			rules[id] = v
		}
		for id, v := range l {
			layers[id] = v
		}
		for _, c := range group {
			kept[c.ID] = true
		}
	}
	// Back to the dispatch order across organizations, then the caps.
	out := cands[:0:0]
	for _, c := range cands {
		if kept[c.ID] {
			out = append(out, c)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	out = capScanCommands(out, slots)
	if len(out) == 0 {
		return nil, nil
	}

	limits := s.sharedInFlightLimits(ctx, out)
	ids := make([]shared.ID, len(out))
	for i, c := range out {
		ids[i] = c.ID
	}
	claimed, err := claimer.ClaimManyShared(ctx, sensorID, caps, ids, limits)
	if err != nil {
		return nil, err
	}
	won := make(map[shared.ID]bool, len(claimed))
	for _, id := range claimed {
		won[id] = true
	}
	got := make([]*commanddom.Command, 0, len(claimed))
	for _, c := range out {
		if !won[c.ID] {
			continue
		}
		// Re-read in the command's own organization: the claim set the
		// holder, the lease and its epoch.
		cmd, err := s.repo.GetByTenantAndID(ctx, c.TenantID, c.ID)
		if err != nil {
			return nil, err
		}
		got = append(got, cmd)
	}
	observeClaimed(claimModeShared, got, time.Now())
	delivered, err := s.deliver(ctx, sensorID.String(), got, rules, layers)
	if err != nil {
		return nil, err
	}
	// Signed per organization: the statement's tenant is the command's.
	signedOrder, signedGroups := byTenant(delivered)
	result := make([]*commanddom.Command, 0, len(delivered))
	for _, tenantID := range signedOrder {
		result = append(result, s.signClaimed(ctx, tenantID, sensorID.String(), signedGroups[tenantID], nil)...)
	}
	return result, nil
}

// sharedSubject is the gate subject of a shared sensor: its grant (which has
// no tenant), its current manifest and the local policy it reported.
func (s *Service) sharedSubject(ctx context.Context, a *sensordom.Sensor) gateSubject {
	subj := gateSubject{report: a.LocalPolicy}
	if s.grants != nil {
		reader, ok := s.grants.(SharedGrantReader)
		if !ok {
			return gateSubject{closed: true}
		}
		g, err := reader.GetShared(ctx, a.ID)
		if err != nil || g == nil {
			s.logger.Warn("cannot read the shared sensor's grant; withholding shared jobs",
				"sensor_id", a.ID.String(), "error", err)
			return gateSubject{closed: true}
		}
		subj.grant = g
		if s.contracts != nil {
			if v, err := s.contracts.CurrentManifest(ctx, nil, a.ID); err == nil && v != nil {
				subj.manifest = &v.Manifest
			}
		}
	}
	return subj
}

// sharedInFlightLimits reads the platform_scans_concurrent limit of every
// organization of cmds. An organization whose limit cannot be read gets 0
// (fail closed: its jobs wait for a later claim).
func (s *Service) sharedInFlightLimits(ctx context.Context, cmds []*commanddom.Command) map[shared.ID]int {
	out := map[shared.ID]int{}
	for _, c := range cmds {
		if _, done := out[c.TenantID]; done {
			continue
		}
		lim, err := s.sharedLimits.Limit(ctx, c.TenantID, plan.PlatformScansConcurrent)
		if err != nil {
			s.logger.Warn("cannot read the organization's shared job limit; its shared jobs wait",
				"tenant_id", c.TenantID.String(), "error", err)
			lim = 0
		}
		out[c.TenantID] = lim
	}
	return out
}

// byTenant groups cmds by organization, each group in cmds order, and lists
// the organizations in order of their first command.
func byTenant(cmds []*commanddom.Command) ([]shared.ID, map[shared.ID][]*commanddom.Command) {
	var order []shared.ID
	groups := map[shared.ID][]*commanddom.Command{}
	for _, c := range cmds {
		if _, seen := groups[c.TenantID]; !seen {
			order = append(order, c.TenantID)
		}
		groups[c.TenantID] = append(groups[c.TenantID], c)
	}
	return order, groups
}

// HeldSharedJob returns the shared job commandID that the shared sensor
// holds, read with the command's organization: the tenant every later step
// of that command (start, complete, fail, release, logs) runs in. Not found
// for anything else.
func (s *Service) HeldSharedJob(ctx context.Context, a *sensordom.Sensor, commandID string) (*commanddom.Command, error) {
	if a == nil || !a.IsShared() || a.TenantID != nil {
		return nil, shared.ErrNotFound
	}
	claimer, ok := s.repo.(SharedClaimer)
	if !ok {
		return nil, shared.ErrNotFound
	}
	id, err := shared.IDFromString(commandID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	cmd, err := claimer.GetHeldSharedJob(ctx, a.ID, id)
	if err != nil {
		return nil, err
	}
	if cmd == nil || !cmd.IsPlatformJob || cmd.SensorID == nil || *cmd.SensorID != a.ID {
		return nil, shared.ErrNotFound
	}
	return cmd, nil
}
