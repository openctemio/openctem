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
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SharedClaimer is the repository side of the shared claim path
// (CommandRepository).
type SharedClaimer interface {
	GetSharedPendingForSensor(ctx context.Context, sensorID shared.ID, capabilities []string, limit int) ([]*commanddom.Command, error)
	ClaimManyShared(ctx context.Context, sensorID shared.ID, capabilities []string, ids []shared.ID, limits map[shared.ID]int) ([]shared.ID, error)
	CountHeldSharedScans(ctx context.Context, sensorID shared.ID) (int, error)
	GetHeldSharedJobForPlatform(ctx context.Context, sensorID, commandID shared.ID) (*commanddom.Command, error)
}

// SharedLimitSource reads an organization's limit of a key through the
// entitlement service, by key and never by plan (*entitlement.Service).
// limits.Unlimited: no limit.
type SharedLimitSource interface {
	Limit(ctx context.Context, tenantID shared.ID, key limits.Key) (int, error)
}

// SharedGrantReader reads a shared sensor's grant (it has no tenant).
type SharedGrantReader interface {
	GetShared(ctx context.Context, sensorID shared.ID) (*sensordom.Grant, error)
}

// SharedAccessPolicy says whether an organization may use shared sensors
// now (the access policy of RFC-100 §5: the instance switch, the
// administrator's decision, the organization's opt-out), and if not, why.
type SharedAccessPolicy func(ctx context.Context, tenantID shared.ID) (bool, string)

// WithSharedAccess wires the access policy the shared claim applies to each
// organization at claim time: jobs an organization queued before it lost
// access (or opted out) wait and expire instead of running. Without it the
// shared claim hands out nothing (fail closed).
func WithSharedAccess(p SharedAccessPolicy) Option {
	return func(s *Service) { s.sharedAccess = p }
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
// pass the access policy (an organization that lost access or opted out is
// skipped) and the same gates as an organization sensor's claim, in that
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
	if !ok || s.sharedLimits == nil || s.sharedAccess == nil {
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
	page := candidateLimit(limit)
	cands, err := claimer.GetSharedPendingForSensor(ctx, sensorID, caps, page)
	if err != nil {
		return nil, err
	}
	if len(cands) == 0 {
		return nil, nil
	}

	subj := s.sharedSubject(ctx, in.Sensor)
	rules := map[shared.ID]*bp.JobRules{}
	layers := map[shared.ID]settingsLayers{}
	allowed := map[shared.ID]bool{}
	pager, canPage := claimer.(SharedPendingPager)
	var out []*commanddom.Command
	var seen []shared.ID
	// Withheld jobs come back first on every poll: when they fill a page,
	// read the next one without them (research/191 W-2).
	for p := 0; ; p++ {
		for _, c := range cands {
			seen = append(seen, c.ID)
		}
		out = append(out, s.holdShared(ctx, subj, sensorID, cands, allowed, rules, layers)...)
		if !canPage || p+1 >= maxClaimPages || len(cands) < page || len(out) >= limit || scanCount(out) >= slots {
			break
		}
		claimPaged(claimModeShared)
		if cands, err = pager.GetSharedPendingForSensorExcluding(ctx, sensorID, caps, page, seen); err != nil {
			return nil, err
		}
		if len(cands) == 0 {
			break
		}
	}
	// The caps last.
	out = capScanCommands(out, slots)
	if len(out) > limit {
		out = out[:limit]
	}
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
// no tenant), its current manifest and the local policy it reported. No
// grant reader, or no grant: closed.
func (s *Service) sharedSubject(ctx context.Context, a *sensordom.Sensor) gateSubject {
	subj := gateSubject{report: a.LocalPolicy}
	// A shared sensor is never handed work outside its grant: without a
	// grant reader that can read a shared sensor's grant, nothing (fail
	// closed; an organization sensor's claim keeps its own rule).
	reader, ok := s.grants.(SharedGrantReader)
	if s.grants == nil || !ok {
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
		lim, err := s.sharedLimits.Limit(ctx, c.TenantID, limits.PlatformScansConcurrent)
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
	cmd, err := claimer.GetHeldSharedJobForPlatform(ctx, a.ID, id)
	if err != nil {
		return nil, err
	}
	if cmd == nil || !cmd.IsPlatformJob || cmd.SensorID == nil || *cmd.SensorID != a.ID {
		return nil, shared.ErrNotFound
	}
	return cmd, nil
}

// SharedPendingPager reads the next page of a shared sensor's candidates,
// without the ones already read (postgres.CommandRepository). Optional.
type SharedPendingPager interface {
	GetSharedPendingForSensorExcluding(ctx context.Context, sensorID shared.ID, capabilities []string, limit int, exclude []shared.ID) ([]*commanddom.Command, error)
}

// holdShared applies the access policy and the checks after the query to
// one page of a shared sensor's candidates, per organization, and returns
// the ones kept in the dispatch order; rules and layers collect what the
// kept ones carry. allowed caches the access decision per organization for
// the claim.
func (s *Service) holdShared(ctx context.Context, subj gateSubject, sensorID shared.ID, cands []*commanddom.Command,
	allowed map[shared.ID]bool, rules map[shared.ID]*bp.JobRules, layers map[shared.ID]settingsLayers,
) []*commanddom.Command {
	order, groups := byTenant(cands)
	kept := map[shared.ID]bool{}
	for _, tenantID := range order {
		ok, decided := allowed[tenantID]
		if !decided {
			var why string
			ok, why = s.sharedAccess(ctx, tenantID)
			allowed[tenantID] = ok
			if !ok {
				s.logger.Debug("organization may not use shared sensors now; its shared jobs wait",
					"tenant_id", tenantID.String(), "reason", why)
			}
		}
		if !ok {
			continue
		}
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
	out := cands[:0:0]
	for _, c := range cands {
		if kept[c.ID] {
			out = append(out, c)
		}
	}
	return out
}
