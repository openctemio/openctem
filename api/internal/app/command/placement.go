package command

// Why a queued command waits (docs/architecture/placement.md).
//
// ExplainPlacement evaluates, for one command and every sensor of its
// tenant, the checks a sensor's poll and claim apply, in the order they
// apply them: the claim SQL's predicates (read back by the repository with
// the same SQL), then the dispatch gate (grant, intensity, local policy,
// private targets, opt-ins; the gate's own code), then the free slots. It
// is read-only and never decides placement: the claim stays the authority,
// and a test keeps the two in agreement (placement_db_test.go).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/ctis/politeness"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxPlacementSensors bounds the sensors one explanation evaluates (by
// name); a larger fleet is reported as truncated.
const MaxPlacementSensors = 100

// SensorPlacement is one sensor's verdict for a command.
type SensorPlacement struct {
	SensorID shared.ID
	Name     string
	// Eligible: the sensor may take the command (it may still be busy).
	Eligible bool
	// Busy: eligible, but it has no free scan slot now.
	Busy bool
	// Reasons are the checks that keep the command from this sensor, in
	// the order the claim applies them (commanddom.Placement*).
	Reasons []string
}

// ReasonCount is how many sensors one reason keeps the command from.
type ReasonCount struct {
	Code  string
	Count int
}

// Placement explains where a command can go.
type Placement struct {
	Status commanddom.CommandStatus
	// Platform: the command waits for platform scanning; no sensor is
	// named or evaluated.
	Platform bool
	// JobReasons hold the command whatever the sensor.
	JobReasons []string
	// Sensors is the tenant's own sensors' verdicts (at most
	// MaxPlacementSensors, by name); Truncated when there were more.
	Sensors   []SensorPlacement
	Truncated bool
	// Eligible counts the sensors that may take it; Busy those of them
	// with no free slot. Blocking counts each reason over the others, most
	// frequent first.
	Eligible int
	Busy     int
	Blocking []ReasonCount
	// HostWait says, when the command waits for its hosts (host_busy),
	// how many of them other tasks of the organization hold and which tasks
	// (at most commanddom.MaxHostHolders). Nil otherwise.
	HostWait *HostWait
	// SharedFleet says, for a task none of the organization's sensors may
	// take, whether the shared fleet was an option: SharedFleetNotUsed (the
	// organization may use shared sensors, but this task was routed to its
	// own sensors), SharedFleetNotAllowed (it may not now; SharedFleetReason
	// is the access policy's reason, English). "" when a sensor of the
	// organization may take it.
	SharedFleet       string
	SharedFleetReason string
}

// SharedFleet values of Placement.
const (
	SharedFleetNotUsed    = "not_used"
	SharedFleetNotAllowed = "not_allowed"
)

// HostWait is why a command waits for its hosts: Held of its Total hosts
// are held by the Holders (the tasks holding the most of them first), and
// CanStart of its Targets are on hosts nobody holds (-1: cannot tell). Only
// counts and the organization's own tasks; never host names.
type HostWait struct {
	Held     int
	Total    int
	Targets  int
	CanStart int
	Holders  []commanddom.HostHolder
}

// ExplainPlacement explains why the command waits. Only a pending command
// is evaluated; for any other status the result carries just the status.
// A command of another tenant is shared.ErrNotFound.
func (s *Service) ExplainPlacement(ctx context.Context, tenantID, commandID shared.ID) (*Placement, error) {
	reader, ok := s.repo.(commanddom.PlacementReader)
	if !ok {
		return nil, errors.New("placement is not available")
	}
	job, claims, err := reader.PlacementPredicates(ctx, tenantID, commandID, MaxPlacementSensors+1)
	if err != nil {
		return nil, err
	}
	out := &Placement{Status: job.Status, Platform: job.IsPlatformJob}
	if job.Status != commanddom.CommandStatusPending || job.IsPlatformJob {
		return out, nil
	}
	out.JobReasons = jobReasons(job)
	cmd, err := s.repo.GetByTenantAndID(ctx, tenantID, commandID)
	if err != nil {
		return nil, fmt.Errorf("read command: %w", err)
	}
	if !job.HostFree {
		hw, err := s.hostWait(ctx, cmd)
		if err != nil {
			return nil, err
		}
		out.HostWait = hw
	}
	if len(claims) > MaxPlacementSensors {
		claims, out.Truncated = claims[:MaxPlacementSensors], true
	}
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	for _, c := range claims {
		sp, err := s.sensorPlacement(ctx, tenantID, cmd, c, now)
		if err != nil {
			return nil, err
		}
		out.Sensors = append(out.Sensors, sp)
	}
	out.summarize()
	if out.Eligible == 0 {
		// Nobody of the organization can take it: say whether the shared
		// fleet could have (research/191 W-1), so the run does not wait in
		// silence until its timeout.
		out.SharedFleet = SharedFleetNotAllowed
		if s.sharedAccess != nil {
			if ok, reason := s.sharedAccess(ctx, tenantID); ok {
				out.SharedFleet, out.SharedFleetReason = SharedFleetNotUsed, ""
			} else {
				out.SharedFleetReason = reason
			}
		}
	}
	return out, nil
}

// ExplainRunTaskPlacement is ExplainPlacement for a task of a scan run: a
// command that is not of that run (or not of the tenant) is
// shared.ErrNotFound, so a run id cannot be used to read another run's
// tasks.
func (s *Service) ExplainRunTaskPlacement(ctx context.Context, tenantID, runID, commandID shared.ID) (*Placement, error) {
	cmd, err := s.repo.GetByTenantAndID(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}
	if payloadRunID(cmd.Payload) != runID.String() {
		return nil, fmt.Errorf("%w: task not found", shared.ErrNotFound)
	}
	return s.ExplainPlacement(ctx, tenantID, commandID)
}

// jobReasons are the job-level predicates that fail.
func jobReasons(j commanddom.PlacementJob) []string {
	var out []string
	if !j.NotExpired {
		out = append(out, commanddom.PlacementExpired)
	}
	if !j.Due {
		out = append(out, commanddom.PlacementWindowClosed)
	}
	if !j.HostFree {
		out = append(out, commanddom.PlacementHostBusy)
	} else if j.SensorHostsBusy {
		out = append(out, commanddom.PlacementSensorHostsBusy)
	}
	return out
}

// maxHostHoldersRead bounds the holders read to count the held hosts.
const maxHostHoldersRead = 50

// RunTaskHostWait is why a pending task of a run waits for its hosts; nil
// when it does not (it is not pending, or nothing holds its hosts). A
// command that is not of that run (or not of the tenant) is
// shared.ErrNotFound.
func (s *Service) RunTaskHostWait(ctx context.Context, tenantID, runID, commandID shared.ID) (*HostWait, error) {
	cmd, err := s.repo.GetByTenantAndID(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}
	if payloadRunID(cmd.Payload) != runID.String() {
		return nil, fmt.Errorf("%w: task not found", shared.ErrNotFound)
	}
	if cmd.Status != commanddom.CommandStatusPending {
		return nil, nil
	}
	hw, err := s.hostWait(ctx, cmd)
	if err != nil || hw == nil || hw.Held == 0 {
		return nil, err
	}
	return hw, nil
}

// payloadRunID is the scan run a command payload names ("" when none).
func payloadRunID(payload json.RawMessage) string {
	var p struct {
		RunID string `json:"scan_run_id"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return ""
	}
	return p.RunID
}

// hostWait counts the command's hosts that tasks of its tenant hold, how
// many of its targets are on free hosts, and names the tasks holding the
// most; nil when the repository cannot tell.
func (s *Service) hostWait(ctx context.Context, cmd *commanddom.Command) (*HostWait, error) {
	reader, ok := s.repo.(commanddom.HostHoldersReader)
	if !ok {
		return nil, nil
	}
	keys, holders, err := reader.HostHolders(ctx, cmd.TenantID, cmd.ID, maxHostHoldersRead)
	if err != nil {
		return nil, fmt.Errorf("read host holders: %w", err)
	}
	held := map[string]bool{}
	var heldKeys []string
	for _, h := range holders {
		for _, k := range h.Keys {
			held[k] = true
			heldKeys = append(heldKeys, k)
		}
	}
	targets := commanddom.PayloadTargets(cmd.Payload)
	hw := &HostWait{Targets: len(targets), CanStart: -1}
	if p, ok := commanddom.PartitionHeld(targets, payloadNetwork(cmd.Payload), keys, heldKeys); ok {
		hw.CanStart = len(p.Free)
	}
	for _, k := range keys {
		if strings.HasPrefix(k, commanddom.HostKeyAddrInBucket) {
			continue // the bucket marker of an address: not a host of its own
		}
		hw.Total++
		for _, c := range hostConflicts(k) {
			if held[c] {
				hw.Held++
				break
			}
		}
	}
	if len(holders) > commanddom.MaxHostHolders {
		holders = holders[:commanddom.MaxHostHolders]
	}
	hw.Holders = holders
	return hw, nil
}

// hostConflicts is the keys that hold host key k back: k itself and, for
// an address, the range key of its bucket (for a range key, the bucket's
// address marker; politeness.Conflicts).
func hostConflicts(k string) []string {
	out := commanddom.HostKeyConflicts([]string{k})
	addr, suffix, _ := strings.Cut(k, politeness.NetworkSep)
	if a, err := netip.ParseAddr(addr); err == nil {
		if suffix != "" {
			suffix = politeness.NetworkSep + suffix
		}
		out = append(out, commanddom.HostKeyRangeBucket+commanddom.AddrBucket(a).String()+suffix)
	}
	return out
}

// sensorPlacement is one sensor's verdict: its state, the claim SQL's
// predicates (c), then, only when those pass, the dispatch gate and the
// free slots, as the poll applies them.
func (s *Service) sensorPlacement(ctx context.Context, tenantID shared.ID, cmd *commanddom.Command, c commanddom.SensorClaim, now time.Time) (SensorPlacement, error) {
	sp := SensorPlacement{SensorID: c.SensorID}
	var sn *sensordom.Sensor
	if s.sensors != nil {
		var err error
		sn, err = s.sensors.GetByTenantAndID(ctx, tenantID, c.SensorID)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return sp, fmt.Errorf("read sensor: %w", err)
		}
	}
	if sn != nil {
		sp.Name = sn.Name
		if sn.Status != sensordom.SensorStatusActive {
			sp.Reasons = append(sp.Reasons, commanddom.PlacementInactive)
		}
		if !sensorReachable(sn.Health) {
			sp.Reasons = append(sp.Reasons, commanddom.PlacementOffline)
		}
	}
	sp.Reasons = append(sp.Reasons, claimReasons(c)...)
	if len(sp.Reasons) > 0 {
		return sp, nil
	}
	if r := s.gateFor(ctx, tenantID, &c.SensorID, []*commanddom.Command{cmd}).refusal(cmd); r != nil {
		sp.Reasons = append(sp.Reasons, gateReason(r))
		return sp, nil
	}
	sp.Eligible = true
	if cmd.Type == commanddom.CommandTypeScan && sn != nil {
		free := sn.FreeSlots(now)
		sp.Busy = freeScanSlots(sn.EffectiveMaxConcurrentJobs(), c.HeldScans, &free) == 0
	}
	return sp, nil
}

// sensorReachable: the sensor checks in (online, or a little late).
func sensorReachable(h sensordom.SensorHealth) bool {
	return h == sensordom.SensorHealthOnline || h == sensordom.SensorHealthLate
}

// claimReasons are the claim SQL's per-sensor predicates that fail, in
// the order the poll's WHERE lists them.
func claimReasons(c commanddom.SensorClaim) []string {
	var out []string
	if !c.PinOK {
		out = append(out, commanddom.PlacementPinnedElsewhere)
	}
	if !c.ZoneOK {
		out = append(out, commanddom.PlacementOutsideZone)
	}
	if !c.ToolOK {
		out = append(out, commanddom.PlacementToolMissing)
	}
	if !c.NotRefused {
		out = append(out, commanddom.PlacementRefusedEarlier)
	}
	if !c.CapabilityOK {
		out = append(out, commanddom.PlacementCapabilityMissing)
	}
	if !c.FeaturesOK {
		// required_features holds only net.confined@1 today.
		out = append(out, commanddom.PlacementNotConfined)
	}
	return out
}

// gateReason is the placement code of a dispatch gate refusal.
func gateReason(r *sensordom.DispatchRefusal) string {
	switch {
	case r.Layer == RefusalLayerGrant && r.Rule == RuleIntensity:
		return commanddom.PlacementIntensity
	case r.Layer == RefusalLayerGrant:
		return commanddom.PlacementGrantPrefix + r.Rule
	case r.Layer == sensordom.RefusalLayerManaged && r.Rule == "unavailable":
		return commanddom.PlacementPolicyUnavailable
	case r.Rule == sensordom.RulePrivateNeedsLocalPlcy:
		return commanddom.PlacementPrivateNeedsPolicy
	case r.Layer == sensordom.RefusalLayerManaged && (r.Rule == sensordom.RuleAllowInteractsh || r.Rule == sensordom.RuleAllowCustomTemplates):
		return commanddom.PlacementOptInDisabled
	default:
		return commanddom.PlacementLocalPolicy
	}
}

// summarize fills the counts: eligible and busy sensors, and each
// blocking reason over the others, most frequent first.
func (p *Placement) summarize() {
	counts := map[string]int{}
	for _, sp := range p.Sensors {
		switch {
		case sp.Eligible:
			p.Eligible++
			if sp.Busy {
				p.Busy++
			}
		default:
			for _, r := range sp.Reasons {
				counts[r]++
			}
		}
	}
	for code, n := range counts {
		p.Blocking = append(p.Blocking, ReasonCount{Code: code, Count: n})
	}
	slices.SortFunc(p.Blocking, func(a, b ReasonCount) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		if a.Code < b.Code {
			return -1
		}
		if a.Code > b.Code {
			return 1
		}
		return 0
	})
}
