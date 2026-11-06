package command

// Proxy pools for scan traffic (docs/architecture/sensor-proxies.md): the
// "egress" member of a scan or retest command names the pool and endpoints
// the claiming sensor uses. It is set on the copy of the command a sensor
// receives (never on the stored command) for that sensor, so the job
// signature covers it. A sensor whose jobs use a pool but which does not
// report the capability to honor one gets no scan or retest jobs at all:
// it would run them directly. Validate jobs probe targets too: a sensor
// whose jobs use a pool gets them only when it also reports that its
// validate executor honors the pool (sensordom.CapabilityEgressValidate),
// and then they carry the member as well.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PayloadKeyEgress is the payload member of a job's proxy pool.
const PayloadKeyEgress = "egress"

// ErrEgressUnsupported refuses a job to a sensor whose jobs use a proxy pool
// but which cannot run them through one.
var ErrEgressUnsupported = shared.NewDomainError("EGRESS_UNSUPPORTED",
	"this sensor's jobs use a proxy pool, but the sensor does not support proxies (upgrade it and run it with network confinement)",
	shared.ErrConflict)

// EgressSource returns the egress a sensor's jobs get (nil: none).
// Satisfied by the proxy pool service.
type EgressSource interface {
	JobEgress(ctx context.Context, tenantID, sensorID shared.ID) (*proxypool.JobEgress, error)
}

// ProxyRequirement says whether an organization requires every scan to go
// through a proxy: a sensor that would otherwise run
// direct, a host-direct sensor included, then gets no job and the work waits.
type ProxyRequirement interface {
	ProxyRequired(ctx context.Context, tenantID shared.ID) (bool, error)
}

// WithProxyRequirement wires the organization's "Proxy required" switch.
// Without it nothing is required, as before.
func WithProxyRequirement(r ProxyRequirement) Option {
	return func(s *Service) { s.proxyRequired = r }
}

// WithEgress makes every scan and retest job an organization sensor
// receives carry its proxy pool, and keeps those jobs from a sensor that
// cannot honor it.
func WithEgress(src EgressSource) Option {
	return func(s *Service) { s.egress = src }
}

// egressCommand reports whether a command type is a scan or retest job,
// which every sensor that honors pools runs through its pool.
func egressCommand(t commanddom.CommandType) bool {
	return t == commanddom.CommandTypeScan || t == commanddom.CommandTypeRetest
}

// egressBound reports whether a command type reaches targets and so
// carries the egress member: scan and retest jobs, and validate jobs.
func egressBound(t commanddom.CommandType) bool {
	return egressCommand(t) || t == commanddom.CommandTypeValidate
}

// egressDecision is the egress of one organization sensor's jobs.
type egressDecision struct {
	egress *proxypool.JobEgress
	// blocked: the jobs use a pool and the sensor cannot honor it.
	blocked bool
	// validateBlocked: the jobs use a pool and the sensor's validate jobs
	// would not go through it (they would probe from its own address).
	validateBlocked bool
	// hostDirect: the sensor's owner set SENSOR_SCAN_EGRESS=direct-only
	// (it reports egress.host-direct@1). With blocked, the jobs wait for a
	// reason other than "upgrade the sensor": the organization requires a
	// proxy, or named a pool for this sensor, and the host refuses pools.
	hostDirect bool
}

// holds reports whether the decision keeps command type t from the sensor.
func (d egressDecision) holds(t commanddom.CommandType) bool {
	if t == commanddom.CommandTypeValidate {
		return d.validateBlocked
	}
	return d.blocked && egressCommand(t)
}

// holdReason is the placement reason (commanddom.PlacementEgress*) the
// decision keeps command type t from the sensor for; "" when it does not.
// Every egress hold has its reason here, so a new kind of hold names itself
// in one place.
func (d egressDecision) holdReason(t commanddom.CommandType) string {
	switch {
	case !d.holds(t):
		return ""
	case d.hostDirect:
		return commanddom.PlacementEgressHostDirect
	case t == commanddom.CommandTypeValidate:
		return commanddom.PlacementEgressValidateUnsupported
	default:
		return commanddom.PlacementEgressUnsupported
	}
}

// PoolNamer names a pool of a tenant ("" when it cannot be read). An
// EgressSource that implements it lets the placement explainer say which
// pool holds a job.
type PoolNamer interface {
	PoolName(ctx context.Context, tenantID shared.ID, poolID string) string
}

// egressFor resolves the egress of sensorID's jobs among cmds (nothing to
// look up when none is a scan or retest job). A shared sensor, or a service
// without the source, gets none. An error fails the delivery: a job never
// leaves without the pool the organization set.
func (s *Service) egressFor(ctx context.Context, tenantID shared.ID, sensorID string, cmds []*commanddom.Command) (egressDecision, error) {
	if s.egress == nil || sensorID == "" || !slices.ContainsFunc(cmds, func(c *commanddom.Command) bool { return egressBound(c.Type) }) {
		return egressDecision{}, nil
	}
	sid, err := shared.IDFromString(sensorID)
	if err != nil {
		return egressDecision{}, fmt.Errorf("%w: invalid sensor id", shared.ErrValidation)
	}
	var sn *sensordom.Sensor
	if s.sensors != nil {
		if sn, err = s.sensors.GetByTenantAndID(ctx, tenantID, sid); err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return egressDecision{}, nil
			}
			return egressDecision{}, fmt.Errorf("look up the sensor for its proxy pool: %w", err)
		}
		if sn == nil || sn.IsShared() {
			return egressDecision{}, nil
		}
	}
	eg, err := s.egress.JobEgress(ctx, tenantID, sid)
	if err != nil {
		return egressDecision{}, fmt.Errorf("read the sensor's proxy pool: %w", err)
	}
	if eg == nil {
		return egressDecision{}, nil
	}
	// A sensor whose owner set direct-only (it reports that, never what an
	// administrator declared) takes no pool. If it only inherits the
	// organization's default pool (public targets only), it runs direct and
	// the console shows the path as set on the host; a pool named for this
	// sensor, or the organization requiring a proxy, is a conflict with the
	// host's veto: its jobs wait, they are never sent direct.
	if sn != nil && slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityEgressHostDirect) &&
		!slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityEgressUpstream) {
		required, err := s.proxyRequiredFor(ctx, tenantID)
		if err != nil {
			return egressDecision{}, err
		}
		if required || eg.AppliesTo != proxypool.AppliesPublic {
			return egressDecision{egress: eg, blocked: true, validateBlocked: true, hostDirect: true}, nil
		}
		return egressDecision{}, nil
	}
	// What the sensor reports it does, never what an administrator
	// declared; no sensor to check means no proof (fail closed).
	supported := sn != nil &&
		slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityEgressUpstream) &&
		slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityNetConfined)
	validates := supported && slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityEgressValidate)
	return egressDecision{egress: eg, blocked: !supported, validateBlocked: !validates}, nil
}

// proxyRequiredFor reads the organization's "Proxy required" switch; an
// error fails the delivery (a job never leaves on a guess).
func (s *Service) proxyRequiredFor(ctx context.Context, tenantID shared.ID) (bool, error) {
	if s.proxyRequired == nil {
		return false, nil
	}
	req, err := s.proxyRequired.ProxyRequired(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("read the organization's proxy requirement: %w", err)
	}
	return req, nil
}

// withoutEgressJobs drops the commands the sensor cannot run through its
// pool (scan and retest jobs when it cannot honor one, validate jobs when
// its validate executor does not); the rest go out as usual. They stay
// pending for a sensor that can.
func (d egressDecision) withoutEgressJobs(cmds []*commanddom.Command) []*commanddom.Command {
	if !d.blocked && !d.validateBlocked {
		return cmds
	}
	out := cmds[:0:0]
	for _, c := range cmds {
		if !d.holds(c.Type) {
			out = append(out, c)
		}
	}
	claimSkipped(skipEgressUnsupported, len(cmds), len(out))
	return out
}

// stamp sets the egress member on copies of the scan, retest and validate
// commands, or removes one a command's creator put there: the field
// belongs to the platform.
func (d egressDecision) stamp(cmds []*commanddom.Command) ([]*commanddom.Command, error) {
	for i, c := range cmds {
		if !egressBound(c.Type) {
			continue
		}
		payload, err := withEgressPayload(c.Payload, d.egress)
		if err != nil {
			return nil, err
		}
		cp := *c
		cp.Payload = payload
		cmds[i] = &cp
	}
	return cmds, nil
}

func withEgressPayload(payload json.RawMessage, eg *proxypool.JobEgress) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(payload) == 0 || string(payload) == jsonNull {
		fields = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("command payload: %w", err)
	}
	if eg == nil {
		if _, ok := fields[PayloadKeyEgress]; !ok {
			return payload, nil
		}
		delete(fields, PayloadKeyEgress)
	} else {
		b, err := json.Marshal(eg)
		if err != nil {
			return nil, err
		}
		fields[PayloadKeyEgress] = b
	}
	return json.Marshal(fields)
}

// egressOne applies the decision to one command a sensor claims by id:
// refused when the sensor cannot honor its pool, else stamped.
func (s *Service) egressOne(ctx context.Context, sensorID string, cmd *commanddom.Command) (*commanddom.Command, error) {
	if cmd == nil || !egressBound(cmd.Type) {
		return cmd, nil
	}
	d, err := s.egressFor(ctx, cmd.TenantID, sensorID, []*commanddom.Command{cmd})
	if err != nil {
		return nil, err
	}
	if d.holds(cmd.Type) {
		return nil, ErrEgressUnsupported
	}
	out, err := d.stamp([]*commanddom.Command{cmd})
	if err != nil {
		return nil, err
	}
	return out[0], nil
}

// EgressLedger records the proxy path a claimed job was handed and charges
// the job's own proxy verdict to it when the job ends (the proxy pool
// service; docs/architecture/sensor-proxies.md, "Task-reported proxy
// faults"). An EgressSource that implements it gets both calls.
type EgressLedger interface {
	RecordJobEgress(ctx context.Context, tenantID, commandID, sensorID shared.ID, leaseEpoch int, eg *proxypool.JobEgress) error
	ObserveJobVerdict(ctx context.Context, tenantID, commandID, sensorID shared.ID, leaseEpoch int, v proxypool.TaskVerdict) error
}

func (s *Service) egressLedger() EgressLedger {
	l, _ := s.egress.(EgressLedger)
	return l
}

// recordEgress records the egress member the platform stamped on each
// claimed job it hands out (the member always comes from stamp, which
// replaces whatever a command's creator put there, never from a sensor). A
// failure is logged and never fails the delivery: the job's proxy faults
// then go uncharged, the job itself is unaffected.
func (s *Service) recordEgress(ctx context.Context, cmds []*commanddom.Command) {
	ledger := s.egressLedger()
	if ledger == nil {
		return
	}
	for _, c := range cmds {
		if c == nil || c.SensorID == nil || !egressBound(c.Type) {
			continue
		}
		eg, ok := stampedEgress(c.Payload)
		if !ok {
			continue
		}
		if err := ledger.RecordJobEgress(ctx, c.TenantID, c.ID, *c.SensorID, c.LeaseEpoch, eg); err != nil {
			s.logger.Error("failed to record the proxy path of a job", "command_id", c.ID.String(), "error", err)
		}
	}
}

// stampedEgress reads the egress member of a payload stamp produced.
func stampedEgress(payload json.RawMessage) (*proxypool.JobEgress, bool) {
	var fields map[string]json.RawMessage
	if len(payload) == 0 || json.Unmarshal(payload, &fields) != nil {
		return nil, false
	}
	raw, ok := fields[PayloadKeyEgress]
	if !ok {
		return nil, false
	}
	var eg proxypool.JobEgress
	if json.Unmarshal(raw, &eg) != nil || eg.Mode != proxypool.ModePool {
		return nil, false
	}
	return &eg, true
}

// observeEgressVerdict charges an ended job's proxy verdict to the path it
// was handed. Logged on failure; the job's own transition stands.
func (s *Service) observeEgressVerdict(ctx context.Context, cmd *commanddom.Command, v proxypool.TaskVerdict) {
	ledger := s.egressLedger()
	if ledger == nil || cmd == nil || cmd.SensorID == nil || !egressBound(cmd.Type) {
		return
	}
	if err := ledger.ObserveJobVerdict(ctx, cmd.TenantID, cmd.ID, *cmd.SensorID, cmd.LeaseEpoch, v); err != nil {
		s.logger.Error("failed to charge a job's proxy verdict", "command_id", cmd.ID.String(), "error", err)
	}
}
