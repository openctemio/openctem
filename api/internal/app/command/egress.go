package command

// Proxy pools for scan traffic (docs/architecture/sensor-proxies.md): the
// "egress" member of a scan or retest command names the pool and endpoints
// the claiming sensor uses. It is set on the copy of the command a sensor
// receives (never on the stored command) for that sensor, so the job
// signature covers it. A sensor whose jobs use a pool but which does not
// report the capability to honor one gets no scan or retest jobs at all:
// it would run them directly.

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

// WithEgress makes every scan and retest job an organization sensor
// receives carry its proxy pool, and keeps those jobs from a sensor that
// cannot honor it.
func WithEgress(src EgressSource) Option {
	return func(s *Service) { s.egress = src }
}

// egressCommand reports whether a command type carries an egress member.
func egressCommand(t commanddom.CommandType) bool {
	return t == commanddom.CommandTypeScan || t == commanddom.CommandTypeRetest
}

// egressDecision is the egress of one organization sensor's jobs.
type egressDecision struct {
	egress *proxypool.JobEgress
	// blocked: the jobs use a pool and the sensor cannot honor it.
	blocked bool
}

// egressFor resolves the egress of sensorID's jobs among cmds (nothing to
// look up when none is a scan or retest job). A shared sensor, or a service
// without the source, gets none. An error fails the delivery: a job never
// leaves without the pool the organization set.
func (s *Service) egressFor(ctx context.Context, tenantID shared.ID, sensorID string, cmds []*commanddom.Command) (egressDecision, error) {
	if s.egress == nil || sensorID == "" || !slices.ContainsFunc(cmds, func(c *commanddom.Command) bool { return egressCommand(c.Type) }) {
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
	// What the sensor reports it does, never what an administrator
	// declared; no sensor to check means no proof (fail closed).
	supported := sn != nil &&
		slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityEgressUpstream) &&
		slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityNetConfined)
	return egressDecision{egress: eg, blocked: !supported}, nil
}

// withoutEgressJobs drops the scan and retest commands when the sensor
// cannot honor its pool; the rest go out as usual.
func (d egressDecision) withoutEgressJobs(cmds []*commanddom.Command) []*commanddom.Command {
	if !d.blocked {
		return cmds
	}
	out := cmds[:0:0]
	for _, c := range cmds {
		if !egressCommand(c.Type) {
			out = append(out, c)
		}
	}
	claimSkipped(skipEgressUnsupported, len(cmds), len(out))
	return out
}

// stamp sets the egress member on copies of the scan and retest commands,
// or removes one a command's creator put there: the field belongs to the
// platform.
func (d egressDecision) stamp(cmds []*commanddom.Command) ([]*commanddom.Command, error) {
	for i, c := range cmds {
		if !egressCommand(c.Type) {
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
	if cmd == nil || !egressCommand(cmd.Type) {
		return cmd, nil
	}
	d, err := s.egressFor(ctx, cmd.TenantID, sensorID, []*commanddom.Command{cmd})
	if err != nil {
		return nil, err
	}
	if d.blocked {
		return nil, ErrEgressUnsupported
	}
	out, err := d.stamp([]*commanddom.Command{cmd})
	if err != nil {
		return nil, err
	}
	return out[0], nil
}
