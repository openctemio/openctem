package command

// Ports of a port scan for a sensor whose local policy lists ports.allow
// (docs/architecture/sensor-local-policy.md, "Port scans"). Such a sensor
// refuses a port-scan job that names no ports. The platform therefore:
//   - fills the job's ports, on the copy it hands out, with the ports the
//     scan would probe that the sensor allows (before the job is signed, so
//     the signature covers them);
//   - when the sensor allows none of them, does not send the job: it stays
//     pending for another sensor that allows some, or, when it is pinned to
//     this sensor or no other sensor may run it, fails at claim with
//     PORTS_NOT_ALLOWED, and its step is skipped with that reason.
// The sensor stays the enforcer: this only avoids jobs it would refuse.

import (
	"context"
	"encoding/json"

	"github.com/openctemio/openctem/server/internal/metrics"
	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/server/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// FailurePortsNotAllowed is the failure code of a port scan refused at claim
// because no sensor that may run it allows any of its ports.
const FailurePortsNotAllowed = scanrundom.FailurePortsNotAllowed

// portsNotAllowedMessage is the English reason a refused job and its step
// carry (the web app explains the code in the reader's language).
const portsNotAllowedMessage = FailurePortsNotAllowed + ": " + sensordom.NoAllowedPortsDetail +
	", and no other sensor that may run it allows any; the task was not sent. " +
	"The network owner can add ports to ports.allow in the sensor's local policy, or the scan can name ports the policy allows"

// refuseNoAllowedPorts fails at claim the jobs of refused whose only reason
// is that this sensor's ports.allow allows none of their ports, when they
// are pinned to the sensor or no other sensor may run them. The ids it
// failed are removed from refused (they are no longer pending).
func (s *Service) refuseNoAllowedPorts(ctx context.Context, sensorID shared.ID, gate *dispatchGate,
	cmds []*commanddom.Command, refused map[shared.ID]string,
) {
	if gate == nil || gate.report == nil || len(refused) == 0 {
		return
	}
	for _, c := range cmds {
		if _, ok := refused[c.ID]; !ok {
			continue
		}
		if !sensordom.NoAllowedPorts(gate.report, sensordom.JobOf(string(c.Type), c.Payload)) {
			continue
		}
		if c.SensorID == nil {
			finder, ok := s.repo.(RequeueCandidateFinder)
			if !ok {
				continue
			}
			other, err := s.anotherSensorAccepts(ctx, finder, c,
				[]commanddom.RefusalRecord{{SensorID: sensorID.String()}})
			if err != nil || other {
				continue // fail closed on an error: the job waits
			}
		}
		if s.failAtClaim(ctx, c, portsNotAllowedMessage, FailurePortsNotAllowed) == recheckFailed {
			metrics.PortScanPortsTotal.WithLabelValues("refused").Inc()
			delete(refused, c.ID)
		}
	}
}

// withPolicyPorts sets, on a copy of each port scan that names no ports, the
// ports the sensor's ports.allow allows (sensordom.PortScanFill). The
// sensor's report is read in the command's own organization; a sensor that
// cannot be read there (a shared sensor) or reports no ports.allow gets the
// job unchanged.
func (s *Service) withPolicyPorts(ctx context.Context, sensorID string, cmds []*commanddom.Command) ([]*commanddom.Command, error) {
	if s.sensors == nil {
		return cmds, nil
	}
	sid, ok := parseSensorID(sensorID)
	if !ok {
		// Not a sensor id: nothing to read, the job is handed out
		// unchanged (the sensor still enforces its policy).
		return cmds, nil
	}
	reports := map[shared.ID]*sensordom.LocalPolicyReport{}
	for i, c := range cmds {
		job := sensordom.JobOf(string(c.Type), c.Payload)
		if !job.PortScan || job.Ports != "" {
			continue
		}
		r, seen := reports[c.TenantID]
		if !seen {
			if a, err := s.sensors.GetByTenantAndID(ctx, c.TenantID, sid); err == nil && a != nil {
				r = a.LocalPolicy
			}
			reports[c.TenantID] = r
		}
		ports, ok := sensordom.PortScanFill(r, job)
		if !ok {
			continue
		}
		payload, err := withPorts(c.Payload, ports)
		if err != nil {
			return nil, err
		}
		cp := *c
		cp.Payload = payload
		cmds[i] = &cp
		metrics.PortScanPortsTotal.WithLabelValues("filled").Inc()
	}
	return cmds, nil
}

// payloadKeyConfig is the payload member of a job's tool settings.
const payloadKeyConfig = "config"

// withPorts sets config.ports to ports and removes the top-N settings of
// config and scanner_config, which the ports replace.
func withPorts(payload json.RawMessage, ports string) (json.RawMessage, error) {
	var p map[string]json.RawMessage
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	for _, k := range []string{payloadKeyConfig, "scanner_config"} {
		raw, ok := p[k]
		if !ok && k != payloadKeyConfig {
			continue
		}
		cfg := map[string]any{}
		if ok && string(raw) != jsonNull {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return nil, err
			}
		}
		delete(cfg, "top_ports")
		delete(cfg, "top_n")
		if k == payloadKeyConfig {
			cfg["ports"] = ports
		}
		b, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		p[k] = b
	}
	return json.Marshal(p)
}

// parseSensorID is sensorID as an id; false when it is not one.
func parseSensorID(sensorID string) (shared.ID, bool) {
	id, err := shared.IDFromString(sensorID)
	return id, err == nil
}
