package command

// Task secrets in the job (docs/architecture/task-secrets.md): when a sensor
// claims a scan, retest, validate or proxy test job, the platform lists in
// the payload member "secrets" (contract secretref.Set) the secrets the job
// may use, before the job is signed, so the job signature covers the list.
// The list names secrets, never carries a value: the sensor fetches values
// per task from the sealed secrets route, which answers only refs recorded
// for that claim. The member belongs to the platform: one a command's
// creator put in the payload is replaced, or removed on every other command.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/contract/secretref"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PayloadKeySecrets is the payload member of a job's secret refs.
const PayloadKeySecrets = secretref.PayloadField

// SecretsGranter lists the secrets a claimed job may use and records them
// for the claim (the task secrets service). cmd is the claimed command as
// it is handed out (egress member already stamped), held by sensorID under
// cmd.LeaseEpoch. An error fails the delivery: the claim is handed back.
type SecretsGranter interface {
	GrantSecrets(ctx context.Context, cmd *commanddom.Command, sensorID shared.ID) (secretref.Set, error)
}

// WithTaskSecrets makes every claimed scan, retest, validate and proxy test
// job carry its secret refs.
func WithTaskSecrets(g SecretsGranter) Option {
	return func(s *Service) { s.secrets = g }
}

// secretBound reports whether a command type may use secrets: the jobs
// that reach targets (and so may run through a proxy pool), and the proxy
// test, which uses its pool's credentials.
func secretBound(t commanddom.CommandType) bool {
	return egressBound(t) || t == commanddom.CommandTypeProxyTest
}

// stampSecrets sets the secrets member on copies of the commands sensorID
// just claimed, or removes one a command's creator put there. The stored
// commands are never changed.
func (s *Service) stampSecrets(ctx context.Context, sensorID string, cmds []*commanddom.Command) ([]*commanddom.Command, error) {
	for i, c := range cmds {
		if c == nil {
			continue
		}
		var set *secretref.Set
		if s.secrets != nil && secretBound(c.Type) && c.SensorID != nil && c.SensorID.String() == sensorID {
			got, err := s.secrets.GrantSecrets(ctx, c, *c.SensorID)
			if err != nil {
				s.logger.Warn("job secrets not granted; command not handed to the sensor",
					"command_id", c.ID.String(), "sensor_id", sensorID, "error", err)
				return nil, fmt.Errorf("job secrets: %w", err)
			}
			set = &got
		}
		// Always decoded, never a byte search: a key spelled with escapes
		// ("\u0073ecrets") is the same member once decoded.
		payload, err := withSecretsPayload(c.Payload, set)
		if err != nil {
			return nil, err
		}
		cp := *c
		cp.Payload = payload
		cmds[i] = &cp
	}
	return cmds, nil
}

// withSecretsPayload sets payload.secrets to set, or removes it when set is
// nil.
func withSecretsPayload(payload json.RawMessage, set *secretref.Set) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(payload) == 0 || string(payload) == jsonNull {
		fields = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(payload, &fields); err != nil {
		if set == nil {
			return payload, nil // not an object: nothing to remove
		}
		return nil, fmt.Errorf("command payload: %w", err)
	}
	found := false
	for k := range fields {
		// The sensor decodes member names without regard to case.
		if strings.EqualFold(k, PayloadKeySecrets) {
			delete(fields, k)
			found = true
		}
	}
	if set == nil {
		if !found {
			return payload, nil
		}
	} else {
		b, err := json.Marshal(set)
		if err != nil {
			return nil, err
		}
		fields[PayloadKeySecrets] = b
	}
	return json.Marshal(fields)
}
