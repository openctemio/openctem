package command

// Tool settings in the job (docs/architecture/sensors.md, "Tool settings"):
// when a sensor claims a scan job, the administrators' values for the job's
// tool go into the payload as settings_layers, before the job is signed, so
// the signature covers them: "tenant" is the organization's defaults the
// sensor inherits (only for the tenant's own sensors, without the keys the
// sensor overrides) and "sensor" the sensor's own values. The sensor
// validates and resolves the layers with its own copy of the settings
// contract.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ToolSettingsSource answers the administrators' layers of a job: the
// organization's defaults the sensor inherits and the sensor's stored values
// of tool (each nil when empty), checked against the sensor's current
// settings schema. An error wrapping sensordom.ErrToolSettingsInvalid means
// the values no longer validate; any other error is transient.
// (*sensor.SensorService).
type ToolSettingsSource interface {
	ToolSettingsLayers(ctx context.Context, tenantID, sensorID shared.ID, tool string) (tenant, sensor map[string]any, err error)
}

// settingsLayers are the layers of one command's payload.
type settingsLayers struct {
	Tenant map[string]any `json:"tenant,omitempty"`
	Sensor map[string]any `json:"sensor,omitempty"`
}

func (l settingsLayers) empty() bool { return len(l.Tenant) == 0 && len(l.Sensor) == 0 }

// WithToolSettings makes Poll and Claim carry each sensor's tool settings
// in its scan jobs.
func WithToolSettings(src ToolSettingsSource) Option {
	return func(s *Service) { s.toolSettings = src }
}

// FailureToolSettingsInvalid is the failure code of a job whose sensor's
// stored settings for the tool no longer validate.
const FailureToolSettingsInvalid = "TOOL_SETTINGS_INVALID"

// settingsLayersField is the payload member that carries the layers.
const settingsLayersField = "settings_layers"

// ErrToolSettingsInvalidAtClaim: the sensor's stored settings for the job's
// tool no longer validate, so the job was failed. It reads as "claimed".
var ErrToolSettingsInvalidAtClaim = fmt.Errorf("%w (%w): the sensor's settings for this tool no longer validate; the job was failed",
	ErrCommandClaimed, shared.ErrConflict)

// ErrToolSettingsUnavailable: the sensor's tool settings could not be read.
// It reads as "claimed"; the command stays pending for a later claim.
var ErrToolSettingsUnavailable = fmt.Errorf("%w (%w): the sensor's tool settings could not be read; try later",
	ErrCommandClaimed, shared.ErrConflict)

// settingsHold looks up the sensor layer of each scan command before it is
// claimed: kept (with its layer, if any), withheld when the settings could
// not be read (it stays pending), or failed when they no longer validate
// (refused rather than run without them).
func (s *Service) settingsHold(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, cmds []*commanddom.Command) ([]*commanddom.Command, map[shared.ID]settingsLayers) {
	if s.toolSettings == nil || sensorID == nil || len(cmds) == 0 {
		return cmds, nil
	}
	layers := map[shared.ID]settingsLayers{}
	out := cmds[:0:0]
	for _, c := range cmds {
		if !c.TenantID.Equals(tenantID) {
			out = append(out, c) // never decided across tenants; the poll is tenant-scoped
			continue
		}
		layer, err := s.settingsDecide(ctx, *sensorID, c)
		if err != nil {
			continue
		}
		if !layer.empty() {
			layers[c.ID] = layer
		}
		out = append(out, c)
	}
	return out, layers
}

// settingsHoldOne is settingsHold for the claim by id.
func (s *Service) settingsHoldOne(ctx context.Context, sensorID shared.ID, c *commanddom.Command) (settingsLayers, error) {
	if s.toolSettings == nil {
		return settingsLayers{}, nil
	}
	return s.settingsDecide(ctx, sensorID, c)
}

// settingsDecide returns the layers of one command (empty: none), or
// ErrToolSettingsInvalidAtClaim (the command was failed) or
// ErrToolSettingsUnavailable (withheld).
func (s *Service) settingsDecide(ctx context.Context, sensorID shared.ID, c *commanddom.Command) (settingsLayers, error) {
	if c.Type != commanddom.CommandTypeScan {
		return settingsLayers{}, nil
	}
	tool := sensordom.NormalizeToolName(commanddom.PayloadTool(c.Payload))
	if tool == "" {
		return settingsLayers{}, nil
	}
	tenant, sensor, err := s.toolSettings.ToolSettingsLayers(ctx, c.TenantID, sensorID, tool)
	switch {
	case errors.Is(err, sensordom.ErrToolSettingsInvalid):
		s.failAtClaim(ctx, c, truncateUTF8(FailureToolSettingsInvalid+": "+err.Error(), MaxFailErrorMessageBytes), FailureToolSettingsInvalid)
		return settingsLayers{}, ErrToolSettingsInvalidAtClaim
	case err != nil:
		s.logger.Warn("tool settings could not be read; withholding the job",
			"command_id", c.ID.String(), "sensor_id", sensorID.String(), "error", err)
		return settingsLayers{}, ErrToolSettingsUnavailable
	}
	return settingsLayers{Tenant: tenant, Sensor: sensor}, nil
}

// withToolSettings sets each command's settings_layers to its layers, or
// removes a settings_layers its creator put there, on copies: the stored
// command is never changed.
func withToolSettings(cmds []*commanddom.Command, layers map[shared.ID]settingsLayers) ([]*commanddom.Command, error) {
	for i, c := range cmds {
		layer := layers[c.ID]
		if layer.empty() && !bytes.Contains(c.Payload, []byte(`"`+settingsLayersField+`"`)) {
			continue
		}
		payload, err := withSettingsLayers(c.Payload, layer)
		if err != nil {
			return nil, err
		}
		cp := *c
		cp.Payload = payload
		cmds[i] = &cp
	}
	return cmds, nil
}

// withSettingsLayers sets payload.settings_layers to the layers, or removes
// it when they are empty.
func withSettingsLayers(payload json.RawMessage, layer settingsLayers) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(payload) == 0 || string(payload) == jsonNull {
		fields = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(payload, &fields); err != nil {
		if layer.empty() {
			return payload, nil // not an object: nothing to remove
		}
		return nil, fmt.Errorf("scan command payload: %w", err)
	}
	if layer.empty() {
		if _, ok := fields[settingsLayersField]; !ok {
			return payload, nil
		}
		delete(fields, settingsLayersField)
	} else {
		b, err := json.Marshal(layer)
		if err != nil {
			return nil, err
		}
		fields[settingsLayersField] = b
	}
	return json.Marshal(fields)
}
