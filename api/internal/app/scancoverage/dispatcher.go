package scancoverage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CommandCreator persists sensor commands. It is the subset of
// command.Repository the dispatcher needs (kept narrow for testability).
type CommandCreator interface {
	Create(ctx context.Context, cmd *command.Command) error
}

// DispatchTenableInput describes one Tenable coverage batch to dispatch to a
// runner. The runner is an OpenCTEM sensor with capability `infra` + tool
// `tenable` (RFC-007 §3.10); it holds the appliance credentials locally and the
// control plane never does.
type DispatchTenableInput struct {
	TenantID shared.ID
	// Targets are the IPs/CIDRs/hostnames in this batch.
	Targets []string
	// SessionID scopes auto-resolve to this batch (tool + session + assets).
	// Generated if empty.
	SessionID string
	// SensorID optionally pins a specific runner (C3). Nil → any tenable-capable
	// sensor picks it up via capability routing.
	SensorID *shared.ID
	// Engine is informational ("nessus_pro" | "tenable_sc"); the runner uses its
	// local engine config.
	Engine string
	// TemplateUUID optionally overrides the runner's default Nessus template.
	TemplateUUID string
	// ScanZoneID is the scan zone the targets route to, or nil. A zoned
	// command is claimable only by that zone's sensors.
	ScanZoneID *shared.ID
}

// Dispatcher creates Tenable scan commands routed to a tenable-capable runner.
type Dispatcher struct {
	commands CommandCreator
}

// NewDispatcher builds a Dispatcher.
func NewDispatcher(commands CommandCreator) *Dispatcher {
	return &Dispatcher{commands: commands}
}

// DispatchTenableScan enqueues a scan command for a Tenable runner and returns
// the command ID and the (possibly generated) scan session id.
//
// The command is a generic scan command whose payload carries scanner="tenable"
// (the discriminator the sensor routes on), the target batch, the coverage
// session id, and the required capability. The runner picks it up via poll,
// scans its LOCAL appliance, and pushes CTIS back.
func (d *Dispatcher) DispatchTenableScan(ctx context.Context, in DispatchTenableInput) (cmdID shared.ID, sessionID string, err error) {
	if in.TenantID.IsZero() {
		return shared.ID{}, "", fmt.Errorf("%w: tenant id required", shared.ErrValidation)
	}
	if len(in.Targets) == 0 {
		return shared.ID{}, "", fmt.Errorf("%w: at least one target required", shared.ErrValidation)
	}

	sessionID = in.SessionID
	if sessionID == "" {
		sessionID = shared.NewID().String()
	}

	payload, err := json.Marshal(map[string]any{
		"scanner":               "tenable",
		"tool":                  "tenable",
		"required_capabilities": []string{"infra"},
		"targets":               in.Targets,
		"session_id":            sessionID,
		"engine":                in.Engine,
		"template_uuid":         in.TemplateUUID,
	})
	if err != nil {
		return shared.ID{}, "", fmt.Errorf("marshal payload: %w", err)
	}

	cmd, err := command.NewCommand(in.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		return shared.ID{}, "", err
	}
	if in.SensorID != nil && !in.SensorID.IsZero() {
		cmd.SensorID = in.SensorID // C3: pin a specific runner
	}
	if in.ScanZoneID != nil {
		cmd.SetScanZone(*in.ScanZoneID)
	}

	if err := d.commands.Create(ctx, cmd); err != nil {
		return shared.ID{}, "", fmt.Errorf("create command: %w", err)
	}
	return cmd.ID, sessionID, nil
}
