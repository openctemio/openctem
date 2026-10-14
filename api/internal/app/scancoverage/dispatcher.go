package scancoverage

import (
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DispatchTenableInput describes one coverage batch. Since RFC-047 the
// dispatcher is the Tenable.sc connector (cmd/server
// connectorCoverageDispatcher): the batch becomes a connector_scan of
// IntegrationID, pinned to the connector's sensor, which holds the Tenable.sc
// credentials; the control plane never does.
type DispatchTenableInput struct {
	TenantID shared.ID
	// IntegrationID is the integration that runs the batch (the Tenable.sc
	// connector, RFC-047), or nil.
	IntegrationID *shared.ID
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
	// NewAddresses is how many addresses the batch may add to the license
	// count (the sensor's license guard checks Tenable.sc has them free).
	NewAddresses int
}

// BatchSettlement is how a license-aware coverage batch ended, per target
// (research/143 §3.3): the targets it assessed, those that did not reply,
// those it never finished (back to due, no failure counted) and those that
// failed with the batch (Error says why). Targets are the batch command's
// own, read against its payload.
type BatchSettlement struct {
	Done, Unreachable, Unfinished, Failed []string
	Error                                 string
}
