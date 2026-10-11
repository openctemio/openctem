package ingest

// What a connector's sync wrote, for "connector inventory is in scope"
// (RFC-054 §14.8): the assets a report of a connector sync created or
// updated are handed to a hook that adds their exact scope entries when the
// connector's switch is on. The connector comes from the server side only:
// a report bound to a connector_sync command (the integration is read from
// the command the platform wrote), or a trusted server-side ingest that
// names its integration (Options.IntegrationID). A sensor report never says
// which connector it is.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ConnectorInventoryHook is told which assets a connector sync wrote: the
// bound connector_sync command (commandID) or the integration a trusted
// ingest named (integrationID); exactly one is set.
type ConnectorInventoryHook func(ctx context.Context, tenantID shared.ID, commandID, integrationID *shared.ID, assetIDs []shared.ID)

// SetConnectorInventoryHook wires the hook. Nil-safe.
func (s *Service) SetConnectorInventoryHook(h ConnectorInventoryHook) { s.connectorInventory = h }

// recordConnectorInventory calls the hook for a connector sync's report.
// Best-effort: the hook runs after the ingest committed what it wrote.
func (s *Service) recordConnectorInventory(ctx context.Context, tenantID shared.ID, binding Binding, opts Options, scope *alterScope) {
	if s.connectorInventory == nil || scope == nil || len(scope.seen) == 0 {
		return
	}
	var commandID, integrationID *shared.ID
	switch {
	case binding.Kind == BindingCommand && binding.CommandType == command.CommandTypeConnectorSync && binding.CommandID != nil:
		commandID = binding.CommandID
	case binding.Kind == BindingTrusted && opts.IntegrationID != nil && !opts.IntegrationID.IsZero():
		integrationID = opts.IntegrationID
	default:
		return
	}
	ids := make([]shared.ID, 0, len(scope.seen))
	for id := range scope.seen {
		ids = append(ids, id)
	}
	s.connectorInventory(ctx, tenantID, commandID, integrationID, ids)
}
