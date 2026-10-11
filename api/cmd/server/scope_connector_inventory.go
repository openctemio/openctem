package main

// Connector inventory into scope (RFC-054 §14.8): the ingest hook resolves
// which connector a sync report belongs to, from the server side only, and
// hands the assets it wrote to the scope service in the background.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// connectorCommands reads a tenant's command (*postgres.CommandRepository).
type connectorCommands interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*command.Command, error)
}

const connectorInventoryTimeout = 2 * time.Minute

// connectorInventoryHook builds the ingest hook. The integration of a
// connector_sync command is read from the payload the platform wrote; the
// scope service checks it is the tenant's and its switch is on.
func connectorInventoryHook(commands connectorCommands, svc *scope.Service, log *logger.Logger) ingest.ConnectorInventoryHook {
	return func(ctx context.Context, tenantID shared.ID, commandID, integrationID *shared.ID, assetIDs []shared.ID) {
		ids := append([]shared.ID(nil), assetIDs...)
		go func() {
			bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), connectorInventoryTimeout)
			defer cancel()
			intg := integrationID
			if intg == nil && commandID != nil {
				cmd, err := commands.GetByTenantAndID(bg, tenantID, *commandID)
				if err != nil || cmd == nil || cmd.Type != command.CommandTypeConnectorSync {
					return
				}
				var p struct {
					IntegrationID string `json:"integration_id"`
				}
				if json.Unmarshal(cmd.Payload, &p) != nil {
					return
				}
				id, err := shared.IDFromString(p.IntegrationID)
				if err != nil {
					return
				}
				intg = &id
			}
			if intg == nil {
				return
			}
			out, err := svc.CoverConnectorAssets(bg, tenantID, *intg, ids)
			if err != nil {
				log.Warn("connector inventory: scope entries not added", "tenant_id", tenantID.String(),
					"integration_id", intg.String(), "error", logger.SanitizeError(err))
				return
			}
			if out != nil && out.Added > 0 {
				log.Info("connector inventory: scope entries added", "tenant_id", tenantID.String(),
					"integration_id", intg.String(), "added", out.Added, "covered", out.Covered, "refused", out.Refused)
			}
		}()
	}
}
