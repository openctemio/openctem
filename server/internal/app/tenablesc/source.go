package tenablesc

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ConnectorSource names the source a connector integration of the tenant
// imports through: its sensor and the connector's tool
// (docs/architecture/source-retirement.md). Another tenant's integration,
// one that is not a connector, or one without a sensor is
// shared.ErrNotFound.
func (s *Service) ConnectorSource(ctx context.Context, tenantID, integrationID shared.ID) (sensorID shared.ID, tool, name string, err error) {
	intg, err := s.integrations.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		return shared.ID{}, "", "", err
	}
	if !IsConnector(intg) || intg.TenantID() != tenantID {
		return shared.ID{}, "", "", shared.ErrNotFound
	}
	cfg, err := ParseConnectorConfig(intg)
	if err != nil || cfg.SensorID.IsZero() {
		return shared.ID{}, "", "", shared.ErrNotFound
	}
	return cfg.SensorID, ToolName, intg.Name(), nil
}
