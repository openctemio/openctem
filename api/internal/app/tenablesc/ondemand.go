package tenablesc

// On-demand scans of chosen assets through a connector ("scan this asset",
// "rescan after a fix"; research/143 §5): the scan service runs them as a
// connector scan, with the Tenable.sc policy, repository and zone the
// connector's rolling coverage uses.

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrOnDemandNeedsCoverageConfig: the connector has no coverage policy and
// repository to scan with.
var ErrOnDemandNeedsCoverageConfig = shared.NewDomainError("CONNECTOR_SCAN_CONFIG_MISSING",
	"set the coverage scan policy and repository on this Tenable.sc connector (coverage_policy_id and coverage_repository_id) before scanning assets with it",
	shared.ErrValidation)

// OnDemandScanConfig returns the connector integration's name and the
// scanner_config of an on-demand scan with it: the integration and its
// coverage_policy_id, coverage_repository_id, coverage_zone_id and
// coverage_max_scan_seconds. Read tenant-scoped: another tenant's
// integration, or one that is not a connector, is not found.
func (s *Service) OnDemandScanConfig(ctx context.Context, tenantID, integrationID shared.ID) (string, map[string]any, error) {
	intg, err := s.integrations.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		return "", nil, err
	}
	if !IsConnector(intg) {
		return "", nil, shared.ErrNotFound
	}
	cfg := intg.Config()
	for _, k := range []string{"coverage_policy_id", "coverage_repository_id"} {
		if v, ok := cfg[k]; !ok || v == nil || v == "" {
			return "", nil, ErrOnDemandNeedsCoverageConfig
		}
	}
	m, err := coverageScanConfig(intg)
	if err != nil {
		var de *shared.DomainError
		if errors.As(err, &de) {
			return "", nil, invalid("the connector's coverage scan settings are not valid: " + de.Message)
		}
		return "", nil, err
	}
	return intg.Name(), m, nil
}
