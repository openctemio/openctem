package scan

// "Scan now" with a connector (research/143 §5; architecture:
// docs/architecture/tenable-sc-connector.md): a member scans chosen
// inventory assets through a Tenable.sc connector, for example to rescan the
// asset of a finding after a fix. The run is an ordinary manual run of one
// hidden scan per connector, so the act scope, the active-probe gate, scan
// windows and scan approval apply exactly as for any scan.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ConnectorOnDemandTag marks the hidden scans that carry on-demand connector
// runs.
const ConnectorOnDemandTag = "tenable-on-demand"

// MaxConnectorScanNowAssets bounds one on-demand connector scan.
const MaxConnectorScanNowAssets = 50

// connectorToolName is the connector scanner (tenablesc.ToolName).
const connectorToolName = "tenable_sc"

// ConnectorOnDemandScanName is the hidden scan of a connector's on-demand
// runs.
func ConnectorOnDemandScanName(integrationName string) string {
	return "Tenable.sc on demand: " + integrationName
}

// ConnectorScanNowInput is a member's request to scan assets with a
// connector now.
type ConnectorScanNowInput struct {
	TenantID      shared.ID
	UserID        shared.ID
	IntegrationID shared.ID
	AssetIDs      []shared.ID
}

// ErrConnectorAssetsNotFound is the one answer for an asset the caller may
// not scan: unknown, another tenant's, deleted or outside their data scope.
var ErrConnectorAssetsNotFound = fmt.Errorf("%w: one or more assets do not exist or are not in your scope", shared.ErrNotFound)

// ErrOnDemandScanNameTaken: a scan that is not the connector's on-demand scan
// already has its name.
var ErrOnDemandScanNameTaken = shared.NewDomainError("ON_DEMAND_SCAN_NAME_TAKEN",
	"a scan named like this connector's on-demand scan already exists; rename that scan to scan assets with this connector",
	shared.ErrConflict)

// StartConnectorScan scans the assets now with the connector integration:
// each asset (tenant-scoped, in the caller's data scope, else not found) is
// scanned by its name with the connector's coverage policy, repository and
// zone, as a manual run by the user of the connector's hidden on-demand scan.
func (s *Service) StartConnectorScan(ctx context.Context, in ConnectorScanNowInput) (*scanrun.Run, error) {
	if in.TenantID.IsZero() || in.UserID.IsZero() || in.IntegrationID.IsZero() {
		return nil, fmt.Errorf("%w: tenant, user and integration are required", shared.ErrValidation)
	}
	ids := dedupeIDs(in.AssetIDs)
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: asset_ids names no asset", shared.ErrValidation)
	}
	if len(ids) > MaxConnectorScanNowAssets {
		return nil, fmt.Errorf("%w: at most %d assets per scan", shared.ErrValidation, MaxConnectorScanNowAssets)
	}
	if s.connectorScans == nil {
		return nil, ErrConnectorScansUnavailable
	}
	// Without the act-scope check the data scope could not be enforced:
	// refuse rather than scan unchecked.
	if s.actScope == nil {
		return nil, fmt.Errorf("%w: the scan scope check is not available", shared.ErrForbidden)
	}

	name, cfg, err := s.connectorScans.OnDemandScanConfig(ctx, in.TenantID, in.IntegrationID)
	if err != nil {
		return nil, err
	}
	raw := make([]string, 0, len(ids))
	for _, id := range ids {
		raw = append(raw, id.String())
	}
	user := in.UserID
	targets, err := s.resolveAssetTargets(ctx, in.TenantID, &user, raw)
	if err != nil {
		if errors.Is(err, errScanAssetsUnavailable) {
			return nil, ErrConnectorAssetsNotFound
		}
		return nil, err
	}

	sc, err := s.connectorOnDemandScan(ctx, in.TenantID, in.IntegrationID, name, cfg, false)
	if err != nil {
		return nil, err
	}
	// The targets go to this run only: the stored scan keeps none, so two
	// members scanning at once never trade targets, and the hidden scan
	// shows nobody another member's assets.
	sc.SetTargets(targets)
	return s.triggerAndRecord(ctx, sc, TriggerScanExecInput{
		TenantID:    in.TenantID.String(),
		ScanID:      sc.ID.String(),
		TriggeredBy: in.UserID.String(),
		Interactive: true,
		Context: map[string]any{
			"trigger":        "connector_scan_now",
			"integration_id": in.IntegrationID.String(),
			"target_count":   len(targets),
		},
	})
}

// connectorOnDemandScan returns the connector's hidden on-demand scan with
// cfg as its scanner config, creating it on first use (ad hoc, hidden from
// the configurations list, like the coverage scans).
func (s *Service) connectorOnDemandScan(ctx context.Context, tenantID, integrationID shared.ID, integrationName string,
	cfg map[string]any, retried bool) (*scan.Scan, error) {
	name := ConnectorOnDemandScanName(integrationName)
	sc, err := s.scanRepo.GetByName(ctx, tenantID, name)
	switch {
	case err == nil:
		if !sc.AdHoc || !hasTag(sc.Tags, ConnectorOnDemandTag) || sc.ScannerName != connectorToolName ||
			fmt.Sprint(sc.ScannerConfig["integration_id"]) != integrationID.String() {
			return nil, ErrOnDemandScanNameTaken
		}
		if err := s.configureSingleScan(ctx, sc, connectorToolName, cfg, 1); err != nil {
			return nil, err
		}
		sc.SetTargets(nil)
		if err := s.scanRepo.Update(ctx, sc); err != nil {
			return nil, fmt.Errorf("failed to update the on-demand scan: %w", err)
		}
		return sc, nil
	case !errors.Is(err, shared.ErrNotFound):
		return nil, fmt.Errorf("load the on-demand scan: %w", err)
	}
	sc, err = scan.NewScan(tenantID, name, shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}
	sc.AdHoc = true
	sc.Description = "Assets scanned now with the Tenable.sc connector " + integrationName
	sc.SetTags([]string{ConnectorOnDemandTag})
	if err := s.configureSingleScan(ctx, sc, connectorToolName, cfg, 1); err != nil {
		return nil, err
	}
	if err := s.scanRepo.Create(ctx, sc); err != nil {
		if errors.Is(err, shared.ErrAlreadyExists) && !retried {
			// Another request created it a moment ago: use that one.
			return s.connectorOnDemandScan(ctx, tenantID, integrationID, integrationName, cfg, true)
		}
		return nil, fmt.Errorf("failed to create the on-demand scan: %w", err)
	}
	return sc, nil
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}
