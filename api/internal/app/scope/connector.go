package scope

// Connector inventory is in scope (RFC-054 §14.8, owner decision
// 2026-10-11): the assets a connector syncs are the organization's own
// inventory, so their exact scope entries are added when the connector's
// switch (integration config "inventory_in_scope", on by default) is on.
// The entries go through CreateTargets as a system decision: guardrails and
// the signer ledger apply to each, and the administrators get one notice
// per sync. Off and On scan approval modes only; exclusions and the deny
// list still win at dispatch. An administrator turns the switch off per
// connector.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ConnectorInventoryInScopeKey is the integration config switch.
const ConnectorInventoryInScopeKey = "inventory_in_scope"

// MaxConnectorEntriesPerSync bounds the entries one sync adds; the rest are
// added by the next sync.
const MaxConnectorEntriesPerSync = 1000

// ConnectorIntegrations reads a tenant's integration (*postgres.IntegrationRepository).
type ConnectorIntegrations interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*integration.Integration, error)
}

// SetConnectorIntegrations wires the connector lookup. Without it connector
// inventory is never put in scope.
func (s *Service) SetConnectorIntegrations(r ConnectorIntegrations) { s.connectors = r }

// InventoryInScope reports whether a connector's synced assets are put in
// scope: the switch is on unless set to false.
func InventoryInScope(intg *integration.Integration) bool {
	if intg == nil {
		return false
	}
	v, ok := intg.Config()[ConnectorInventoryInScopeKey].(bool)
	return !ok || v
}

// connectorEntryAssetTypes are what a connector's inventory puts in scope:
// the network types plus hosts (a vulnerability scanner's inventory).
var connectorEntryAssetTypes = map[asset.AssetType]bool{
	asset.AssetTypeDomain:      true,
	asset.AssetTypeSubdomain:   true,
	asset.AssetTypeIPAddress:   true,
	asset.AssetTypeNetwork:     true,
	asset.AssetTypeService:     true,
	asset.AssetTypeApplication: true,
	asset.AssetTypeHost:        true,
}

// ConnectorCoverage is what a sync did to scope.
type ConnectorCoverage struct {
	Added, Covered, Refused int
}

// CoverConnectorAssets adds the exact scope entry of each asset a sync of
// the tenant's connector integrationID wrote that no entry covers. nil when
// the rule does not apply (Strict, the switch off, an unknown or another
// tenant's integration, nothing to add).
func (s *Service) CoverConnectorAssets(ctx context.Context, tenantID, integrationID shared.ID, assetIDs []shared.ID) (*ConnectorCoverage, error) {
	if s.connectors == nil || len(assetIDs) == 0 {
		return nil, nil
	}
	intg, err := s.connectors.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) || errors.Is(err, integration.ErrIntegrationNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("load connector: %w", err)
	}
	if !InventoryInScope(intg) {
		return nil, nil
	}
	p, err := s.loadPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if p.twoPerson() {
		return nil, nil
	}
	reader, ok := s.assetRepo.(assetsByID)
	if !ok {
		return nil, errors.New("scope: asset lookup by id is not wired")
	}
	active, err := s.targetRepo.ListActive(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list scope entries: %w", err)
	}
	out := &ConnectorCoverage{}
	var items []BulkTargetItem
	seen := map[string]bool{}
	now := time.Now()
	for start := 0; start < len(assetIDs) && len(items) < MaxConnectorEntriesPerSync; start += 500 {
		end := min(start+500, len(assetIDs))
		assets, err := reader.GetByIDs(ctx, tenantID, assetIDs[start:end])
		if err != nil {
			return nil, fmt.Errorf("load synced assets: %w", err)
		}
		for _, a := range assets {
			if a == nil || !connectorEntryAssetTypes[asset.CanonicalPair(a.Type(), a.SubType()).Type] {
				continue
			}
			typ, pattern, ok := scopedom.ExactEntryFor(a.Name())
			if !ok {
				continue
			}
			key := string(typ) + ":" + pattern
			if seen[key] {
				continue
			}
			seen[key] = true
			if coveredByAny(active, pattern, now) {
				out.Covered++
				continue
			}
			if len(items) < MaxConnectorEntriesPerSync {
				items = append(items, BulkTargetItem{TargetType: string(typ), Pattern: pattern})
			}
		}
	}
	if len(items) == 0 {
		return nil, nil
	}
	reason := "Synced by connector " + intg.Name()
	for start := 0; start < len(items); start += MaxBulkTargets {
		end := min(start+MaxBulkTargets, len(items))
		outcomes, err := s.CreateTargets(ctx, BulkTargetsInput{
			TenantID: tenantID.String(), Items: items[start:end], Reason: reason, Origin: scopedom.OriginImport,
		})
		if err != nil {
			return nil, err
		}
		for _, o := range outcomes {
			var dup *scopedom.DuplicateError
			switch {
			case o.Err == nil:
				out.Added++
			case errors.As(o.Err, &dup):
				out.Covered++
			default:
				out.Refused++
			}
		}
	}
	if out.Added > 0 {
		s.NotifyAdmins(ctx, tenantID, fmt.Sprintf("%d scope entries added from connector %s", out.Added, intg.Name()),
			"The connector's inventory is in scope; turn this off on the connector if it should not be.")
	}
	return out, nil
}
