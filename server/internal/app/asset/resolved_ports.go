package asset

// Ports on resolved addresses: a port scan of a host name stores each open
// port on the address it was found on (name -resolves_to-> address
// -exposes-> "<address>:<port>"), so the name's page reads them through
// those relations. Docs: docs/architecture/easm.md ("Ports of a name").

import (
	"context"
	"fmt"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// resolvedPortsLimit caps the ports one name's page lists.
const resolvedPortsLimit = 200

// SetResolvedPorts wires the reader of a name's resolved ports. Unset, a
// name lists none.
func (s *AssetService) SetResolvedPorts(r assetdom.ResolvedPortReader) { s.resolvedPorts = r }

// GetResolvedPorts returns the open ports of the addresses a domain or
// subdomain resolves to. The asset must be one the caller may see (another
// tenant's or one outside the caller's data scope is not found); each
// address and port is filtered by the caller's data scope as well, and the
// ones left out are only counted. Other asset types have none.
func (s *AssetService) GetResolvedPorts(ctx context.Context, tenantID, assetID string) (*assetdom.ResolvedPorts, error) {
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	empty := &assetdom.ResolvedPorts{Items: []assetdom.ResolvedPort{}}
	if s.resolvedPorts == nil || (a.Type() != assetdom.AssetTypeDomain && a.Type() != assetdom.AssetTypeSubdomain) {
		return empty, nil
	}
	var scope *shared.DataScope
	if s.dataScope != nil {
		if scope, err = s.dataScope.Resolve(ctx, a.TenantID()); err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
	}
	res, err := s.resolvedPorts.ResolvedPorts(ctx, a.TenantID(), a.ID(), scope, resolvedPortsLimit)
	if err != nil {
		return nil, fmt.Errorf("list resolved ports: %w", err)
	}
	return res, nil
}
