package bountyprogram

// The targets a followed public program lists become assets of the
// organization (RFC-065 §16.5), so the passive work of the CTEM loop
// (inventory, vulnerability matching) covers them before anyone accepts the
// terms. An asset the organization already has is never changed here: the
// program assignment pass adds the program link and the system tags, and the
// asset stays the organization's own.

import (
	"context"
	"errors"
	"fmt"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TargetCreator creates the missing assets of a program's exact targets.
type TargetCreator interface {
	EnsureTargets(ctx context.Context, tenantID shared.ID, targets []bp.Planned) (int, error)
}

// SetTargetCreator wires program target assets.
func (s *Service) SetTargetCreator(c TargetCreator) { s.targets = c }

// ensureTargets creates the assets of a followed program's exact names and
// addresses (wildcards and ranges are found by discovery). Best effort: the
// subscription stands; the next feed change retries.
func (s *Service) ensureTargets(ctx context.Context, p *bp.Program, pv *Preview) {
	if s.targets == nil {
		return
	}
	var exact []bp.Planned
	for _, e := range pv.Entries {
		if e.Status == PlanRefused {
			continue
		}
		switch {
		case e.TargetType == scopedom.TargetTypeIPAddress,
			e.TargetType == scopedom.TargetTypeDomain && len(e.Pattern) > 0 && e.Pattern[0] != '*':
			exact = append(exact, bp.Planned{TargetType: e.TargetType, Pattern: e.Pattern})
		}
	}
	if len(exact) == 0 {
		return
	}
	if _, err := s.targets.EnsureTargets(ctx, p.TenantID, exact); err != nil {
		s.log.Warn("program target assets not created", "program_id", p.ID.String(), "error", err)
	}
}

// maxProgramTargets bounds the assets one program creates.
const maxProgramTargets = 500

// AssetTargets creates program target assets through the asset repository.
type AssetTargets struct{ Repo assetdom.Repository }

// EnsureTargets creates the assets the tenant does not have yet.
func (a AssetTargets) EnsureTargets(ctx context.Context, tenantID shared.ID, targets []bp.Planned) (int, error) {
	if len(targets) > maxProgramTargets {
		targets = targets[:maxProgramTargets]
	}
	names := make([]string, 0, len(targets))
	for _, t := range targets {
		names = append(names, t.Pattern)
	}
	have, err := a.Repo.GetByNames(ctx, tenantID, names)
	if err != nil {
		return 0, fmt.Errorf("read assets: %w", err)
	}
	created := 0
	for _, t := range targets {
		if have[t.Pattern] != nil {
			continue
		}
		typ := assetdom.AssetTypeDomain
		if t.TargetType == scopedom.TargetTypeIPAddress {
			typ = assetdom.AssetTypeIPAddress
		}
		x, err := assetdom.NewAssetWithTenant(tenantID, t.Pattern, typ, assetdom.CriticalityMedium)
		if err != nil {
			continue // a name the asset model refuses stays a scope entry only
		}
		x.SetDiscoverySource("program")
		if err := a.Repo.Create(ctx, x); err != nil {
			if errors.Is(err, shared.ErrConflict) || errors.Is(err, shared.ErrAlreadyExists) {
				continue
			}
			return created, fmt.Errorf("create %s: %w", t.Pattern, err)
		}
		created++
	}
	return created, nil
}
