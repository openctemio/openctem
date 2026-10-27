package scan

// Changing a saved scan's targets. An edit's new targets pass every gate a
// new scan's targets pass, as the editor: target validation (no internal or
// loopback address outside a scan zone), the editor's act scope, ownership
// for active scanning, intrusive proof and the scope tier ceiling; asset
// groups must be the tenant's. The approval of a governed scan covers its
// definition, targets included, so a changed scan needs approving again.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// targetsChanged reports whether an update names new targets or groups.
func (in UpdateScanInput) targetsChanged() bool {
	return in.Targets != nil || in.AssetIDs != nil || in.AssetGroupIDs != nil
}

// applyTargetEdit replaces sc's direct targets (Targets plus the assets of
// AssetIDs, when either is given) and its asset groups (when AssetGroupIDs
// is given), refusing anything a new scan with them would be refused. sc
// keeps its scanner settings: call it after the scanner or workflow edit.
func (s *Service) applyTargetEdit(ctx context.Context, sc *scan.Scan, in UpdateScanInput) error {
	tenantID := sc.TenantID
	actor := userIDPtr(in.ActorID)

	targets := sc.Targets
	if in.Targets != nil || in.AssetIDs != nil {
		var typed []string
		if in.Targets != nil {
			typed = *in.Targets
		}
		assetTargets, err := s.resolveAssetTargets(ctx, tenantID, actor, in.AssetIDs)
		if err != nil {
			return err
		}
		merged, err := mergeDirectTargets(typed, assetTargets)
		if err != nil {
			return err
		}
		probe := CreateScanInput{TenantID: tenantID.String(), Targets: merged}
		validated, err := s.validateScanTargets(ctx, probe)
		if err != nil {
			return err
		}
		if err := s.refuseOutOfActScope(ctx, tenantID, actor, validated); err != nil {
			return err
		}
		if err := s.refuseUnownedTargets(s.withScanPlacement(ctx, sc), tenantID, "scan_update", validated, IsTakeoverOnlyProbe(sc.ScannerName, sc.ScannerConfig)); err != nil {
			return err
		}
		if err := s.refuseUnprovenIntrusive(ctx, tenantID, sc.ScannerName, validated); err != nil {
			return err
		}
		if err := s.refuseTierExceeded(ctx, tenantID, sc.ScannerName, validated); err != nil {
			return err
		}
		targets = validated
	}

	groupID, groupIDs := sc.AssetGroupID, sc.AssetGroupIDs
	if in.AssetGroupIDs != nil {
		var err error
		groupID, groupIDs, err = s.validateScanAssetGroups(ctx, tenantID, CreateScanInput{
			TenantID: tenantID.String(), AssetGroupIDs: *in.AssetGroupIDs,
		})
		if err != nil {
			return err
		}
	}

	if len(targets) == 0 && groupID.IsZero() && len(groupIDs) == 0 {
		return fmt.Errorf("%w: a scan needs targets, assets or an asset group", shared.ErrValidation)
	}

	sc.SetTargets(targets)
	if in.AssetGroupIDs != nil {
		// Replaced whole, the legacy primary group included (it is the
		// first of the list, or none).
		sc.AssetGroupID = groupID
		sc.SetAssetGroupIDs(groupIDs)
	}
	// Targets skipped when the scan was saved no longer describe it.
	if in.Targets != nil || in.AssetIDs != nil {
		sc.SkippedTargets = nil
	}
	return nil
}
