package scan

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
)

// FilteringResult represents the result of smart filtering during scan trigger.
// It shows which assets were scanned vs skipped and why.
type FilteringResult struct {
	// Counts
	TotalAssets        int `json:"total_assets"`
	ScannedAssets      int `json:"scanned_assets"`
	SkippedAssets      int `json:"skipped_assets"`
	UnclassifiedAssets int `json:"unclassified_assets"`

	// Compatibility percentage (0-100)
	CompatibilityPercent float64 `json:"compatibility_percent"`

	// Details by asset type
	ScannedByType map[string]int `json:"scanned_by_type,omitempty"`
	SkippedByType map[string]int `json:"skipped_by_type,omitempty"`

	// Reasons for skipping (for UI display)
	SkipReasons []SkipReason `json:"skip_reasons,omitempty"`

	// Whether any filtering occurred
	WasFiltered bool `json:"was_filtered"`

	// Tool info for context
	ToolName         string   `json:"tool_name,omitempty"`
	SupportedTargets []string `json:"supported_targets,omitempty"`
}

// SkipReason explains why assets of a certain type were skipped.
type SkipReason struct {
	AssetType string `json:"asset_type"`
	Count     int    `json:"count"`
	Reason    string `json:"reason"`
}

// AssetCompatibilityPreview represents a compatibility preview at scan creation.
// This is shown as a warning before the scan is created.
type AssetCompatibilityPreview struct {
	// Whether fully compatible
	IsFullyCompatible bool `json:"is_fully_compatible"`

	// Compatibility percentage (0-100)
	CompatibilityPercent float64 `json:"compatibility_percent"`

	// Counts by compatibility
	CompatibleCount   int `json:"compatible_count"`
	IncompatibleCount int `json:"incompatible_count"`
	UnclassifiedCount int `json:"unclassified_count"`
	TotalCount        int `json:"total_count"`

	// Details
	CompatibleTypes   []string `json:"compatible_types,omitempty"`
	IncompatibleTypes []string `json:"incompatible_types,omitempty"`

	// Human-readable message
	Message string `json:"message"`
}

// AssetFilterService handles smart filtering of assets based on tool compatibility.
type AssetFilterService struct {
	targetMappingRepo tool.TargetMappingRepository
	assetGroupRepo    assetgroup.Repository
}

// NewAssetFilterService creates a new AssetFilterService.
func NewAssetFilterService(
	targetMappingRepo tool.TargetMappingRepository,
	assetGroupRepo assetgroup.Repository,
) *AssetFilterService {
	return &AssetFilterService{
		targetMappingRepo: targetMappingRepo,
		assetGroupRepo:    assetGroupRepo,
	}
}

// PreviewCompatibility checks asset compatibility at scan creation time.
// Returns a preview showing what percentage of assets will be scanned.
func (s *AssetFilterService) PreviewCompatibility(
	ctx context.Context,
	toolTargets []string,
	groupIDs []shared.ID,
) (*AssetCompatibilityPreview, error) {
	if len(groupIDs) == 0 {
		return &AssetCompatibilityPreview{
			IsFullyCompatible:    true,
			CompatibilityPercent: 100,
			Message:              "No asset groups specified",
		}, nil
	}

	// Get all distinct asset types across groups
	var allAssetTypes []string
	var totalCounts = make(map[string]int64)

	for _, groupID := range groupIDs {
		counts, err := s.assetGroupRepo.CountAssetsByType(ctx, groupID)
		if err != nil {
			return nil, fmt.Errorf("count assets by type for group %s: %w", groupID, err)
		}
		for assetType, count := range counts {
			totalCounts[assetType] += count
			// Track unique types
			found := false
			for _, t := range allAssetTypes {
				if t == assetType {
					found = true
					break
				}
			}
			if !found {
				allAssetTypes = append(allAssetTypes, assetType)
			}
		}
	}

	if len(allAssetTypes) == 0 {
		return &AssetCompatibilityPreview{
			IsFullyCompatible:    true,
			CompatibilityPercent: 100,
			Message:              "Asset groups are empty",
		}, nil
	}

	// If tool has no supported targets, skip compatibility check
	if len(toolTargets) == 0 {
		return &AssetCompatibilityPreview{
			IsFullyCompatible:    true,
			CompatibilityPercent: 100,
			Message:              "Tool has no target restrictions",
		}, nil
	}

	// Convert to asset.AssetType for compatibility check
	assetTypes := make([]asset.AssetType, len(allAssetTypes))
	for i, t := range allAssetTypes {
		assetTypes[i] = asset.AssetType(t)
	}

	// Get compatible asset types
	compatibleTypes, err := s.targetMappingRepo.GetCompatibleAssetTypes(ctx, toolTargets, assetTypes)
	if err != nil {
		return nil, fmt.Errorf("get compatible asset types: %w", err)
	}

	// Build sets
	compatibleSet := make(map[string]bool)
	for _, t := range compatibleTypes {
		compatibleSet[string(t)] = true
	}

	// Calculate counts
	var compatibleCount, incompatibleCount, unclassifiedCount int64
	var compatibleTypesList, incompatibleTypesList []string

	for assetType, count := range totalCounts {
		switch {
		case assetType == string(asset.AssetTypeUnclassified):
			unclassifiedCount += count
		case compatibleSet[assetType]:
			compatibleCount += count
			compatibleTypesList = append(compatibleTypesList, assetType)
		default:
			incompatibleCount += count
			incompatibleTypesList = append(incompatibleTypesList, assetType)
		}
	}

	totalCount := compatibleCount + incompatibleCount + unclassifiedCount
	var compatibilityPercent float64
	if totalCount > 0 {
		compatibilityPercent = float64(compatibleCount) / float64(totalCount) * 100
	}

	isFullyCompatible := incompatibleCount == 0 && unclassifiedCount == 0

	// Build message
	var message string
	switch {
	case isFullyCompatible:
		message = fmt.Sprintf("All %d assets are compatible with this scanner", totalCount)
	case compatibleCount == 0:
		message = fmt.Sprintf("No assets are compatible. %d assets will be skipped", totalCount)
	default:
		message = fmt.Sprintf("%.0f%% compatible: %d assets will be scanned, %d will be skipped",
			compatibilityPercent, compatibleCount, incompatibleCount+unclassifiedCount)
	}

	return &AssetCompatibilityPreview{
		IsFullyCompatible:    isFullyCompatible,
		CompatibilityPercent: compatibilityPercent,
		CompatibleCount:      int(compatibleCount),
		IncompatibleCount:    int(incompatibleCount),
		UnclassifiedCount:    int(unclassifiedCount),
		TotalCount:           int(totalCount),
		CompatibleTypes:      compatibleTypesList,
		IncompatibleTypes:    incompatibleTypesList,
		Message:              message,
	}, nil
}

// FilterAssetsForScan filters assets based on tool compatibility.
// Returns the filtering result showing what was scanned vs skipped.
func (s *AssetFilterService) FilterAssetsForScan(
	ctx context.Context,
	toolTargets []string,
	toolName string,
	assetTypeCounts map[string]int64,
) (*FilteringResult, error) {
	result := &FilteringResult{
		ToolName:         toolName,
		SupportedTargets: toolTargets,
		ScannedByType:    make(map[string]int),
		SkippedByType:    make(map[string]int),
	}

	// If no assets, return empty result
	if len(assetTypeCounts) == 0 {
		return result, nil
	}

	// Calculate total
	for _, count := range assetTypeCounts {
		result.TotalAssets += int(count)
	}

	// If tool has no supported targets, scan all
	if len(toolTargets) == 0 {
		result.ScannedAssets = result.TotalAssets
		result.CompatibilityPercent = 100
		for assetType, count := range assetTypeCounts {
			result.ScannedByType[assetType] = int(count)
		}
		return result, nil
	}

	// Get all asset types
	assetTypes := make([]asset.AssetType, 0, len(assetTypeCounts))
	for t := range assetTypeCounts {
		assetTypes = append(assetTypes, asset.AssetType(t))
	}

	// Get compatible types
	compatibleTypes, err := s.targetMappingRepo.GetCompatibleAssetTypes(ctx, toolTargets, assetTypes)
	if err != nil {
		return nil, fmt.Errorf("get compatible types: %w", err)
	}

	compatibleSet := make(map[string]bool)
	for _, t := range compatibleTypes {
		compatibleSet[string(t)] = true
	}

	// Categorize
	for assetType, count := range assetTypeCounts {
		intCount := int(count)

		switch {
		case assetType == string(asset.AssetTypeUnclassified):
			result.UnclassifiedAssets += intCount
			result.SkippedAssets += intCount
			result.SkippedByType[assetType] = intCount
			result.SkipReasons = append(result.SkipReasons, SkipReason{
				AssetType: assetType,
				Count:     intCount,
				Reason:    "Unclassified assets cannot be matched to scanner targets",
			})
		case compatibleSet[assetType]:
			result.ScannedAssets += intCount
			result.ScannedByType[assetType] = intCount
		default:
			result.SkippedAssets += intCount
			result.SkippedByType[assetType] = intCount
			result.SkipReasons = append(result.SkipReasons, SkipReason{
				AssetType: assetType,
				Count:     intCount,
				Reason:    fmt.Sprintf("Asset type '%s' is not compatible with scanner targets %v", assetType, toolTargets),
			})
		}
	}

	// Calculate compatibility percent
	if result.TotalAssets > 0 {
		result.CompatibilityPercent = float64(result.ScannedAssets) / float64(result.TotalAssets) * 100
	}

	result.WasFiltered = result.SkippedAssets > 0

	return result, nil
}
