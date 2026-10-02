package app

// Compatibility shim — real impl lives in internal/app/asset/.
// 10 files: asset, asset_group, asset_import, asset_relationship,
// asset_type, branch, business_unit, component, sbom_import,
// relationship_suggestion.

import "github.com/openctemio/api/internal/app/asset"

type (
	AssetService                  = asset.AssetService
	AssetGroupService             = asset.AssetGroupService
	AssetImportService            = asset.AssetImportService
	AssetRelationshipService      = asset.AssetRelationshipService
	AssetTypeService              = asset.AssetTypeService
	BranchService                 = asset.BranchService
	BusinessUnitService           = asset.BusinessUnitService
	ComponentService              = asset.ComponentService
	RelationshipSuggestionService = asset.RelationshipSuggestionService
	SBOMImportService             = asset.SBOMImportService

	AssetImportResult                   = asset.AssetImportResult
	BatchCreateRelationshipInput        = asset.BatchCreateRelationshipInput
	BatchCreateRelationshipResult       = asset.BatchCreateRelationshipResult
	BatchCreateRelationshipResultItem   = asset.BatchCreateRelationshipResultItem
	BatchCreateRelationshipResultStatus = asset.BatchCreateRelationshipResultStatus
	BulkAssetStatusResult               = asset.BulkAssetStatusResult
	BulkUpdateAssetStatusInput          = asset.BulkUpdateAssetStatusInput
	BulkUpdateInput                     = asset.BulkUpdateInput
	CreateAssetGroupInput               = asset.CreateAssetGroupInput
	CreateAssetInput                    = asset.CreateAssetInput
	CreateBranchInput                   = asset.CreateBranchInput
	CreateBusinessUnitInput             = asset.CreateBusinessUnitInput
	CreateComponentInput                = asset.CreateComponentInput
	CreateRelationshipInput             = asset.CreateRelationshipInput
	CreateRepositoryAssetInput          = asset.CreateRepositoryAssetInput
	K8sDiscoveryInput                   = asset.K8sDiscoveryInput
	K8sNamespace                        = asset.K8sNamespace
	K8sWorkload                         = asset.K8sWorkload
	ListAssetGroupsInput                = asset.ListAssetGroupsInput
	ListAssetGroupsOutput               = asset.ListAssetGroupsOutput
	ListAssetsInput                     = asset.ListAssetsInput
	ListBranchesInput                   = asset.ListBranchesInput
	ListComponentsInput                 = asset.ListComponentsInput
	RelationshipTypeUsage               = asset.RelationshipTypeUsage
	RiskScorePreviewItem                = asset.RiskScorePreviewItem
	SBOMImportResult                    = asset.SBOMImportResult
	UpdateAssetGroupInput               = asset.UpdateAssetGroupInput
	UpdateAssetInput                    = asset.UpdateAssetInput
	UpdateBranchInput                   = asset.UpdateBranchInput
	UpdateBranchScanStatusInput         = asset.UpdateBranchScanStatusInput
	UpdateBusinessUnitInput             = asset.UpdateBusinessUnitInput
	UpdateComponentInput                = asset.UpdateComponentInput
	UpdateRelationshipInput             = asset.UpdateRelationshipInput
	UpdateRepositoryExtensionInput      = asset.UpdateRepositoryExtensionInput
	UserMatcher                         = asset.UserMatcher
)

const (
	BatchCreateStatusCreated   = asset.BatchCreateStatusCreated
	BatchCreateStatusDuplicate = asset.BatchCreateStatusDuplicate
	BatchCreateStatusError     = asset.BatchCreateStatusError
)

type (
	TenantScoringConfigProvider = asset.TenantScoringConfigProvider
)

var (
	NewTenantScoringConfigProvider   = asset.NewTenantScoringConfigProvider
	MapTenantToAssetScoringConfig    = asset.MapTenantToAssetScoringConfig
	NewAssetService                  = asset.NewAssetService
	NewAssetGroupService             = asset.NewAssetGroupService
	NewAssetImportService            = asset.NewAssetImportService
	NewAssetRelationshipService      = asset.NewAssetRelationshipService
	NewAssetTypeService              = asset.NewAssetTypeService
	NewBranchService                 = asset.NewBranchService
	NewBusinessUnitService           = asset.NewBusinessUnitService
	NewComponentService              = asset.NewComponentService
	NewRelationshipSuggestionService = asset.NewRelationshipSuggestionService
	NewSBOMImportService             = asset.NewSBOMImportService
	PromoteKnownProperties           = asset.PromoteKnownProperties
)
