package audit

// Destructive deletes of tenant configuration and inventory objects. Each
// delete leaves one entry per deleted object (a bulk delete leaves one per
// item that was deleted), so an administrator can answer who removed an
// object and when after the row is gone.
const (
	ActionAssetGroupDeleted        Action = "asset_group.deleted"
	ActionBusinessUnitDeleted      Action = "business_unit.deleted"
	ActionBusinessServiceDeleted   Action = "business_service.deleted"
	ActionAttackerProfileDeleted   Action = "attacker_profile.deleted"
	ActionPentestTemplateDeleted   Action = "pentest_template.deleted"
	ActionAssetRelationshipDeleted Action = "asset_relationship.deleted"
	ActionAssetDuplicateMerged     Action = "asset.duplicate_merged"
)

// Resource types.
const (
	ResourceTypeBusinessUnit      ResourceType = "business_unit"
	ResourceTypeBusinessService   ResourceType = "business_service"
	ResourceTypeAttackerProfile   ResourceType = "attacker_profile"
	ResourceTypePentestTemplate   ResourceType = "pentest_template"
	ResourceTypeAssetRelationship ResourceType = "asset_relationship"
)

var _ = registerActions("asset_group", map[Action]Severity{
	ActionAssetGroupDeleted: SeverityMedium,
})

var _ = registerActions("business_unit", map[Action]Severity{
	ActionBusinessUnitDeleted: SeverityMedium,
})

var _ = registerActions("business_service", map[Action]Severity{
	ActionBusinessServiceDeleted: SeverityMedium,
})

var _ = registerActions("attacker_profile", map[Action]Severity{
	ActionAttackerProfileDeleted: SeverityMedium,
})

var _ = registerActions("pentest_template", map[Action]Severity{
	ActionPentestTemplateDeleted: SeverityMedium,
})

var _ = registerActions("asset_relationship", map[Action]Severity{
	ActionAssetRelationshipDeleted: SeverityLow,
})

// ActionAssetDuplicateMerged is recorded once per asset a duplicate
// review approval folds into the kept asset and deletes. High, like any
// asset deletion: the asset's rows move to the kept asset and the asset
// itself is gone.
var _ = registerActions("asset", map[Action]Severity{
	ActionAssetDuplicateMerged: SeverityHigh,
})

func init() {
	for _, r := range []ResourceType{
		ResourceTypeAssetGroup, ResourceTypeBusinessUnit, ResourceTypeBusinessService,
		ResourceTypeAttackerProfile, ResourceTypePentestTemplate, ResourceTypeAssetRelationship,
	} {
		configResourceTypes[r] = struct{}{}
	}
}
