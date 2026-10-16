package audit

// Content catalog (docs/rfcs/RFC-099-content-packages.md).

const (
	ActionContentPackageInstalled      Action = "content_package.installed"
	ActionContentPackageUpdated        Action = "content_package.updated"
	ActionContentPackageRolledBack     Action = "content_package.rolled_back"
	ActionContentPackageUninstalled    Action = "content_package.uninstalled"
	ActionContentPackagePinned         Action = "content_package.pinned"
	ActionContentPackageUnpinned       Action = "content_package.unpinned"
	ActionContentPackageAutoUpdated    Action = "content_package.auto_updated"
	ActionContentPackageRequested      Action = "content_package.requested"
	ActionContentPackageRequestApprove Action = "content_package.request_approved"
	ActionContentPackageRequestReject  Action = "content_package.request_rejected"
	ActionContentPackageRequestCancel  Action = "content_package.request_canceled"
	ActionContentCatalogSettings       Action = "content_catalog.settings_updated"
)

// ResourceTypeContentPackage is a content package of the catalog.
const ResourceTypeContentPackage ResourceType = "content_package"

var _ = registerActions("content_package", map[Action]Severity{
	ActionContentPackageInstalled:      SeverityMedium,
	ActionContentPackageUpdated:        SeverityMedium,
	ActionContentPackageRolledBack:     SeverityMedium,
	ActionContentPackageUninstalled:    SeverityMedium,
	ActionContentPackagePinned:         SeverityLow,
	ActionContentPackageUnpinned:       SeverityLow,
	ActionContentPackageAutoUpdated:    SeverityMedium,
	ActionContentPackageRequested:      SeverityLow,
	ActionContentPackageRequestApprove: SeverityMedium,
	ActionContentPackageRequestReject:  SeverityLow,
	ActionContentPackageRequestCancel:  SeverityLow,
	ActionContentCatalogSettings:       SeverityHigh,
})

func init() {
	configResourceTypes[ResourceTypeContentPackage] = struct{}{}
}
