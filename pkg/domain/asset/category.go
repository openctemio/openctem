package asset

// Category groups asset types for UI organization and filtering.
// This is a derived value — NOT stored in the database.
type Category string

const (
	CategoryExternalSurface Category = "external_surface"
	CategoryApplication     Category = "application"
	CategoryInfrastructure  Category = "infrastructure"
	CategoryNetwork         Category = "network"
	CategoryCloud           Category = "cloud"
	CategoryData            Category = "data"
	CategoryCode            Category = "code"
	CategoryIdentity        Category = "identity"
	CategoryOther           Category = "other"
)

// typeToCategory maps each asset type to its category.
var typeToCategory = map[AssetType]Category{
	// External Surface — internet-facing discovery artifacts
	AssetTypeDomain:      CategoryExternalSurface,
	AssetTypeSubdomain:   CategoryExternalSurface,
	AssetTypeCertificate: CategoryExternalSurface,
	AssetTypeIPAddress:   CategoryExternalSurface,

	// Application — software applications accessible by users
	AssetTypeWebsite:        CategoryApplication,
	AssetTypeWebApplication: CategoryApplication,
	AssetTypeAPI:            CategoryApplication,
	AssetTypeMobileApp:      CategoryApplication,
	AssetTypeApplication:    CategoryApplication, // consolidated type

	// Infrastructure — machines and compute
	AssetTypeHost:                CategoryInfrastructure,
	AssetTypeCompute:             CategoryInfrastructure,
	AssetTypeServerless:          CategoryInfrastructure,
	AssetTypeContainer:           CategoryInfrastructure,
	AssetTypeKubernetesCluster:   CategoryInfrastructure,
	AssetTypeKubernetesNamespace: CategoryInfrastructure,
	AssetTypeKubernetes:          CategoryInfrastructure, // consolidated type
	AssetTypeEndpoint:            CategoryInfrastructure, // Q3/WS-B: user-operated device (laptop, workstation, mobile)

	// Network — network segments, devices, and services
	AssetTypeNetwork:       CategoryNetwork,
	AssetTypeVPC:           CategoryNetwork,
	AssetTypeSubnet:        CategoryNetwork,
	AssetTypeFirewall:      CategoryNetwork,
	AssetTypeLoadBalancer:  CategoryNetwork,
	AssetTypeService:       CategoryNetwork,
	AssetTypeHTTPService:   CategoryNetwork,
	AssetTypeOpenPort:      CategoryNetwork,
	AssetTypeDiscoveredURL: CategoryNetwork,

	// Cloud — cloud provider accounts and storage
	AssetTypeCloudAccount:      CategoryCloud,
	AssetTypeStorage:            CategoryCloud,
	AssetTypeContainerRegistry: CategoryCloud,

	// Data — databases and data stores
	AssetTypeDatabase:  CategoryData,
	AssetTypeDataStore: CategoryData,
	AssetTypeS3Bucket:  CategoryData,

	// Code — source code repositories
	AssetTypeRepository: CategoryCode,

	// Identity — IAM users, roles, service accounts
	AssetTypeIAMUser:        CategoryIdentity,
	AssetTypeIAMRole:        CategoryIdentity,
	AssetTypeServiceAccount: CategoryIdentity,
	AssetTypeIdentity:       CategoryIdentity, // consolidated type

	// Other
	AssetTypeUnclassified: CategoryOther,
}

// CategoryForType returns the category for an asset type.
// Returns CategoryOther for unknown types.
func CategoryForType(t AssetType) Category {
	if c, ok := typeToCategory[t]; ok {
		return c
	}
	return CategoryOther
}

// AllCategories returns all defined categories in display order.
func AllCategories() []Category {
	return []Category{
		CategoryExternalSurface,
		CategoryApplication,
		CategoryInfrastructure,
		CategoryNetwork,
		CategoryCloud,
		CategoryData,
		CategoryCode,
		CategoryIdentity,
		CategoryOther,
	}
}

// CategoryLabel returns a human-readable label for a category.
func (c Category) Label() string {
	switch c {
	case CategoryExternalSurface:
		return "External Surface"
	case CategoryApplication:
		return "Applications"
	case CategoryInfrastructure:
		return "Infrastructure"
	case CategoryNetwork:
		return "Network"
	case CategoryCloud:
		return "Cloud"
	case CategoryData:
		return "Data"
	case CategoryCode:
		return "Code"
	case CategoryIdentity:
		return "Identity"
	default:
		return "Other"
	}
}

// TypesInCategory returns all asset types belonging to a category.
func TypesInCategory(c Category) []AssetType {
	var types []AssetType
	for t, cat := range typeToCategory {
		if cat == c {
			types = append(types, t)
		}
	}
	return types
}
