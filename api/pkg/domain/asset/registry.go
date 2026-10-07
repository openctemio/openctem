package asset

// The asset type registry (RFC-042 §6.3, docs/rfcs/RFC-042-asset-inventory-v2.md).
//
// Every asset type is declared once, in api/configs/asset-types.yaml. The
// data lives in registry_generated.go (`make generate-asset-types`); this
// file holds the shapes and the lookups. A type belongs to exactly one
// class, and a class to exactly one lens (the `other` class has none).
// GET /api/v1/asset-types serves RegistryDocument(); the assets table keeps
// asset_class and asset_lens in step through a trigger seeded from the same
// YAML.

// Class is the abstract kind of an asset (JupiterOne `_class`), one level
// above AssetType.
type Class string

// Lens is a fixed group of classes, shown as an inventory tab.
type Lens string

// Category is the legacy derived grouping returned as `category` on asset
// responses. New code uses Class and Lens. It is not stored.
type Category string

// AttributeKind is the type of a per-type attribute.
type AttributeKind string

// Attribute kinds.
const (
	AttributeString AttributeKind = "string"
	AttributeInt    AttributeKind = "int"
	AttributeNumber AttributeKind = "number"
	AttributeBool   AttributeKind = "bool"
	AttributeTime   AttributeKind = "time"
	AttributeEnum   AttributeKind = "enum"
	AttributeList   AttributeKind = "list"
	AttributeObject AttributeKind = "object"
)

// LensDefinition describes one lens.
type LensDefinition struct {
	ID             Lens    `json:"id"`
	Label          string  `json:"label"`
	Description    string  `json:"description"`
	Row            string  `json:"row"`
	DefaultGroupBy string  `json:"default_group_by"`
	Classes        []Class `json:"classes"`
}

// ClassDefinition describes one class. Lens is empty for ClassOther.
type ClassDefinition struct {
	ID         Class       `json:"id"`
	Label      string      `json:"label"`
	Lens       Lens        `json:"lens,omitempty"`
	JupiterOne string      `json:"jupiterone"`
	Types      []AssetType `json:"types"`
}

// AttributeDefinition is one typed attribute of a type, stored in
// assets.properties. Facet and Group mark the attributes exposed as facets
// and group-by fields (`<type>.<name>` in OQL).
type AttributeDefinition struct {
	Name   string        `json:"name"`
	Kind   AttributeKind `json:"type"`
	Values []string      `json:"values,omitempty"`
	Facet  bool          `json:"facet"`
	Group  bool          `json:"group"`
}

// TypeRef names a stored (type, sub_type) pair. SubType is empty when any
// sub-type matches.
type TypeRef struct {
	Type    AssetType `json:"type"`
	SubType string    `json:"sub_type,omitempty"`
}

// RelationshipRule lists the peer types one relationship type allows for a
// type, in one direction.
type RelationshipRule struct {
	Relationship RelationshipType `json:"relationship"`
	// SubType restricts the rule to the type's assets of one sub-type
	// ("" = any sub-type).
	SubType string    `json:"sub_type,omitempty"`
	Peers   []TypeRef `json:"peers"`
}

// TypeRelationships are the relationships a type may take part in, resolved
// from configs/relationship-types.yaml: Out as the source, In as the target.
type TypeRelationships struct {
	Out []RelationshipRule `json:"out"`
	In  []RelationshipRule `json:"in"`
}

// TypeDefinition is one registry entry.
type TypeDefinition struct {
	Type           AssetType             `json:"type"`
	Label          string                `json:"label"`
	Plural         string                `json:"plural"`
	Icon           string                `json:"icon"`
	Class          Class                 `json:"class"`
	Lens           Lens                  `json:"lens,omitempty"`
	AliasOf        *TypeRef              `json:"alias_of,omitempty"`
	SubTypes       []string              `json:"sub_types"`
	LegacyCategory Category              `json:"legacy_category"`
	Storage        string                `json:"storage"`
	IdentityKeys   []string              `json:"identity_keys"`
	Attributes     []AttributeDefinition `json:"attributes"`
	Facets         []string              `json:"facets"`
	GroupBy        []string              `json:"group_by"`
	Columns        []string              `json:"columns"`
	Card           string                `json:"card"`
	Sections       []string              `json:"sections"`
	Relationships  TypeRelationships     `json:"relationships"`
	// ScannableBy lists the tool target types (supported_targets) that can
	// scan the type (RFC-042 §6.3.8 R5).
	ScannableBy []string `json:"scannable_by"`
	// ExposureDefault is the exposure the type has by nature ("" = none).
	ExposureDefault string `json:"exposure_default,omitempty"`
}

// SectionDefinition is one detail section from the closed set the web
// implements.
type SectionDefinition struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// PropertyFormat says how a property value is shown beyond its attribute
// type ("" = by the value's own shape).
type PropertyFormat string

// Property formats.
const (
	// PropertyFormatIP: each value is an IP address (links to the IP asset).
	PropertyFormatIP PropertyFormat = "ip"
	// PropertyFormatURL: an http(s) link.
	PropertyFormatURL PropertyFormat = "url"
	// PropertyFormatCode: an identifier, shown monospace.
	PropertyFormatCode PropertyFormat = "code"
)

// PropertyDefinition is one key of the property schema (RFC-042 §6.3.9):
// its labels, display format, the synonym keys that fold into it and, when
// set, the only classes whose assets may hold it.
type PropertyDefinition struct {
	Key      string         `json:"key"`
	Label    string         `json:"label"`
	LabelVI  string         `json:"label_vi"`
	Format   PropertyFormat `json:"format,omitempty"`
	Synonyms []string       `json:"synonyms,omitempty"`
	Classes  []Class        `json:"classes,omitempty"`
}

// Registry is the whole registry, as served by GET /api/v1/asset-types.
type Registry struct {
	Version    string              `json:"version"`
	Lenses     []LensDefinition    `json:"lenses"`
	Classes    []ClassDefinition   `json:"classes"`
	Types      []TypeDefinition    `json:"types"`
	Sections   []SectionDefinition `json:"sections"`
	Cards      []string            `json:"cards"`
	CoreFields []string            `json:"core_fields"`
	// Properties is the property dictionary, CommonProperties the keys
	// every type may hold besides its attributes.
	Properties       []PropertyDefinition `json:"properties"`
	CommonProperties []string             `json:"common_properties"`
}

type legacyCategoryDefinition struct {
	ID    Category
	Label string
}

var (
	registryTypeIndex  = indexRegistryTypes()
	registryClassIndex = indexRegistryClasses()
	registryAliasIndex = indexRegistryAliases()
)

func indexRegistryTypes() map[AssetType]*TypeDefinition {
	m := make(map[AssetType]*TypeDefinition, len(registryTypes))
	for i := range registryTypes {
		m[registryTypes[i].Type] = &registryTypes[i]
	}
	return m
}

func indexRegistryClasses() map[Class]*ClassDefinition {
	m := make(map[Class]*ClassDefinition, len(registryClasses))
	for i := range registryClasses {
		m[registryClasses[i].ID] = &registryClasses[i]
	}
	return m
}

// indexRegistryAliases maps a stored (core type, sub_type) pair to the alias
// type it came from, e.g. (host, serverless) to serverless.
func indexRegistryAliases() map[TypeRef]*TypeDefinition {
	m := make(map[TypeRef]*TypeDefinition)
	for i := range registryTypes {
		if a := registryTypes[i].AliasOf; a != nil {
			m[*a] = &registryTypes[i]
		}
	}
	return m
}

// RegistryDocument returns the registry. Callers must not modify it.
func RegistryDocument() Registry {
	return Registry{
		Version:    RegistryVersion,
		Lenses:     registryLenses,
		Classes:    registryClasses,
		Types:      registryTypes,
		Sections:   registrySections,
		Cards:      registryCards,
		CoreFields: registryCoreFields,

		Properties:       registryProperties,
		CommonProperties: registryCommonProperties,
	}
}

// LookupType returns the registry entry for t.
func LookupType(t AssetType) (TypeDefinition, bool) {
	d, ok := registryTypeIndex[t]
	if !ok {
		return TypeDefinition{}, false
	}
	return *d, true
}

// ClassOf returns the class of a stored asset. An alias keeps its own
// class: (host, serverless) is ClassFunction, not ClassHost. Unknown types
// are ClassOther. The database trigger on assets applies the same rule.
func ClassOf(t AssetType, subType string) Class {
	if subType != "" {
		if d, ok := registryAliasIndex[TypeRef{Type: t, SubType: subType}]; ok {
			return d.Class
		}
	}
	if d, ok := registryTypeIndex[t]; ok {
		return d.Class
	}
	return ClassOther
}

// LensOf returns the lens of a stored asset, or "" for ClassOther.
func LensOf(t AssetType, subType string) Lens {
	return LensForClass(ClassOf(t, subType))
}

// LensForClass returns the lens a class belongs to, or "" when it has none.
func LensForClass(c Class) Lens {
	if d, ok := registryClassIndex[c]; ok {
		return d.Lens
	}
	return ""
}

// AllClasses returns every class in display order.
func AllClasses() []Class {
	out := make([]Class, len(registryClasses))
	for i, c := range registryClasses {
		out[i] = c.ID
	}
	return out
}

// AllLenses returns every lens in display order.
func AllLenses() []Lens {
	out := make([]Lens, len(registryLenses))
	for i, l := range registryLenses {
		out[i] = l.ID
	}
	return out
}

// CategoryForType returns the legacy category of an asset type, or
// CategoryOther for unknown types.
func CategoryForType(t AssetType) Category {
	if d, ok := registryTypeIndex[t]; ok {
		return d.LegacyCategory
	}
	// A legacy type input (web_application) has the category of the pair it
	// is stored as.
	if a, ok := TypeAliases[t]; ok {
		if d, ok := registryAliasIndex[TypeRef{Type: a.CoreType, SubType: a.SubType}]; ok {
			return d.LegacyCategory
		}
		if d, ok := registryTypeIndex[a.CoreType]; ok {
			return d.LegacyCategory
		}
	}
	return CategoryOther
}

// AllCategories returns every legacy category in display order.
func AllCategories() []Category {
	out := make([]Category, len(registryLegacyCategories))
	for i, c := range registryLegacyCategories {
		out[i] = c.ID
	}
	return out
}

// Label returns the human-readable label of a legacy category.
func (c Category) Label() string {
	for _, d := range registryLegacyCategories {
		if d.ID == c {
			return d.Label
		}
	}
	return "Other"
}

// TypesInCategory returns the asset types of a legacy category, in registry
// order.
func TypesInCategory(c Category) []AssetType {
	var types []AssetType
	for _, d := range registryTypes {
		if d.LegacyCategory == c {
			types = append(types, d.Type)
		}
	}
	return types
}

// TypeInput is what an accepted input is stored as (RFC-042 §6.3.8): a core
// type, a sub-type from its closed list ("" for none), a provider and
// attribute values. Provider and Attributes apply only where the asset has
// no value yet.
type TypeInput struct {
	Type       AssetType
	SubType    string
	Provider   Provider
	Attributes map[string]string
}
