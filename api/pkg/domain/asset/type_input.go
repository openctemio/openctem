package asset

// Input types and stored types (RFC-042 §6.3.8,
// docs/rfcs/RFC-042-asset-inventory-v2.md).
//
// Only core types are stored. An alias (`website`, `iam_user`, `s3_bucket`
// …) and a legacy sub-type (`postgresql`, `aws`, `server` …) are input
// names: every write path resolves them here, from the registry, before an
// asset is created or changed. The resolver only maps names to names; it
// never widens what the caller may do (tenant, data scope and permission
// checks happen where they always did, on the resolved asset).

import (
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PropKeyNativeSubType keeps a sub-type that ingest received but the
// registry does not know, so the asset can be re-classified when the
// registry grows. It is in the quarantined x_* namespace.
const PropKeyNativeSubType = "x_native_sub_type"

// maxSubTypeLength bounds an input sub-type (assets.sub_type is VARCHAR(50)).
const maxSubTypeLength = 50

// ResolvedType is a stored (type, sub_type) plus what the input implied.
type ResolvedType struct {
	Type    AssetType
	SubType string
	// Provider and Attributes are implied by the input (`s3_bucket` implies
	// provider aws). Apply them only where the asset has no value.
	Provider   Provider
	Attributes map[string]string
	// NativeSubType is an unknown sub-type that lenient resolution dropped.
	NativeSubType string
}

// IsStored reports whether t is a core type, one assets.asset_type may hold.
func (t AssetType) IsStored() bool {
	return slices.Contains(registryStoredTypes, t)
}

// StoredAssetTypes returns the core types in registry order.
func StoredAssetTypes() []AssetType {
	return slices.Clone(registryStoredTypes)
}

// SubTypesOf returns the closed sub-type list of a core type (nil for an
// alias or an unknown type).
func SubTypesOf(t AssetType) []string {
	d, ok := registryTypeIndex[t]
	if !ok || d.AliasOf != nil {
		return nil
	}
	return slices.Clone(d.SubTypes)
}

// IsValidSubType reports whether subType may be stored with the core type t.
// The empty sub-type is always valid.
func IsValidSubType(t AssetType, subType string) bool {
	if subType == "" {
		return true
	}
	d, ok := registryTypeIndex[t]
	return ok && d.AliasOf == nil && slices.Contains(d.SubTypes, subType)
}

// ResolveInputType resolves an input (type, sub_type) to the stored pair, for
// writes made by people and API clients (REST, CSV and bulk import). An
// unknown type, an unknown sub-type and a sub-type that contradicts an alias
// are validation errors (shared.ErrValidation).
func ResolveInputType(rawType, rawSubType string) (ResolvedType, error) {
	return resolveInputType(rawType, rawSubType, false)
}

// ResolveInputTypeLenient is ResolveInputType for machine producers (ingest,
// sensors, connectors): an unknown sub-type is not an error. It is dropped
// and returned in NativeSubType, so a scan is never refused for it. An
// unknown type is still an error; callers map it to `unclassified` first.
func ResolveInputTypeLenient(rawType, rawSubType string) (ResolvedType, error) {
	return resolveInputType(rawType, rawSubType, true)
}

func resolveInputType(rawType, rawSubType string, lenient bool) (ResolvedType, error) {
	typ := AssetType(strings.ToLower(strings.TrimSpace(rawType)))
	sub := strings.ToLower(strings.TrimSpace(rawSubType))
	if len(sub) > maxSubTypeLength {
		if !lenient {
			return ResolvedType{}, fmt.Errorf("%w: sub_type is longer than %d characters", shared.ErrValidation, maxSubTypeLength)
		}
		sub = sub[:maxSubTypeLength]
	}

	var out ResolvedType
	switch {
	case typ.IsStored():
		out.Type = typ
	case typ != "":
		in, ok := registryInputs[TypeRef{Type: typ}]
		if !ok {
			return ResolvedType{}, fmt.Errorf("%w: invalid asset type: %s", shared.ErrValidation, rawType)
		}
		out = fromInput(in)
		if out.SubType == "" {
			break // the alias leaves the sub-type open: validate it below
		}
		// An alias fixes the sub-type: the same value (or none) is
		// accepted, a different one contradicts it.
		if sub != "" && sub != out.SubType {
			if !lenient {
				return ResolvedType{}, fmt.Errorf("%w: sub_type %q contradicts asset type %q (stored as %s/%s)",
					shared.ErrValidation, sub, typ, out.Type, out.SubType)
			}
			out.NativeSubType = sub
		}
		return out, nil
	default:
		return ResolvedType{}, fmt.Errorf("%w: asset type is required", shared.ErrValidation)
	}

	if sub == "" || IsValidSubType(out.Type, sub) {
		out.SubType = sub
		return out, nil
	}
	if in, ok := registryInputs[TypeRef{Type: out.Type, SubType: sub}]; ok {
		mapped := fromInput(in)
		if mapped.Provider == "" {
			mapped.Provider = out.Provider
		}
		for k, v := range out.Attributes {
			if _, set := mapped.Attributes[k]; !set {
				if mapped.Attributes == nil {
					mapped.Attributes = map[string]string{}
				}
				mapped.Attributes[k] = v
			}
		}
		return mapped, nil
	}
	if lenient {
		out.NativeSubType = sub
		return out, nil
	}
	return ResolvedType{}, fmt.Errorf("%w: invalid sub_type %q for asset type %q (allowed: %s)",
		shared.ErrValidation, sub, out.Type, allowedSubTypes(out.Type))
}

func fromInput(in TypeInput) ResolvedType {
	out := ResolvedType{Type: in.Type, SubType: in.SubType, Provider: in.Provider}
	if len(in.Attributes) > 0 {
		out.Attributes = make(map[string]string, len(in.Attributes))
		for k, v := range in.Attributes {
			out.Attributes[k] = v
		}
	}
	return out
}

func allowedSubTypes(t AssetType) string {
	subs := SubTypesOf(t)
	if len(subs) == 0 {
		return "none"
	}
	return strings.Join(subs, ", ")
}

// MergeImplied adds the provider attribute values and the native sub-type a
// resolution implied to props, without overwriting a value already there,
// and returns props (allocated when nil and something is added).
func (r ResolvedType) MergeImplied(props map[string]any) map[string]any {
	set := func(k string, v any) {
		if props == nil {
			props = make(map[string]any)
		}
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	for k, v := range r.Attributes {
		set(k, v)
	}
	if r.NativeSubType != "" {
		set(PropKeyNativeSubType, r.NativeSubType)
	}
	return props
}

// RegistryTypeInputs returns every accepted input that is not stored as such
// (aliases keyed {Type: alias}, legacy sub-types keyed {Type, SubType}) and
// what it is stored as. The map is a copy.
func RegistryTypeInputs() map[TypeRef]TypeInput {
	out := make(map[TypeRef]TypeInput, len(registryInputs))
	for k, v := range registryInputs {
		out[k] = v
	}
	return out
}
