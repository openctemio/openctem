package asset

// Behavior declared in the registry, not coded (RFC-042 §6.3.8 R5,
// docs/rfcs/RFC-042-asset-inventory-v2.md): the default exposure of a type,
// which tool target types can scan it, and which relationships it may take
// part in. Every lookup takes a stored (type, sub_type) pair. A row still
// stored under a legacy alias name (before the data normalisation) is read
// as the pair that alias stands for, so these answers never depend on which
// spelling the row has.

import (
	"slices"
	"strings"
)

// registryDefFor returns the registry entry that describes a stored pair:
// the alias whose (type, sub_type) it is, else the type's own entry.
func registryDefFor(t AssetType, subType string) (*TypeDefinition, bool) {
	if subType != "" {
		if d, ok := registryAliasIndex[TypeRef{Type: t, SubType: subType}]; ok {
			return d, true
		}
	}
	d, ok := registryTypeIndex[t]
	return d, ok
}

// coreDefFor returns the core type entry behind a definition (itself for a
// core type).
func coreDefFor(d *TypeDefinition) *TypeDefinition {
	if d.AliasOf == nil {
		return d
	}
	if c, ok := registryTypeIndex[d.AliasOf.Type]; ok {
		return c
	}
	return d
}

// CanonicalPair returns the (core type, sub_type) a stored pair stands for.
// A core pair is returned as is; a legacy row stored under an alias name is
// its alias's pair (an explicit sub-type on such a row wins).
func CanonicalPair(t AssetType, subType string) TypeRef {
	d, ok := registryTypeIndex[t]
	if !ok || d.AliasOf == nil {
		return TypeRef{Type: t, SubType: subType}
	}
	if subType == "" {
		subType = d.AliasOf.SubType
	}
	return TypeRef{Type: d.AliasOf.Type, SubType: subType}
}

// DefaultExposure is the exposure a stored pair has by nature (public for
// domains, certificates and web applications), or ExposureUnknown.
func DefaultExposure(t AssetType, subType string) Exposure {
	d, ok := registryDefFor(t, subType)
	if !ok {
		return ExposureUnknown
	}
	if d.ExposureDefault == "" {
		d = coreDefFor(d)
	}
	if d.ExposureDefault == "" {
		return ExposureUnknown
	}
	return Exposure(d.ExposureDefault)
}

// ScannableBy returns the tool target types (supported_targets) that can
// scan a stored pair. An alias without a list of its own uses its core
// type's. Unknown types have none.
func ScannableBy(t AssetType, subType string) []string {
	d, ok := registryDefFor(t, subType)
	if !ok {
		return nil
	}
	if len(d.ScannableBy) == 0 {
		d = coreDefFor(d)
	}
	return slices.Clone(d.ScannableBy)
}

// CoverageRules returns the coverage rules of a stored pair: an alias's own
// when the pair is an alias, else the core type's. Unknown types have none.
func CoverageRules(t AssetType, subType string) []CoverageRule {
	d, ok := registryDefFor(t, subType)
	if !ok {
		return nil
	}
	return slices.Clone(d.Coverage)
}

// subTypeMatches reports whether an asset's sub-type satisfies a rule's.
// A rule without a sub-type matches every asset of the type. An asset
// without a sub-type (its kind was never recorded, e.g. an application
// created before the typed pages sent one) matches every rule of its type:
// refusing it would block edges the registry allows for each of its kinds.
func subTypeMatches(rule, asset string) bool {
	return rule == "" || asset == "" || rule == asset
}

// RelationshipAllowed reports whether the registry allows a relationship of
// type rel from source to target (both stored pairs). A rule with a peer
// sub-type matches only that sub-type (or an asset with none); a rule
// without one matches any.
func RelationshipAllowed(rel RelationshipType, source, target TypeRef) bool {
	src := CanonicalPair(source.Type, source.SubType)
	tgt := CanonicalPair(target.Type, target.SubType)
	d, ok := registryTypeIndex[src.Type]
	if !ok {
		return false
	}
	for _, r := range d.Relationships.Out {
		if r.Relationship != rel || !subTypeMatches(r.SubType, src.SubType) {
			continue
		}
		for _, p := range r.Peers {
			if p.Type == tgt.Type && subTypeMatches(p.SubType, tgt.SubType) {
				return true
			}
		}
	}
	return false
}

// AllowedRelationshipTargets lists the peers a source pair may point at with
// rel, for error messages and pickers.
func AllowedRelationshipTargets(rel RelationshipType, source TypeRef) []TypeRef {
	src := CanonicalPair(source.Type, source.SubType)
	d, ok := registryTypeIndex[src.Type]
	if !ok {
		return nil
	}
	var out []TypeRef
	for _, r := range d.Relationships.Out {
		if r.Relationship != rel || !subTypeMatches(r.SubType, src.SubType) {
			continue
		}
		for _, p := range r.Peers {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// WithLegacyNames returns the given core types plus every alias name that is
// stored as one of them, for a type filter that must still find rows written
// under an alias name before the data normalisation (RFC-042 §6.3.8 T3).
func WithLegacyNames(types ...AssetType) []AssetType {
	out := slices.Clone(types)
	for _, d := range registryTypes {
		if d.AliasOf != nil && slices.Contains(types, d.AliasOf.Type) && !slices.Contains(out, d.Type) {
			out = append(out, d.Type)
		}
	}
	return out
}

// TypeNameMatches reports whether a type name a person wrote in a rule (a
// core type such as `host`, or an alias such as `website` or `firewall`)
// covers an asset's stored pair. The name is resolved through the registry,
// never compared as a string: a rule on `website` matches a stored
// (application, website). A core name covers every sub-type; an asset whose
// kind was never recorded is covered by every name of its type. An unknown
// name matches nothing.
func TypeNameMatches(name string, ref TypeRef) bool {
	n := AssetType(strings.ToLower(strings.TrimSpace(name)))
	if _, known := registryTypeIndex[n]; !known {
		return false
	}
	want := CanonicalPair(n, "")
	got := CanonicalPair(ref.Type, ref.SubType)
	return want.Type == got.Type && subTypeMatches(want.SubType, got.SubType)
}

// ScanTargetPair is one fact of the registry's scannable_by: a tool that
// accepts TargetType can scan assets of the registry type Type (an alias
// type is its stored pair, SubType).
type ScanTargetPair struct {
	TargetType string
	Type       AssetType
	SubType    string
}

// ScanTargetPairs lists every (target type, registry type) the registry
// declares scannable, in registry order. Callers must not modify the result.
func ScanTargetPairs() []ScanTargetPair {
	var out []ScanTargetPair
	for i := range registryTypes {
		d := &registryTypes[i]
		stored := TypeRef{Type: d.Type}
		if d.AliasOf != nil {
			stored = *d.AliasOf
		}
		for _, target := range ScannableBy(stored.Type, stored.SubType) {
			out = append(out, ScanTargetPair{TargetType: target, Type: d.Type, SubType: stored.SubType})
		}
	}
	return out
}

// RegistryCoversMapping reports whether the registry already lets a tool that
// accepts targetType scan everything an administrator mapping of
// (targetType, name) would add. A mapping reaches the stored pair the name
// stands for and, when that pair has no sub-type, every alias sub-type of its
// type; it is covered only when scannable_by lists the target for all of them,
// so removing a covered mapping never changes what can be scanned.
func RegistryCoversMapping(targetType string, name AssetType) bool {
	if !name.IsValid() {
		return false
	}
	ref := TypeRef{Type: name}
	if !name.IsStored() {
		ref = CanonicalPair(name, "")
	}
	if _, ok := registryTypeIndex[ref.Type]; !ok {
		return false
	}
	pairs := []TypeRef{ref}
	if ref.SubType == "" {
		for i := range registryTypes {
			if a := registryTypes[i].AliasOf; a != nil && a.Type == ref.Type {
				pairs = append(pairs, *a)
			}
		}
	}
	for _, p := range pairs {
		if !slices.Contains(ScannableBy(p.Type, p.SubType), targetType) {
			return false
		}
	}
	return true
}
