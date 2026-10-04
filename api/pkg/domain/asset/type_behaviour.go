package asset

// Behaviour declared in the registry, not coded (RFC-042 §6.3.8 R5,
// docs/rfcs/RFC-042-asset-inventory-v2.md): the default exposure of a type,
// which tool target types can scan it, and which relationships it may take
// part in. Every lookup takes a stored (type, sub_type) pair. A row still
// stored under a legacy alias name (before the data normalisation) is read
// as the pair that alias stands for, so these answers never depend on which
// spelling the row has.

import "slices"

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

// RelationshipAllowed reports whether the registry allows a relationship of
// type rel from source to target (both stored pairs). A rule with a peer
// sub-type matches only that sub-type; a rule without one matches any.
func RelationshipAllowed(rel RelationshipType, source, target TypeRef) bool {
	src := CanonicalPair(source.Type, source.SubType)
	tgt := CanonicalPair(target.Type, target.SubType)
	d, ok := registryTypeIndex[src.Type]
	if !ok {
		return false
	}
	for _, r := range d.Relationships.Out {
		if r.Relationship != rel || (r.SubType != "" && r.SubType != src.SubType) {
			continue
		}
		for _, p := range r.Peers {
			if p.Type == tgt.Type && (p.SubType == "" || p.SubType == tgt.SubType) {
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
		if r.Relationship != rel || (r.SubType != "" && r.SubType != src.SubType) {
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
