package asset

// CTIS technical blocks → flat schema keys (RFC-042 §6.3.10, architecture
// page "Property names", rule 2: properties are flat).
//
// A CTIS report carries the facts of a domain, an IP address, a service or
// a certificate in a technical block (`technical.domain`, …). Ingest used to
// store each block as one object under a common key
// (`properties.certificate.not_after`), next to the registry's flat
// attributes for the same facts (`not_after`), so every reader had to look
// in both places. PromoteTechnicalBlocks moves a block's facts to the flat
// keys of the asset's type and removes the block. A flat value already there
// wins. A block field the type has no key for is dropped: such a fact is
// either a relationship (a service's certificate is a certificate asset, a
// host's ports are services) or something nothing reads.

import (
	"slices"
	"sort"
	"strings"
)

// Technical block keys: the common property keys a CTIS technical block is
// stored under.
const (
	BlockDomain      = "domain"
	BlockIPAddress   = "ip_address"
	BlockService     = "service"
	BlockCertificate = "certificate"
)

// TechnicalBlockKeys are the property keys that hold a CTIS technical block
// when their value is an object.
var TechnicalBlockKeys = []string{BlockDomain, BlockIPAddress, BlockService, BlockCertificate}

// blockFieldTargets maps a block field whose CTIS name differs from the
// schema key to the keys it may fill, in order; the first one the asset's
// type declares is used. Every other field fills the key of its own name.
var blockFieldTargets = map[string]map[string][]string{
	BlockCertificate: {
		"fingerprint": {"fingerprint_sha256"},
		"self_signed": {"is_self_signed"},
		"expired":     {"is_expired"},
	},
	BlockService: {
		// nmap's service name ("ssh") on an open port; the web server on an
		// HTTP service.
		"name":          {"service", "server"},
		"tls":           {"has_tls"},
		"auth_required": {"is_auth_required"},
	},
	BlockIPAddress: {
		"address": {PropKeyIPAddresses},
	},
}

// attributeKeysOf returns the attribute keys of a stored (type, sub_type):
// its type's and its alias's, without the common keys.
func attributeKeysOf(t AssetType, subType string) map[string]bool {
	keys := map[string]bool{}
	add := func(d *TypeDefinition) {
		for _, a := range d.Attributes {
			keys[a.Name] = true
		}
	}
	if d, ok := registryTypeIndex[t]; ok {
		add(d)
	}
	if subType != "" {
		if d, ok := registryAliasIndex[TypeRef{Type: t, SubType: subType}]; ok {
			add(d)
		}
	}
	return keys
}

// PromoteTechnicalBlocks moves the facts of every CTIS technical block in
// props to the flat schema keys of the stored (type, sub_type) and removes
// the block. A flat value already set wins; a list key (ip_addresses)
// merges. A domain block's DNS records also give the summary keys a list
// filters on: dns_record_types, the A/AAAA addresses and the first CNAME
// target. props is changed in place and returned.
func PromoteTechnicalBlocks(t AssetType, subType string, props map[string]any) map[string]any {
	if len(props) == 0 {
		return props
	}
	attrs := attributeKeysOf(t, subType)
	class := ClassOf(t, subType)
	for _, block := range TechnicalBlockKeys {
		fields, ok := props[block].(map[string]any)
		if !ok {
			continue
		}
		delete(props, block)
		// Sorted, so the first of two fields that fill one key is stable.
		names := make([]string, 0, len(fields))
		for k := range fields {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, field := range names {
			promoteField(props, class, attrs, block, field, fields[field])
		}
		if block == BlockDomain && class == ClassDomain {
			promoteDNSRecords(props, attrs, fields["dns_records"])
		}
	}
	return props
}

// blockClasses are the classes a block describes. On an asset of another
// class only the fields in crossClassFields are promoted: an IP block's
// `version` is the IP version, never an application's version.
var blockClasses = map[string][]Class{
	BlockDomain:      {ClassDomain},
	BlockIPAddress:   {ClassIPAddress},
	BlockService:     {ClassService, ClassApplication},
	BlockCertificate: {ClassCertificate},
}

// crossClassFields are the block fields that also describe an asset of
// another class: the address it resolves to or listens on, a host's name.
var crossClassFields = map[string]map[string]bool{
	BlockIPAddress: {"address": true, "hostname": true},
}

// PromotionTarget returns the flat key a technical block's field fills on
// an asset of the stored (type, sub_type), or "" when the type has none.
func PromotionTarget(t AssetType, subType, block, field string) string {
	return promotionTarget(ClassOf(t, subType), attributeKeysOf(t, subType), block, field)
}

func promotionTarget(class Class, attrs map[string]bool, block, field string) string {
	if !slices.Contains(blockClasses[block], class) && !crossClassFields[block][field] {
		return ""
	}
	targets := blockFieldTargets[block][field]
	if targets == nil {
		targets = []string{field}
	}
	for _, target := range targets {
		if key := CanonicalPropertyKey(target); attrs[key] {
			return key
		}
	}
	return ""
}

func promoteField(props map[string]any, class Class, attrs map[string]bool, block, field string, v any) {
	if isEmptyValue(v) {
		return
	}
	key := promotionTarget(class, attrs, block, field)
	switch {
	case key == "":
		return
	case key == PropKeyIPAddresses:
		if s, ok := v.(string); ok {
			AddIPAddress(props, s)
		}
	default:
		if _, exists := props[key]; !exists {
			props[key] = v
		}
	}
}

// promoteDNSRecords derives the flat DNS summary of a name from its records.
func promoteDNSRecords(props map[string]any, attrs map[string]bool, raw any) {
	records, ok := raw.([]any)
	if !ok {
		if typed, ok := raw.([]map[string]any); ok {
			for _, r := range typed {
				records = append(records, r)
			}
		}
	}
	if len(records) == 0 {
		return
	}
	var types []string
	cname := ""
	for _, r := range records {
		rec, ok := r.(map[string]any)
		if !ok {
			continue
		}
		rt, _ := rec["type"].(string)
		rt = strings.ToUpper(strings.TrimSpace(rt))
		val, _ := rec["value"].(string)
		if rt == "" {
			continue
		}
		if !slices.Contains(types, rt) {
			types = append(types, rt)
		}
		switch rt {
		case "A", "AAAA":
			if attrs[PropKeyIPAddresses] {
				AddIPAddress(props, val)
			}
		case "CNAME":
			if cname == "" {
				cname = strings.TrimSuffix(strings.TrimSpace(val), ".")
			}
		}
	}
	if _, exists := props["dns_record_types"]; !exists && attrs["dns_record_types"] && len(types) > 0 {
		props["dns_record_types"] = strings.Join(types, ", ")
	}
	if _, exists := props["cname_target"]; !exists && attrs["cname_target"] && cname != "" {
		props["cname_target"] = cname
	}
}

func isEmptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(x) == ""
	case []any:
		return len(x) == 0
	case []string:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// NormalizeAssetProperties is the one write-path step for an asset's
// properties: technical blocks promoted to the flat keys of the stored
// (type, sub_type), then synonyms folded (NormalizeProperties).
func NormalizeAssetProperties(t AssetType, subType string, props map[string]any) map[string]any {
	return NormalizeProperties(PromoteTechnicalBlocks(t, subType, props))
}
