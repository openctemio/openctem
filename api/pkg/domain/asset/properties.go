package asset

// The property schema (RFC-042 §6.3.9, docs/rfcs/RFC-042-asset-inventory-v2.md).
//
// api/configs/asset-types.yaml declares every property key once: its labels,
// display format, the synonym keys scanners and older code wrote for it and,
// for a key like `port`, the only classes whose assets may hold it. The data
// is generated into registry_generated.go; this file holds the lookups.
//
// Every reader of a multi-key property (an asset's IP addresses above all)
// goes through PropertyStrings / IPAddresses, and every write path folds
// synonyms with NormalizeProperties, so no package keeps a key list of its
// own.

import (
	"net"
	"slices"
	"sort"
	"strings"
)

// PropKeyIPAddresses is the canonical key of an asset's IP addresses: a
// host's interfaces, the addresses a domain resolves to, the address a
// service listens on. Its synonyms (ip, ips, resolved_ips, ...) fold into it.
const PropKeyIPAddresses = "ip_addresses"

var (
	propertyIndex = indexProperties()
	// synonymIndex maps a synonym key to its canonical key.
	synonymIndex     = indexSynonyms()
	commonProperties = indexCommon()
)

func indexProperties() map[string]*PropertyDefinition {
	m := make(map[string]*PropertyDefinition, len(registryProperties))
	for i := range registryProperties {
		m[registryProperties[i].Key] = &registryProperties[i]
	}
	return m
}

func indexSynonyms() map[string]string {
	m := map[string]string{}
	for _, p := range registryProperties {
		for _, s := range p.Synonyms {
			m[s] = p.Key
		}
	}
	return m
}

func indexCommon() map[string]bool {
	m := make(map[string]bool, len(registryCommonProperties))
	for _, k := range registryCommonProperties {
		m[k] = true
	}
	return m
}

// LookupProperty returns the schema entry of a canonical property key.
func LookupProperty(key string) (PropertyDefinition, bool) {
	p, ok := propertyIndex[key]
	if !ok {
		return PropertyDefinition{}, false
	}
	return *p, true
}

// CanonicalPropertyKey returns the canonical key a synonym folds into, or the
// key itself.
func CanonicalPropertyKey(key string) string {
	if c, ok := synonymIndex[key]; ok {
		return c
	}
	return key
}

// PropertySynonyms returns every synonym key, sorted.
func PropertySynonyms() []string {
	out := make([]string, 0, len(synonymIndex))
	for s := range synonymIndex {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// PropertyKeysOf returns the keys an asset of the stored (type, sub_type)
// may hold under the schema: the attributes of its type, of the alias the
// pair came from, and the common keys.
func PropertyKeysOf(t AssetType, subType string) map[string]bool {
	keys := make(map[string]bool, len(commonProperties)+16)
	for k := range commonProperties {
		keys[k] = true
	}
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

// IsCustomPropertyKey reports whether a key is in the namespace third-party
// and custom properties use (`x_`).
func IsCustomPropertyKey(key string) bool {
	return strings.HasPrefix(key, "x_")
}

// UnknownPropertyKeys returns, sorted, the keys of props that are outside the
// schema of the stored (type, sub_type): neither its attributes, a common
// key, a synonym (NormalizeProperties folds those), a platform-owned key nor
// an `x_` custom key.
func UnknownPropertyKeys(t AssetType, subType string, props map[string]any) []string {
	if len(props) == 0 {
		return nil
	}
	known := PropertyKeysOf(t, subType)
	out := make([]string, 0, len(props))
	for k := range props {
		if known[k] || IsCustomPropertyKey(k) || IsReservedPropertyKey(k) {
			continue
		}
		if _, syn := synonymIndex[k]; syn {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MisplacedPropertyKeys returns, sorted, the keys of props that only assets
// of other classes may hold (a `port` on a domain). Such a key belongs on
// another asset, never on this one.
func MisplacedPropertyKeys(t AssetType, subType string, props map[string]any) []string {
	class := ClassOf(t, subType)
	var out []string
	for k := range props {
		if p, ok := propertyIndex[k]; ok && len(p.Classes) > 0 && !slices.Contains(p.Classes, class) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// NormalizeProperties folds every synonym key of props into its canonical
// key and removes it. A list key (`List`): string and list values are merged
// into it, without duplicates. An object under a synonym key is not a value
// of the canonical key (the CTIS technical `ip_address` block) and stays;
// only its `address` joins an `ip` list. Values of an `ip` key are parsed: a
// comma-separated string is split, the addresses are kept in canonical form
// and anything that is not an address is dropped. A scalar key (a renamed
// boolean, a timestamp): the canonical key keeps its own value; without one
// it takes the first synonym's value, unchanged. props is changed in place
// and returned (a nil map stays nil).
func NormalizeProperties(props map[string]any) map[string]any {
	if len(props) == 0 {
		return props
	}
	for i := range registryProperties {
		p := &registryProperties[i]
		if len(p.Synonyms) == 0 {
			continue
		}
		if !p.List {
			foldScalarSynonyms(props, p)
			continue
		}
		present := false
		if _, ok := props[p.Key]; ok {
			present = true
		}
		for _, s := range p.Synonyms {
			if _, ok := props[s]; ok {
				present = true
				break
			}
		}
		if !present {
			continue
		}
		values, keep := collectPropertyValues(props, p)
		for _, s := range p.Synonyms {
			if v, ok := props[s]; ok {
				if _, isObject := v.(map[string]any); !isObject {
					delete(props, s)
				}
			}
		}
		if len(values) == 0 && len(keep) == 0 {
			delete(props, p.Key)
			continue
		}
		list := make([]any, 0, len(keep)+len(values))
		list = append(list, keep...)
		for _, v := range values {
			list = append(list, v)
		}
		props[p.Key] = list
	}
	return props
}

// foldScalarSynonyms moves the first synonym value of a scalar key to the key
// when it has none, and removes every synonym that is not an object.
func foldScalarSynonyms(props map[string]any, p *PropertyDefinition) {
	_, has := props[p.Key]
	for _, s := range p.Synonyms {
		v, ok := props[s]
		if !ok {
			continue
		}
		if _, isObject := v.(map[string]any); isObject {
			continue
		}
		if !has && v != nil {
			props[p.Key] = v
			has = true
		}
		delete(props, s)
	}
}

// collectPropertyValues returns the string values of p's key and synonyms,
// deduplicated in order, and the non-string elements of p's own list (kept
// as they are).
func collectPropertyValues(props map[string]any, p *PropertyDefinition) ([]string, []any) {
	var values []string
	var keep []any
	seen := map[string]bool{}
	add := func(s string) {
		for _, v := range splitPropertyValue(s, p.Format) {
			if !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
	}
	visit := func(v any, own bool) {
		switch x := v.(type) {
		case string:
			add(x)
		case []string:
			for _, s := range x {
				add(s)
			}
		case []any:
			for _, e := range x {
				if s, ok := e.(string); ok {
					add(s)
				} else if own && e != nil {
					keep = append(keep, e)
				}
			}
		case map[string]any:
			if p.Format == PropertyFormatIP {
				if s, ok := x["address"].(string); ok {
					add(s)
				}
			}
		}
	}
	visit(props[p.Key], true)
	for _, s := range p.Synonyms {
		visit(props[s], false)
	}
	return values, keep
}

// splitPropertyValue returns the values one string holds: for an `ip` key
// the addresses of a comma- or space-separated list in canonical form (not
// an address: none), otherwise the trimmed string.
func splitPropertyValue(s string, format PropertyFormat) []string {
	if format != PropertyFormatIP {
		if s = strings.TrimSpace(s); s == "" {
			return nil
		}
		return []string{s}
	}
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if ip := net.ParseIP(strings.TrimSpace(f)); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// PropertyStrings returns the string values an asset holds for a canonical
// key, from the key and from any synonym not yet folded (rows written before
// the normalisation), deduplicated in order. It does not change props.
func PropertyStrings(props map[string]any, key string) []string {
	if len(props) == 0 {
		return nil
	}
	p, ok := propertyIndex[key]
	if !ok {
		p = &PropertyDefinition{Key: key}
	}
	values, _ := collectPropertyValues(props, p)
	return values
}

// IPAddresses returns the IP addresses an asset's properties record, in
// canonical form, from ip_addresses and its synonyms. Scope exclusion,
// correlation and relationship inference all read addresses through it.
func IPAddresses(props map[string]any) []string {
	return PropertyStrings(props, PropKeyIPAddresses)
}

// AddIPAddress adds ip (when it parses) to the asset's ip_addresses,
// folding synonyms first.
func AddIPAddress(props map[string]any, ip string) {
	if props == nil {
		return
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return
	}
	NormalizeProperties(props)
	ips := IPAddresses(props)
	if slices.Contains(ips, parsed.String()) {
		return
	}
	list := make([]any, 0, len(ips)+1)
	for _, v := range ips {
		list = append(list, v)
	}
	props[PropKeyIPAddresses] = append(list, parsed.String())
}

// AddressPropertyKeys returns ip_addresses and every synonym of it: the keys
// a database query must read to see an address recorded on a row that has
// not been normalised.
func AddressPropertyKeys() []string {
	p := propertyIndex[PropKeyIPAddresses]
	return append([]string{PropKeyIPAddresses}, p.Synonyms...)
}
