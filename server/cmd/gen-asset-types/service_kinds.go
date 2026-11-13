package main

// Service kinds (docs/architecture/service-kinds.md): the closed list of
// application protocols a service asset is classified as, the categories
// they belong to and the sources a kind is learned from. Declared in
// configs/asset-types.yaml next to the types, generated into the Go and
// TypeScript registry files, and served with the registry.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// serviceCategoryCfg is one service category.
type serviceCategoryCfg struct {
	ID      string `yaml:"id" json:"id"`
	Label   string `yaml:"label" json:"label"`
	LabelVI string `yaml:"label_vi" json:"label_vi"`
}

// kindSourceCfg is one source a service kind is learned from.
type kindSourceCfg struct {
	ID         string `yaml:"id" json:"id"`
	Label      string `yaml:"label" json:"label"`
	LabelVI    string `yaml:"label_vi" json:"label_vi"`
	Confidence int    `yaml:"confidence" json:"confidence"`
}

// serviceKindCfg is one service kind.
type serviceKindCfg struct {
	ID            string   `yaml:"id" json:"id"`
	Label         string   `yaml:"label" json:"label"`
	LabelVI       string   `yaml:"label_vi" json:"label_vi"`
	Category      string   `yaml:"category" json:"category"`
	TCP           []int    `yaml:"tcp" json:"tcp,omitempty"`
	UDP           []int    `yaml:"udp" json:"udp,omitempty"`
	Aliases       []string `yaml:"aliases" json:"aliases,omitempty"`
	TLSAliases    []string `yaml:"tls_aliases" json:"tls_aliases,omitempty"`
	Risk          string   `yaml:"risk" json:"risk,omitempty"`
	RiskAnonymous string   `yaml:"risk_anonymous" json:"risk_anonymous,omitempty"`
}

// attrTypeEnum is the enum attribute type.
const attrTypeEnum = "enum"

// valuesFromSections are the registry sections an enum attribute may take
// its values from (`values_from`).
const (
	valuesServiceKinds      = "service_kinds"
	valuesServiceCategories = "service_categories"
	valuesKindSources       = "kind_sources"
)

var (
	// A kind id is a protocol name: lower case, digits and hyphens
	// (docker-api, ethernet-ip).
	kindIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)
	// An alias is matched in its normal form (normalServiceName).
	aliasRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]*$`)
	riskOrder = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
)

// normalServiceName is the form a producer's protocol name is matched in:
// lower case, `_` and spaces read as `-`. Keep in sync with
// pkg/domain/asset.normalServiceName.
func normalServiceName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("_", "-", " ", "-").Replace(s)
}

// resolveServiceKinds validates the service sections, fills the values of
// every `values_from` attribute and returns the sections for the model.
//
//nolint:gocognit,gocyclo,cyclop // one linear validation pass
func resolveServiceKinds(cfg *config) error {
	if len(cfg.ServiceKinds) > 0 && (len(cfg.ServiceCategories) == 0 || len(cfg.KindSources) == 0) {
		return fmt.Errorf("service_kinds need service_categories and kind_sources")
	}
	categories := map[string]bool{}
	for _, c := range cfg.ServiceCategories {
		switch {
		case !identRe.MatchString(c.ID):
			return fmt.Errorf("service category %q: must be lower snake_case", c.ID)
		case categories[c.ID]:
			return fmt.Errorf("duplicate service category %q", c.ID)
		case c.Label == "" || c.LabelVI == "":
			return fmt.Errorf("service category %q: label and label_vi are required", c.ID)
		}
		categories[c.ID] = true
	}
	sources := map[string]bool{}
	last := 101
	for _, s := range cfg.KindSources {
		switch {
		case !identRe.MatchString(s.ID):
			return fmt.Errorf("kind source %q: must be lower snake_case", s.ID)
		case sources[s.ID]:
			return fmt.Errorf("duplicate kind source %q", s.ID)
		case s.Label == "" || s.LabelVI == "":
			return fmt.Errorf("kind source %q: label and label_vi are required", s.ID)
		case s.Confidence < 1 || s.Confidence >= last:
			return fmt.Errorf("kind source %q: confidence must be in 1..100 and below the source before it (highest first)", s.ID)
		}
		sources[s.ID] = true
		last = s.Confidence
	}
	kinds := map[string]bool{}
	names := map[string]string{} // normal name -> kind
	ports := map[string]string{} // "tcp/22" -> kind
	for i := range cfg.ServiceKinds {
		k := &cfg.ServiceKinds[i]
		where := fmt.Sprintf("service kind %q", k.ID)
		switch {
		case !kindIDRe.MatchString(k.ID):
			return fmt.Errorf("%s: must be lower case letters, digits and hyphens", where)
		case kinds[k.ID]:
			return fmt.Errorf("duplicate service kind %q", k.ID)
		case k.Label == "":
			return fmt.Errorf("%s: label is required", where)
		case !categories[k.Category]:
			return fmt.Errorf("%s: unknown category %q", where, k.Category)
		case k.Risk != "" && riskOrder[k.Risk] == 0:
			return fmt.Errorf("%s: risk %q is not low, medium, high or critical", where, k.Risk)
		case k.RiskAnonymous != "" && (k.Risk == "" || riskOrder[k.RiskAnonymous] < riskOrder[k.Risk]):
			return fmt.Errorf("%s: risk_anonymous needs a risk and must not be below it", where)
		}
		if k.LabelVI == "" {
			k.LabelVI = k.Label
		}
		kinds[k.ID] = true
		for _, transport := range []struct {
			name  string
			ports []int
		}{{"tcp", k.TCP}, {"udp", k.UDP}} {
			for _, p := range transport.ports {
				key := fmt.Sprintf("%s/%d", transport.name, p)
				switch {
				case p < 1 || p > 65535:
					return fmt.Errorf("%s: port %d out of range", where, p)
				case ports[key] != "":
					return fmt.Errorf("%s: port %s already belongs to %q", where, key, ports[key])
				}
				ports[key] = k.ID
			}
		}
		for _, list := range [][]string{{k.ID}, k.Aliases, k.TLSAliases} {
			for _, a := range list {
				n := normalServiceName(a)
				switch {
				case n != a || !aliasRe.MatchString(a):
					return fmt.Errorf("%s: alias %q must be written in its normal form (lower case, - for _ and spaces)", where, a)
				case names[n] != "":
					return fmt.Errorf("%s: name %q already names %q", where, a, names[n])
				}
				names[n] = k.ID
			}
		}
	}
	// A kind id is a name of its own kind only.
	for _, k := range cfg.ServiceKinds {
		for _, a := range slices.Concat(k.Aliases, k.TLSAliases) {
			if kinds[a] && a != k.ID {
				return fmt.Errorf("service kind %q: alias %q is another kind's id", k.ID, a)
			}
		}
	}

	values := map[string][]string{valuesServiceKinds: {}, valuesServiceCategories: {}, valuesKindSources: {}}
	for _, k := range cfg.ServiceKinds {
		values[valuesServiceKinds] = append(values[valuesServiceKinds], k.ID)
	}
	for _, c := range cfg.ServiceCategories {
		values[valuesServiceCategories] = append(values[valuesServiceCategories], c.ID)
	}
	for _, s := range cfg.KindSources {
		values[valuesKindSources] = append(values[valuesKindSources], s.ID)
	}
	for ti := range cfg.Types {
		for ai := range cfg.Types[ti].Attributes {
			a := &cfg.Types[ti].Attributes[ai]
			if a.ValuesFrom == "" {
				continue
			}
			vs, ok := values[a.ValuesFrom]
			switch {
			case !ok || len(vs) == 0:
				return fmt.Errorf("type %q attribute %q: values_from %q is not one of %s, %s, %s",
					cfg.Types[ti].Type, a.Name, a.ValuesFrom, valuesServiceKinds, valuesServiceCategories, valuesKindSources)
			case a.Type != attrTypeEnum || len(a.Values) > 0:
				return fmt.Errorf("type %q attribute %q: values_from needs an enum without values", cfg.Types[ti].Type, a.Name)
			}
			a.Values = slices.Clone(vs)
		}
	}
	return nil
}

// renderGoServiceKinds writes the service sections of the Go registry.
func renderGoServiceKinds(w func(string, ...any), m *model) {
	ints := func(xs []int) string {
		if len(xs) == 0 {
			return "nil"
		}
		s := make([]string, len(xs))
		for i, x := range xs {
			s[i] = fmt.Sprint(x)
		}
		return "[]int{" + strings.Join(s, ", ") + "}"
	}
	w("var registryServiceCategories = []ServiceCategoryDefinition{\n")
	for _, c := range m.ServiceCategories {
		w("{ID: %q, Label: %q, LabelVI: %q},\n", c.ID, c.Label, c.LabelVI)
	}
	w("}\n\nvar registryKindSources = []KindSourceDefinition{\n")
	for _, s := range m.KindSources {
		w("{ID: %q, Label: %q, LabelVI: %q, Confidence: %d},\n", s.ID, s.Label, s.LabelVI, s.Confidence)
	}
	w("}\n\nvar registryServiceKinds = []ServiceKindDefinition{\n")
	for _, k := range m.ServiceKinds {
		w("{ID: %q, Label: %q, LabelVI: %q, Category: %q", k.ID, k.Label, k.LabelVI, k.Category)
		if len(k.TCP) > 0 {
			w(", TCP: %s", ints(k.TCP))
		}
		if len(k.UDP) > 0 {
			w(", UDP: %s", ints(k.UDP))
		}
		if len(k.Aliases) > 0 {
			w(", Aliases: %s", goStrings(k.Aliases))
		}
		if len(k.TLSAliases) > 0 {
			w(", TLSAliases: %s", goStrings(k.TLSAliases))
		}
		if k.Risk != "" {
			w(", Risk: %q", k.Risk)
		}
		if k.RiskAnonymous != "" {
			w(", RiskAnonymous: %q", k.RiskAnonymous)
		}
		w("},\n")
	}
	w("}\n\n")
}

// renderTSServiceKinds writes the service kind, category and source labels
// of the TypeScript registry (the web labels facet values and attributes
// with them before the registry loads).
func renderTSServiceKinds(w func(string, ...any), m *model) {
	label := func(id, en, vi string) {
		w("  %s: { label: %s, labelVi: %s },\n", tsKey(id), tsString(en), tsString(vi))
	}
	w("export interface RegistryValueLabel {\n  label: string\n  labelVi: string\n}\n\n")
	w("/** Service categories (attribute service_category), in display order. */\n")
	w("export const SERVICE_CATEGORY_LABELS: Readonly<Record<string, RegistryValueLabel>> = {\n")
	for _, c := range m.ServiceCategories {
		label(c.ID, c.Label, c.LabelVI)
	}
	w("}\n\n/** Kind sources (attribute kind_source), highest confidence first. */\n")
	w("export const KIND_SOURCES: ReadonlyArray<RegistryValueLabel & { id: string; confidence: number }> = [\n")
	for _, s := range m.KindSources {
		w("  { id: '%s', label: %s, labelVi: %s, confidence: %d },\n", s.ID, tsString(s.Label), tsString(s.LabelVI), s.Confidence)
	}
	w("]\n\n/** Service kinds (attribute service_kind) with their category. */\n")
	w("export const SERVICE_KIND_LABELS: Readonly<Record<string, RegistryValueLabel & { category: string }>> = {\n")
	for _, k := range m.ServiceKinds {
		w("  %s: { label: %s, labelVi: %s, category: '%s' },\n", tsKey(k.ID), tsString(k.Label), tsString(k.LabelVI), k.Category)
	}
	w("}\n\n")
}

// tsKey is an object key: bare when it is an identifier, quoted otherwise
// (docker-api).
func tsKey(id string) string {
	if strings.Contains(id, "-") {
		return "'" + id + "'"
	}
	return id
}

// renderServiceKindsSQL prints the lookup tables of the service kind
// backfill (`-service-kinds-sql`): every name with its kind, every default
// port with its kind and every kind with its category, as SQL VALUES lists
// a migration pastes. A migration is frozen once merged; rows reach later
// table changes on their next scan.
func renderServiceKindsSQL(m *model) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	names := make([]string, 0, len(m.ServiceKinds)*3)
	ports := make([]string, 0, len(m.ServiceKinds))
	kinds := make([]string, 0, len(m.ServiceKinds))
	for _, k := range m.ServiceKinds {
		kinds = append(kinds, fmt.Sprintf("(%s, %s)", sqlString(k.ID), sqlString(k.Category)))
		for _, n := range slices.Concat([]string{k.ID}, k.Aliases, k.TLSAliases) {
			names = append(names, fmt.Sprintf("(%s, %s)", sqlString(n), sqlString(k.ID)))
		}
		for _, p := range k.TCP {
			ports = append(ports, fmt.Sprintf("('tcp', %d, %s)", p, sqlString(k.ID)))
		}
		for _, p := range k.UDP {
			ports = append(ports, fmt.Sprintf("('udp', %d, %s)", p, sqlString(k.ID)))
		}
	}
	w("kind_names(name, kind) AS (VALUES\n    %s),\n", strings.Join(names, ",\n    "))
	w("kind_ports(transport, port, kind) AS (VALUES\n    %s),\n", strings.Join(ports, ",\n    "))
	w("kind_categories(kind, category) AS (VALUES\n    %s)\n", strings.Join(kinds, ",\n    "))
	return b.String()
}
