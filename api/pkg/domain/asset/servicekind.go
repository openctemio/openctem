package asset

// Service kinds: what a service asset speaks (docs/architecture/service-kinds.md).
//
// A service's kind is its application protocol from the closed list in the
// registry (configs/asset-types.yaml, service_kinds), its category follows
// from the kind, and its source says how the platform knows it. The three
// keys are derived here on every write of a service and nowhere else: a
// client or a report never sets them (they are reserved property keys).
//
// Precedence: a source never overwrites the kind of a higher one; an equal
// one does (the service may have changed). The source of a write is decided
// by the platform (the capability the report was bound to), never taken
// from the producer. A port guess (the port's IANA default service) is the
// lowest source: it is shown as a guess and never drives an exposure, a
// finding or an active check.

import (
	"strconv"
	"strings"
)

// Service kind property keys (all derived; see reservedPropertyKeys).
const (
	PropKeyServiceKind     = "service_kind"
	PropKeyServiceCategory = "service_category"
	PropKeyKindSource      = "kind_source"
	// PropKeyHasAnonymousAccess is a measured fact: a probe saw the service
	// answer without credentials. Only a true value is recorded.
	PropKeyHasAnonymousAccess = "has_anonymous_access"
)

// KindSource is the evidence behind a service kind.
type KindSource string

// Kind sources, highest confidence first (registry kind_sources).
const (
	KindSourceFingerprint KindSource = "fingerprint"
	KindSourceTLSALPN     KindSource = "tls_alpn"
	KindSourceHTTPProbe   KindSource = "http_probe"
	KindSourceReported    KindSource = "reported"
	KindSourcePortGuess   KindSource = "port_guess"
)

// ServiceCategoryDefinition is one service category.
type ServiceCategoryDefinition struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	LabelVI string `json:"label_vi"`
}

// KindSourceDefinition is one kind source and its confidence (1..100).
type KindSourceDefinition struct {
	ID         KindSource `json:"id"`
	Label      string     `json:"label"`
	LabelVI    string     `json:"label_vi"`
	Confidence int        `json:"confidence"`
}

// ServiceKindDefinition is one service kind.
type ServiceKindDefinition struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	LabelVI  string `json:"label_vi"`
	Category string `json:"category"`
	// TCP and UDP are the IANA default ports a port guess uses.
	TCP []int `json:"tcp,omitempty"`
	UDP []int `json:"udp,omitempty"`
	// Aliases are other names producers use for the kind; TLSAliases also
	// say the service speaks TLS (https, imaps).
	Aliases    []string `json:"aliases,omitempty"`
	TLSAliases []string `json:"tls_aliases,omitempty"`
	// Risk is the severity of the exposure an internet-facing service of
	// the kind raises once its kind was measured ("" = none);
	// RiskAnonymous the severity when anonymous access was observed.
	Risk          string `json:"risk,omitempty"`
	RiskAnonymous string `json:"risk_anonymous,omitempty"`
}

type serviceName struct {
	kind string
	tls  bool
}

var (
	serviceKindIndex   = map[string]*ServiceKindDefinition{}
	serviceNameIndex   = map[string]serviceName{}
	servicePortIndex   = map[string]string{} // "tcp/22" -> kind
	kindSourceIndex    = map[KindSource]int{}
	serviceCategorySet = map[string]bool{}
)

func init() {
	for i := range registryServiceKinds {
		k := &registryServiceKinds[i]
		serviceKindIndex[k.ID] = k
		serviceNameIndex[k.ID] = serviceName{kind: k.ID}
		for _, a := range k.Aliases {
			serviceNameIndex[a] = serviceName{kind: k.ID}
		}
		for _, a := range k.TLSAliases {
			serviceNameIndex[a] = serviceName{kind: k.ID, tls: true}
		}
		for _, p := range k.TCP {
			servicePortIndex[portKeyOf("tcp", p)] = k.ID
		}
		for _, p := range k.UDP {
			servicePortIndex[portKeyOf("udp", p)] = k.ID
		}
	}
	for _, s := range registryKindSources {
		kindSourceIndex[s.ID] = s.Confidence
	}
	for _, c := range registryServiceCategories {
		serviceCategorySet[c.ID] = true
	}
}

func portKeyOf(transport string, port int) string {
	return transport + "/" + strconv.Itoa(port)
}

// ServiceKinds returns every service kind in registry order. Callers must
// not modify it.
func ServiceKinds() []ServiceKindDefinition { return registryServiceKinds }

// LookupServiceKind returns the definition of a kind id.
func LookupServiceKind(id string) (ServiceKindDefinition, bool) {
	k, ok := serviceKindIndex[id]
	if !ok {
		return ServiceKindDefinition{}, false
	}
	return *k, true
}

// IsServiceCategory reports whether id is a service category.
func IsServiceCategory(id string) bool { return serviceCategorySet[id] }

// Confidence is the source's confidence (1..100); 0 for an unknown source.
func (s KindSource) Confidence() int { return kindSourceIndex[s] }

// IsValid reports whether s is a kind source of the registry.
func (s KindSource) IsValid() bool { return kindSourceIndex[s] > 0 }

// IsGuess reports whether the kind was only guessed from the port.
func (s KindSource) IsGuess() bool { return s == KindSourcePortGuess }

// normalServiceName is the form a producer's protocol name is matched in:
// lower case, `_` and spaces read as `-`. Keep in sync with
// cmd/gen-asset-types normalServiceName.
func normalServiceName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("_", "-", " ", "-").Replace(s)
}

// notProtocols are values producers put where a protocol belongs that name
// no protocol: a transport, or a scanner's "could not tell".
var notProtocols = func() map[string]bool {
	m := map[string]bool{}
	//nolint:goconst // scanners' placeholder words, not the risk level of the same spelling
	for _, s := range []string{"", "tcp", "udp", "sctp", "unknown", "general", "tcpwrapped", "none", "-"} {
		m[s] = true
	}
	return m
}()

// maxProtocolNameLength bounds the names looked up (a protocol name is
// short; anything longer is not one of ours).
const maxProtocolNameLength = 64

// The web sub-type of a service and the kind it speaks.
const (
	serviceSubTypeHTTP = "http"
	serviceKindHTTP    = "http"
)

// ServiceProtocol is one reading of a producer's protocol name.
type ServiceProtocol struct {
	// Kind is the matched kind ("" when the name is none of ours).
	Kind string
	// Named: the value names a protocol (not empty, not a transport).
	Named bool
	// TLS: the name says the service speaks TLS (https, ssl/http).
	TLS bool
	// Guess: the producer marked the name as a guess (trailing "?").
	Guess bool
}

// ParseServiceProtocol reads a producer's protocol name (IANA service
// name, scanner name, "ssl/http", "ssh?").
func ParseServiceProtocol(raw string) ServiceProtocol {
	if len(raw) > maxProtocolNameLength {
		return ServiceProtocol{}
	}
	n := normalServiceName(raw)
	var p ServiceProtocol
	if strings.HasSuffix(n, "?") {
		p.Guess = true
		n = strings.TrimRight(n, "?")
	}
	for _, prefix := range []string{"ssl/", "tls/"} {
		if rest, ok := strings.CutPrefix(n, prefix); ok {
			p.TLS = true
			n = rest
		}
	}
	if notProtocols[n] {
		return ServiceProtocol{}
	}
	p.Named = true
	if s, ok := serviceNameIndex[n]; ok {
		p.Kind = s.kind
		p.TLS = p.TLS || s.tls
	}
	return p
}

// GuessServiceKind returns the kind a port guess gives a port of a
// transport ("" when the port has no well-known service).
func GuessServiceKind(transport string, port int) string {
	t := normalServiceName(transport)
	if t == "" {
		t = "tcp"
	}
	return servicePortIndex[portKeyOf(t, port)]
}

// ServiceClassification is the kind one write of a service gives it.
type ServiceClassification struct {
	Kind     string
	Category string
	Source   KindSource
	// TLS: a measured name says the service speaks TLS.
	TLS bool
}

// ClassifyService derives the classification a write gives a service from
// the write's own facts: incoming holds what this write reports (its
// protocol is the only name read), stored the asset's current properties
// (port and transport, which are part of the service's identity, are read
// from either). evidence is the source of a name this write reports, as the
// platform decided it. ok is false when the write says nothing about the
// kind: a measured name that is none of ours never falls back to a guess.
func ClassifyService(subType string, incoming, stored map[string]any, evidence KindSource) (ServiceClassification, bool) {
	if !evidence.IsValid() || evidence.IsGuess() {
		evidence = KindSourceReported
	}
	if raw, ok := incoming["protocol"].(string); ok {
		p := ParseServiceProtocol(raw)
		switch {
		case p.Kind != "" && !p.Guess:
			return classification(p.Kind, evidence, p.TLS), true
		case p.Kind != "" && p.Guess:
			return classification(p.Kind, KindSourcePortGuess, false), true
		case p.Named && !p.Guess:
			return ServiceClassification{}, false
		}
	}
	// A web service (an HTTP probe answered on it) speaks HTTP.
	if subType == serviceSubTypeHTTP {
		tls := false
		if s, _ := firstString(incoming, stored, "scheme"); strings.EqualFold(s, "https") {
			tls = true
		}
		return classification(serviceKindHTTP, evidence, tls), true
	}
	port := firstInt(incoming, stored, "port")
	if port <= 0 || port > 65535 {
		return ServiceClassification{}, false
	}
	transport, _ := firstString(incoming, stored, "transport")
	if kind := GuessServiceKind(transport, port); kind != "" {
		return classification(kind, KindSourcePortGuess, false), true
	}
	return ServiceClassification{}, false
}

func classification(kind string, src KindSource, tls bool) ServiceClassification {
	c := ServiceClassification{Kind: kind, Source: src, TLS: tls && !src.IsGuess()}
	if k, ok := serviceKindIndex[kind]; ok {
		c.Category = k.Category
	}
	return c
}

// ApplyServiceClassification writes c into props unless props holds a kind
// of a higher source. A measured TLS name sets has_tls. It reports whether
// the kind keys changed.
func ApplyServiceClassification(props map[string]any, c ServiceClassification) bool {
	if props == nil || c.Kind == "" || !c.Source.IsValid() {
		return false
	}
	if cur, ok := props[PropKeyKindSource].(string); ok && KindSource(cur).Confidence() > c.Source.Confidence() {
		if _, hasKind := props[PropKeyServiceKind].(string); hasKind {
			return false
		}
	}
	changed := props[PropKeyServiceKind] != c.Kind || props[PropKeyServiceCategory] != c.Category ||
		props[PropKeyKindSource] != string(c.Source)
	props[PropKeyServiceKind] = c.Kind
	props[PropKeyServiceCategory] = c.Category
	props[PropKeyKindSource] = string(c.Source)
	if c.TLS && !c.Source.IsGuess() {
		props["has_tls"] = true
	}
	return changed
}

// ClassifyService classifies a service asset from what one write reported
// (incoming, the write's own properties) with the given source. Other types
// are left alone.
func (a *Asset) ClassifyService(incoming map[string]any, evidence KindSource) {
	if a == nil || a.Type() != AssetTypeService {
		return
	}
	if a.properties == nil {
		a.properties = map[string]any{}
	}
	if c, ok := ClassifyService(a.SubType(), incoming, a.properties, evidence); ok {
		ApplyServiceClassification(a.properties, c)
	}
}

// ServiceKindOf returns an asset's stored kind and source ("" when none).
func ServiceKindOf(props map[string]any) (string, KindSource) {
	kind, _ := props[PropKeyServiceKind].(string)
	src, _ := props[PropKeyKindSource].(string)
	if _, ok := serviceKindIndex[kind]; !ok {
		return "", ""
	}
	return kind, KindSource(src)
}

func firstString(a, b map[string]any, key string) (string, bool) {
	for _, m := range []map[string]any{a, b} {
		if s, ok := m[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s), true
		}
	}
	return "", false
}

func firstInt(a, b map[string]any, key string) int {
	for _, m := range []map[string]any{a, b} {
		switch v := m[key].(type) {
		case int:
			return v
		case int64:
			if v >= 0 && v <= 65535 {
				return int(v)
			}
		case float64:
			if v >= 0 && v <= 65535 && v == float64(int(v)) {
				return int(v)
			}
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		}
	}
	return 0
}
