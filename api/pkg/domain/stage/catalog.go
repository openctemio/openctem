// Package stage is the scan stage catalog: the code-reviewed type system
// of scan composition. Design: docs/rfcs/RFC-046-scans-redesign.md (§5, the
// stage catalog) and research/27 §4-§6 (owner decisions G1-G12).
//
// A stage is one capability ("discover.subdomains", "probe.http", ...). It
// declares the asset types it consumes and produces and its intrusiveness
// tier. Which tools implement it, under which settings keys and whether
// they take a target list, is not in this package: it comes from the tool
// contracts an organization's sensors report (WithTools, RFC-092). The
// platform connects one stage's
// outputs to the next stage's inputs by type, through the inventory and the
// per-hop gate; a sensor never feeds another sensor.
//
// The catalog is platform data. A tenant, a sensor or a report cannot
// widen it: a sensor's manifest may only narrow what it runs, and a report
// bound to a stage may only create the asset types the stage declares.
package stage

import (
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// Key is a stage's capability key, "<verb>.<object>".
type Key string

// Stage keys of catalog v1.
const (
	DiscoverSubdomains Key = "discover.subdomains"
	ResolveDNS         Key = "resolve.dns"
	LookupRDAP         Key = "lookup.rdap"
	LookupASN          Key = "lookup.asn"
	DiscoverHosts      Key = "discover.hosts"
	ScanPorts          Key = "scan.ports"
	ProbeHTTP          Key = "probe.http"
	CrawlWeb           Key = "crawl.web"
	VulnTemplates      Key = "vuln.templates"
	DASTWeb            Key = "dast.web"
	SecretsCode        Key = "secrets.code"
	SASTCode           Key = "sast.code"
	SCADeps            Key = "sca.deps"
	IaCMisconfig       Key = "iac.misconfig"
	ContainerImage     Key = "container.image"
	NetworkVAConnector Key = "network_va.connector"
)

// Tier is how intrusive a stage is toward its targets.
type Tier int

const (
	// TierPassive (T0): no traffic to the target beyond DNS, or no target
	// traffic at all (third-party sources, code and image analysis). A T0
	// stage may take names that are not confirmed yet (discovered,
	// needs_review, candidate); it never takes a rejected or tombstoned
	// name.
	TierPassive Tier = 0
	// TierActive (T1): non-intrusive active checks (connect scans, HTTP
	// probes, crawling, non-intrusive templates). A T1 stage takes only
	// what the active-scan ownership gate allows.
	TierActive Tier = 1
	// TierIntrusive (T2): intrusive checks (fuzzing, intrusive templates).
	// Needs an approver and a verified seed (RFC-036 O3); not planned by
	// the P0 router.
	TierIntrusive Tier = 2
)

// String is the tier's label ("T0", "T1", "T2").
func (t Tier) String() string { return fmt.Sprintf("T%d", int(t)) }

// Passive reports whether the tier sends no active traffic (T0).
func (t Tier) Passive() bool { return t == TierPassive }

// Implementation is one tool that runs a stage.
type Implementation struct {
	// Tool is the tool registry name.
	Tool string `json:"tool"`
	// Default marks the implementation the planner picks for a step that
	// names only the capability. Exactly one per stage.
	Default bool `json:"default"`
	// Batch: the tool takes a list of targets in one task; otherwise one
	// target per task (the contract's input.batch).
	Batch bool `json:"batch"`
	// ByCapability: the tool runs this stage only for a step or job that
	// names the capability: it is not the tool's primary capability (the
	// first its contract implements). A step that pins the tool without
	// naming a capability runs the primary one (naabu: a port scan, not
	// host discovery).
	ByCapability bool `json:"by_capability,omitempty"`
	// Params maps the capability's standard params this tool accepts to
	// the tool's own config key (the contract's implements[].params).
	Params map[string]string `json:"params"`
}

// Stage is one catalog entry.
type Stage struct {
	Key         Key    `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Inputs are the stored (type, sub_type) pairs the stage may be handed
	// as targets; an empty SubType matches any sub-type.
	Inputs []asset.TypeRef `json:"inputs"`
	// Outputs are the stored pairs a report of the stage may create.
	Outputs []asset.TypeRef `json:"outputs"`
	// Relations are the relationship types the stage's outputs carry.
	Relations []string `json:"relations,omitempty"`
	// Findings: the stage reports findings.
	Findings bool `json:"findings"`
	// Endpoints: the stage reports web endpoints (CTIS 1.6 endpoints[]).
	Endpoints bool `json:"endpoints,omitempty"`
	Tier      Tier `json:"tier"`
	// Implementations, the default first: set only on a stage of an
	// organization's Catalog, from the contracts its sensors report.
	Implementations []Implementation `json:"implementations"`
	// MaxFanout bounds how many derived targets one run hands this stage.
	// An engine may lower it, never raise it.
	MaxFanout int `json:"max_fanout"`
	// MaxPerParent bounds how many derived targets one parent may
	// contribute (a domain with more subdomains than this is a suspected
	// wildcard); 0 means MaxFanout.
	MaxPerParent int `json:"max_per_parent,omitempty"`
	// Legacy are the capability words of the pre-catalog vocabulary
	// (tools.capabilities, workflow step capabilities) that name this stage
	// on their own.
	Legacy []string `json:"-"`

	// The capability contract (contract.go): major version, typed ports,
	// standard params and the fields a report must carry. Tier is the
	// contract's tier floor.
	Version              int        `json:"version"`
	InPorts              []PortType `json:"in_ports"`
	OutPorts             []PortType `json:"out_ports"`
	Params               []Param    `json:"params"`
	RequiredOutputFields []string   `json:"required_output_fields"`
	// ChunkSize is how many targets one task of a list-taking tool gets
	// when a workflow step's targets are cut into chunks that any eligible
	// sensor may claim (0: the step stays one task).
	ChunkSize int `json:"chunk_size,omitempty"`
	// CrossCutting capabilities (verify.finding) are used by other flows,
	// never as a workflow node.
	CrossCutting bool `json:"cross_cutting,omitempty"`

	// From the capability taxonomy (ctis/capability): the engagement phase
	// and its CTEM stage, the MITRE ATT&CK techniques and D3FEND functions
	// of the act, and the required-output rules a report is checked
	// against.
	Phase          string            `json:"phase,omitempty"`
	CTEMStage      string            `json:"ctem_stage,omitempty"`
	Attack         []string          `json:"attack,omitempty"`
	D3FEND         []string          `json:"d3fend,omitempty"`
	RequiredOutput []capability.Rule `json:"required_output,omitempty"`
}

// Fan-out caps (research/27 §5.6). The run cap stays the dispatch cap of a
// scan run (10 000 targets).
const (
	RunFanoutCap       = 10000
	DefaultPerParent   = 5000
	webFanoutCap       = 5000
	connectorFanoutCap = 2000
)

// Run-wide chain depth (owner decision G5): how many discovery hops a
// derived target may be from the run's seeds.
const MaxHops = 3

// Stored pairs of catalog v1. Alias type names (http_service, open_port,
// website, ...) are input-only (RFC-042 §6.3.8): the catalog names the
// stored pair they resolve to.
var (
	tDomain        = asset.TypeRef{Type: asset.AssetTypeDomain}
	tSubdomain     = asset.TypeRef{Type: asset.AssetTypeSubdomain}
	tIP            = asset.TypeRef{Type: asset.AssetTypeIPAddress}
	tHost          = asset.TypeRef{Type: asset.AssetTypeHost}
	tCertificate   = asset.TypeRef{Type: asset.AssetTypeCertificate}
	tNetwork       = asset.TypeRef{Type: asset.AssetTypeNetwork}
	tContainer     = asset.TypeRef{Type: asset.AssetTypeContainer}
	tHTTPService   = asset.TypeRef{Type: asset.AssetTypeService, SubType: "http"}
	tOpenPort      = asset.TypeRef{Type: asset.AssetTypeService, SubType: "open_port"}
	tDiscoveredURL = asset.TypeRef{Type: asset.AssetTypeService, SubType: "discovered_url"}
	tWebsite       = asset.TypeRef{Type: asset.AssetTypeApplication, SubType: "website"}
	tAPI           = asset.TypeRef{Type: asset.AssetTypeApplication, SubType: "api"}

	dnsNames   = []asset.TypeRef{tDomain, tSubdomain}
	codeInputs = []asset.TypeRef{canonical(asset.AssetTypeRepository)}
)

// canonical is the stored pair of a type name (a core type is itself).
func canonical(t asset.AssetType) asset.TypeRef { return asset.CanonicalPair(t, "") }

// catalog is catalog v1 (research/27 §6.1). Order is display order.
var catalog = []Stage{
	{
		Key: DiscoverSubdomains, Name: "Subdomain discovery",
		Description: "Find subdomains of a root domain from passive sources.",
		Inputs:      []asset.TypeRef{tDomain},
		Outputs:     dnsNames,
		Relations:   []string{"subdomain_of"},
		Tier:        TierPassive,
		MaxFanout:   RunFanoutCap, MaxPerParent: DefaultPerParent,
		Legacy: []string{"subdomain"},
	},
	{
		Key: ResolveDNS, Name: "DNS resolution",
		Description: "Resolve names to addresses and aliases.",
		Inputs:      dnsNames,
		Outputs:     []asset.TypeRef{tDomain, tSubdomain, tIP},
		Relations:   []string{string(asset.RelTypeResolvesTo), string(asset.RelTypeCnameOf)},
		Tier:        TierPassive,
		MaxFanout:   RunFanoutCap, MaxPerParent: DefaultPerParent,
		Legacy: []string{"dns"},
	},
	{
		Key: LookupRDAP, Name: "Domain registration lookup",
		Description: "Registrar, registrant organization, name servers and registration dates of a root domain, from the RDAP service of its registry.",
		Inputs:      []asset.TypeRef{tDomain},
		Outputs:     []asset.TypeRef{tDomain},
		Tier:        TierPassive,
		MaxFanout:   RunFanoutCap, MaxPerParent: DefaultPerParent,
	},
	{
		Key: LookupASN, Name: "Network ownership lookup",
		Description: "Origin autonomous system, holder and announced range of an address or network, from public routing data.",
		Inputs:      []asset.TypeRef{tIP, tNetwork},
		Outputs:     []asset.TypeRef{tIP, tNetwork},
		Tier:        TierPassive,
		MaxFanout:   RunFanoutCap, MaxPerParent: DefaultPerParent,
	},
	{
		Key: DiscoverHosts, Name: "Host discovery",
		Description: "Find the live addresses of a range or an address list with light probes before deeper scans.",
		Inputs:      []asset.TypeRef{tIP, tNetwork},
		Outputs:     []asset.TypeRef{tIP},
		Tier:        TierActive,
		MaxFanout:   RunFanoutCap, MaxPerParent: DefaultPerParent,
	},
	{
		Key: ScanPorts, Name: "Port scan",
		Description: "Find open TCP ports (connect scan).",
		Inputs:      []asset.TypeRef{tDomain, tSubdomain, tIP, tHost},
		Outputs:     []asset.TypeRef{tIP, tHost, tOpenPort},
		Relations:   []string{string(asset.RelTypeExposes)},
		Tier:        TierActive,
		MaxFanout:   RunFanoutCap, MaxPerParent: DefaultPerParent,
		Legacy: []string{"portscan"},
	},
	{
		Key: ProbeHTTP, Name: "HTTP probe",
		Description: "Probe web services: status, title, technologies, TLS certificate.",
		Inputs: []asset.TypeRef{
			tDomain, tSubdomain, tIP,
			tHost, tOpenPort, tHTTPService,
		},
		Outputs: []asset.TypeRef{
			tHTTPService, tCertificate, tIP,
		},
		Relations: []string{"serves_certificate", "hosted_by"},
		Tier:      TierActive,
		MaxFanout: RunFanoutCap, MaxPerParent: DefaultPerParent,
		Legacy: []string{"http"},
	},
	{
		Key: CrawlWeb, Name: "Web crawl",
		Description: "Crawl web services for URLs, staying on the same host.",
		Inputs:      []asset.TypeRef{tHTTPService, tDiscoveredURL, tWebsite},
		Outputs:     []asset.TypeRef{tHTTPService},
		Endpoints:   true,
		Tier:        TierActive,
		MaxFanout:   webFanoutCap,
		Legacy:      []string{"crawler", "url_discovery"},
	},
	{
		Key: VulnTemplates, Name: "Vulnerability templates",
		Description: "Run non-intrusive vulnerability templates.",
		Inputs: []asset.TypeRef{
			tHTTPService, tDiscoveredURL, tOpenPort,
			tDomain, tSubdomain, tIP,
			tWebsite, tAPI,
		},
		Findings:  true,
		Tier:      TierActive,
		MaxFanout: RunFanoutCap,
	},
	{
		Key: DASTWeb, Name: "Web application scan",
		Description: "Dynamic application security testing of a web application.",
		Inputs:      []asset.TypeRef{tWebsite, tAPI, tHTTPService, tDiscoveredURL},
		Findings:    true,
		Endpoints:   true,
		// An active DAST scan sends attack payloads: intrusive.
		Tier:      TierIntrusive,
		MaxFanout: webFanoutCap,
	},
	{
		Key: SecretsCode, Name: "Secrets in code",
		Description: "Find committed secrets in a repository.",
		Inputs:      codeInputs, Findings: true, Tier: TierPassive,
		MaxFanout: RunFanoutCap,
		Legacy:    []string{"secrets"},
	},
	{
		Key: SASTCode, Name: "Static analysis",
		Description: "Static application security testing of source code.",
		Inputs:      codeInputs, Findings: true, Tier: TierPassive,
		MaxFanout: RunFanoutCap,
		Legacy:    []string{"sast"},
	},
	{
		Key: SCADeps, Name: "Dependency scan",
		Description: "Find vulnerable dependencies and build a component inventory.",
		Inputs:      []asset.TypeRef{canonical(asset.AssetTypeRepository), tContainer},
		Findings:    true, Tier: TierPassive,
		MaxFanout: RunFanoutCap,
		Legacy:    []string{"sca"},
	},
	{
		Key: IaCMisconfig, Name: "Infrastructure-as-code misconfiguration",
		Description: "Find misconfigurations in infrastructure-as-code files.",
		Inputs:      codeInputs, Findings: true, Tier: TierPassive,
		MaxFanout: RunFanoutCap,
		Legacy:    []string{"iac"},
	},
	{
		Key: ContainerImage, Name: "Container image scan",
		Description: "Find vulnerabilities in a container image.",
		Inputs:      []asset.TypeRef{tContainer},
		Findings:    true, Tier: TierPassive,
		MaxFanout: RunFanoutCap,
		Legacy:    []string{"container"},
	},
	{
		Key: NetworkVAConnector, Name: "Network vulnerability assessment (connector)",
		Description: "Run a network vulnerability scan through a connected scanner product.",
		Inputs:      []asset.TypeRef{tIP, tHost, tNetwork},
		Findings:    true, Tier: TierActive,
		MaxFanout: connectorFanoutCap,
	},
}

// All returns a copy of the capability catalog, in display order, without
// implementations: which tools run a stage is an organization's fact
// (Catalog.All).
func All() []Stage { return Catalog{}.All() }

// clone is a deep copy of the stage.
func (s Stage) clone() Stage {
	s.Inputs = slices.Clone(s.Inputs)
	s.Outputs = slices.Clone(s.Outputs)
	s.Relations = slices.Clone(s.Relations)
	s.Implementations = cloneImplementations(s.Implementations)
	s.Legacy = slices.Clone(s.Legacy)
	s.InPorts = slices.Clone(s.InPorts)
	s.OutPorts = slices.Clone(s.OutPorts)
	s.Params = slices.Clone(s.Params)
	s.RequiredOutputFields = slices.Clone(s.RequiredOutputFields)
	s.Attack = slices.Clone(s.Attack)
	s.D3FEND = slices.Clone(s.D3FEND)
	s.RequiredOutput = slices.Clone(s.RequiredOutput)
	return s
}

// Lookup returns the stage with this key, without implementations
// (Catalog.Lookup).
func Lookup(k Key) (Stage, bool) { return Catalog{}.Lookup(k) }

// DefaultTool is the stage's default implementation.
func (s Stage) DefaultTool() string {
	for _, i := range s.Implementations {
		if i.Default {
			return i.Tool
		}
	}
	if len(s.Implementations) > 0 {
		return s.Implementations[0].Tool
	}
	return ""
}

// Tools are the stage's implementations, the default first.
func (s Stage) Tools() []string {
	out := make([]string, 0, len(s.Implementations))
	if d := s.DefaultTool(); d != "" {
		out = append(out, d)
	}
	for _, i := range s.Implementations {
		if i.Tool != "" && !slices.Contains(out, i.Tool) {
			out = append(out, i.Tool)
		}
	}
	return out
}

// Implements reports whether tool implements the stage.
func (s Stage) Implements(tool string) bool {
	tool = normalizeTool(tool)
	for _, i := range s.Implementations {
		if i.Tool == tool {
			return true
		}
	}
	return false
}

// Accepts reports whether the stage takes a target of the stored pair.
func (s Stage) Accepts(ref asset.TypeRef) bool { return typeIn(ref, s.Inputs) }

// Produces reports whether a report of the stage may create an asset of the
// stored pair.
func (s Stage) Produces(ref asset.TypeRef) bool { return typeIn(ref, s.Outputs) }

// MayReport reports whether a report bound to the stage may carry an asset
// of the stored pair: what the stage produces, and the inputs it re-observes
// (research/27 §5.2).
func (s Stage) MayReport(ref asset.TypeRef) bool { return s.Produces(ref) || s.Accepts(ref) }

// PerParentCap is the per-parent derived-target cap.
func (s Stage) PerParentCap() int {
	if s.MaxPerParent > 0 {
		return s.MaxPerParent
	}
	return s.MaxFanout
}

// typeIn reports whether the pair ref is one of types, comparing canonical
// pairs: an input name such as "http_service" is the stored service/http.
// A type with no sub-type matches any sub-type of it.
func typeIn(ref asset.TypeRef, types []asset.TypeRef) bool {
	got := asset.CanonicalPair(ref.Type, ref.SubType)
	for _, t := range types {
		want := asset.CanonicalPair(t.Type, t.SubType)
		if want.Type != got.Type {
			continue
		}
		if want.SubType == "" || want.SubType == got.SubType {
			return true
		}
	}
	return false
}

// Label is a pair's label: "type" or "type/sub_type" (the form run
// contexts and tools.output_types use).
func Label(ref asset.TypeRef) string {
	if ref.SubType == "" {
		return string(ref.Type)
	}
	return string(ref.Type) + "/" + ref.SubType
}

// normalizeTool is the registry spelling of a tool name.
func normalizeTool(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// Resolution errors.
var (
	// ErrUnknownCapability: no stage matches the capabilities.
	ErrUnknownCapability = fmt.Errorf("no catalog stage matches these capabilities")
	// ErrAmbiguousCapability: the capabilities name more than one stage.
	ErrAmbiguousCapability = fmt.Errorf("these capabilities name more than one catalog stage; pin a tool or name one capability")
)

// ForCapabilities maps a step's capability list to its stage: a stage key
// ("probe.http") names the stage directly; otherwise the pre-catalog words
// that name exactly one stage ("portscan", "dns", ...) do. Qualifier words
// ("recon", "web", "tech_detect") name no stage on their own.
//
// The stage has no implementations; Catalog.ForCapabilities has them.
func ForCapabilities(caps []string) (Stage, error) { return Catalog{}.ForCapabilities(caps) }

// ForWord is the stage one capability word names: a stage key
// ("resolve.dns") or a pre-catalog word that names exactly one stage
// ("dns"). Qualifier words ("recon", "scan") name none.
func ForWord(word string) (Stage, bool) { return Catalog{}.ForWord(word) }
