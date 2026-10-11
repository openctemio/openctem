package stage

// Capability contracts: the typed interface of each catalog capability.
//
// A capability ("scan.ports@1") is what a workflow node asks for; a tool is
// one implementation of it. The contract is what every implementation must
// honor, so a workflow is wired once and any conforming tool can run it:
//
//   - typed ports: the closed set of PortTypes a node takes and emits. An
//     edge connects an output port to an input port of the same type, and
//     the hop router still gates every hop;
//   - standard params: the settings every implementation accepts, with a
//     per-tool mapping to the tool's own config key;
//   - required output fields: what a report of the capability must carry;
//   - a major version: changing ports, removing params or adding required
//     output fields bumps it.
//
// Design: research note "scan workflow designer" §3.1 and §3.13 (local).

import (
	"fmt"
	"slices"

	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// PortType is the type of a workflow node port. The set is closed: ports
// are compared by identity when two nodes are wired.
type PortType string

// Port types of contract v1.
const (
	PortRootDomain     PortType = "root_domain"
	PortHostname       PortType = "hostname"
	PortIP             PortType = "ip"
	PortCIDR           PortType = "cidr"
	PortService        PortType = "service"
	PortURL            PortType = "url"
	PortRepository     PortType = "repository"
	PortContainerImage PortType = "container_image"
	PortCloudAccount   PortType = "cloud_account"
	// PortFinding is an output sink (and an input only for enrichers).
	PortFinding PortType = "finding"
	// PortEndpoint is a stream of web endpoints (CTIS 1.6 endpoints[]). They
	// are a sub-inventory of their origin, not assets (RFC-056), so the
	// stream carries the origin: a consumer runs against the origin and the
	// incremental selector expands it to the origin's endpoints.
	PortEndpoint PortType = "endpoint"
)

// PortTypeInfo describes one port type.
type PortTypeInfo struct {
	Type  PortType `json:"type"`
	Label string   `json:"label"`
	// Carries are the stored asset pairs a stream of this type holds; empty
	// for findings.
	Carries []asset.TypeRef `json:"-"`
}

// portTypes is the closed set, in display order.
var portTypes = []PortTypeInfo{
	{Type: PortRootDomain, Label: "Root domain", Carries: []asset.TypeRef{tDomain}},
	{Type: PortHostname, Label: "Hostname", Carries: dnsNames},
	{Type: PortIP, Label: "IP address", Carries: []asset.TypeRef{tIP, tHost}},
	{Type: PortCIDR, Label: "Network range", Carries: []asset.TypeRef{tNetwork}},
	{Type: PortService, Label: "Service (host:port)", Carries: []asset.TypeRef{tOpenPort}},
	{Type: PortURL, Label: "URL", Carries: []asset.TypeRef{tHTTPService, tDiscoveredURL, tWebsite, tAPI}},
	{Type: PortRepository, Label: "Repository", Carries: codeInputs},
	{Type: PortContainerImage, Label: "Container image", Carries: []asset.TypeRef{tContainer}},
	{Type: PortCloudAccount, Label: "Cloud account", Carries: []asset.TypeRef{canonical(asset.AssetTypeCloudAccount)}},
	{Type: PortFinding, Label: "Finding"},
	{Type: PortEndpoint, Label: "Web endpoint", Carries: []asset.TypeRef{tHTTPService}},
}

// PortTypes returns the closed port type set, in display order.
func PortTypes() []PortTypeInfo {
	out := make([]PortTypeInfo, len(portTypes))
	for i, p := range portTypes {
		p.Carries = slices.Clone(p.Carries)
		out[i] = p
	}
	return out
}

// LookupPortType returns a port type's description.
func LookupPortType(t PortType) (PortTypeInfo, bool) {
	for _, p := range portTypes {
		if p.Type == t {
			p.Carries = slices.Clone(p.Carries)
			return p, true
		}
	}
	return PortTypeInfo{}, false
}

// Carries reports whether a stream of port type t holds the stored pair.
func (t PortType) Carries(ref asset.TypeRef) bool {
	p, ok := LookupPortType(t)
	return ok && typeIn(ref, p.Carries)
}

// ParamType is the value type of a standard capability param.
type ParamType string

// Param value types.
const (
	ParamString     ParamType = "string"
	ParamStringList ParamType = "string_list"
	ParamInteger    ParamType = "integer"
	ParamBoolean    ParamType = "boolean"
	// ParamPortList is a list of ports and port ranges ("80,443,8000-8100").
	ParamPortList ParamType = "port_list"
)

// Param is one standard param of a capability.
type Param struct {
	Name        string    `json:"name"`
	Type        ParamType `json:"type"`
	Description string    `json:"description"`
	// Enum, when set, is the closed set of allowed values (for a list, of
	// each item).
	Enum []string `json:"enum,omitempty"`
	Min  *int     `json:"min,omitempty"`
	Max  *int     `json:"max,omitempty"`
}

// Adapter is the capability that turns one port type into another: what the
// editor offers to insert when two incompatible ports are wired.
type Adapter struct {
	From       PortType `json:"from"`
	To         PortType `json:"to"`
	Capability Key      `json:"capability"`
}

// adapters, in preference order.
var adapters = []Adapter{
	{From: PortHostname, To: PortURL, Capability: ProbeHTTP},
	{From: PortHostname, To: PortIP, Capability: ResolveDNS},
	{From: PortIP, To: PortService, Capability: ScanPorts},
	{From: PortHostname, To: PortService, Capability: ScanPorts},
	{From: PortService, To: PortURL, Capability: ProbeHTTP},
	{From: PortIP, To: PortURL, Capability: ProbeHTTP},
	{From: PortRootDomain, To: PortHostname, Capability: DiscoverSubdomains},
}

// Adapters returns the adapter table.
func Adapters() []Adapter { return slices.Clone(adapters) }

// AdapterFor is the first capability that takes from and emits to.
func AdapterFor(from, to PortType) (Adapter, bool) {
	for _, a := range adapters {
		if a.From == from && a.To == to {
			return a, true
		}
	}
	return Adapter{}, false
}

// contract is the typed interface of one capability.
type contract struct {
	in, out   []PortType
	params    []Param
	required  []string
	tier      Tier
	phase     string
	ctemStage string
	attack    []string
	d3fend    []string
	rules     []capability.Rule
	// chunk is how many targets one task of a list-taking tool gets when a
	// workflow step's targets are cut into chunks (0: never cut).
	chunk int
}

// requiredFields are the display names of the fields a report of each
// routed capability must carry. The checked rules are the capability's
// required output in ctis/capability (RequiredOutput).
var requiredFields = map[Key][]string{
	DiscoverSubdomains: []string{"name", "root_domain", "discovery_method"},
	ResolveDNS:         []string{"name", "resolves_to"},
	LookupRDAP:         []string{"name", "registration"},
	LookupASN:          []string{"address", "asn"},
	ScanPorts:          []string{"host", "port", "protocol"},
	ProbeHTTP:          []string{"url", "status_code", "title"},
	CrawlWeb:           []string{"url", "parent_url"},
	VulnTemplates:      []string{"rule_id", "severity", "location", "evidence"},
	DASTWeb:            []string{"rule_id", "severity", "url", "evidence"},
	SecretsCode:        []string{"rule_id", "file", "line", "masked_value"},
	SASTCode:           []string{"rule_id", "file", "line", "severity"},
	SCADeps:            []string{"purl", "version", "cve"},
	IaCMisconfig:       []string{"rule_id", "file", "resource"},
	ContainerImage:     []string{"purl", "version", "cve", "image_digest"},
	NetworkVAConnector: []string{"plugin_id", "host", "severity"},
}

// chunkSizes are how many targets one task of a list-taking tool gets when
// a workflow step of the capability is cut into chunks (absent: never cut).
var chunkSizes = map[Key]int{
	DiscoverSubdomains: 50,
	ResolveDNS:         200,
	LookupRDAP:         100,
	LookupASN:          500,
	ScanPorts:          50,
	ProbeHTTP:          200,
	CrawlWeb:           10,
	VulnTemplates:      25,
	DASTWeb:            10,
}

// toolParams maps a tool's standard params to its own config keys: the keys
// the sensor's settings schema for that tool declares. A tool listed with
// no entry for a param does not accept it yet. Keep in step with
// scan workflow.stepToolSettings.
var toolParams = map[string]map[string]string{
	"naabu":  {"ports": "ports", "top_n": "top_ports", "rate": "rate"},
	"nuclei": {"severity": "severity", "tags": "tags", "exclude_tags": "exclude_tags"},
	"rdap":   {"follow_registrar": "follow_registrar"},
	"asn":    {"include_announced": "include_announced", "max_ranges": "max_ranges"},
}

// batchTools take a list of targets in one task (the sensor executor reads
// the payload's `targets`); every other tool takes one target per task.
var batchTools = map[string]bool{
	"nuclei": true, "subfinder": true, "dnsx": true, "naabu": true, "httpx": true, "katana": true,
	"rdap": true, "asn": true,
}

// capabilityJobTools run capability jobs on the sensor (their embedded
// descriptors implement the capability, sensor SN1): a step that runs one
// names its capability in the command (TakesCapabilityJobs). Every other
// tool gets the command as before. Kept with toolParams and batchTools as
// the built-in fallback until the platform reads every tool's contract
// from its sensors (RFC-055 TC12).
var capabilityJobTools = map[string]bool{
	"subfinder": true, "dnsx": true, "naabu": true, "httpx": true, "katana": true,
	"nuclei": true, "trivy": true, "semgrep": true, "codeql": true, "betterleaks": true, "gitleaks": true,
	"rdap": true, "asn": true,
}

// TakesCapabilityJobs reports whether a step running tool for the stage
// should name the capability in its command: the tool implements the stage
// and runs capability jobs on the sensor.
func TakesCapabilityJobs(s Stage, tool string) bool {
	tool = normalizeTool(tool)
	return capabilityJobTools[tool] && s.Implements(tool)
}

// ContractVersion is the major version of every capability contract of
// catalog v1.
const ContractVersion = 1

func init() {
	for i := range catalog {
		c := contractOf(catalog[i].Key, requiredFields[catalog[i].Key])
		c.chunk = chunkSizes[catalog[i].Key]
		if catalog[i].Tier != c.tier {
			panic(fmt.Sprintf("stage %s: tier %s, the capability's floor is %s", catalog[i].Key, catalog[i].Tier, c.tier))
		}
		catalog[i].applyContract(c)
		for j := range catalog[i].Implementations {
			impl := &catalog[i].Implementations[j]
			impl.Batch = batchTools[impl.Tool]
			impl.Params = toolParamsFor(impl.Tool, c.params)
		}
	}
	planned = plannedStages()
}

func (s *Stage) applyContract(c contract) {
	s.Version = ContractVersion
	s.InPorts = c.in
	s.OutPorts = c.out
	s.Params = c.params
	s.RequiredOutputFields = c.required
	s.Phase, s.CTEMStage = c.phase, c.ctemStage
	s.Attack, s.D3FEND = c.attack, c.d3fend
	s.RequiredOutput = c.rules
	s.ChunkSize = c.chunk
}

// ChunkSizeFor is how many targets one task of tool gets when a workflow
// step of this capability is cut into chunks: the capability's chunk size
// when tool implements it and takes a target list, else 0 (one task for the
// whole step).
func (s Stage) ChunkSizeFor(tool string) int {
	if s.ChunkSize <= 0 {
		return 0
	}
	name := normalizeTool(tool)
	for _, impl := range s.Implementations {
		if impl.Tool == name {
			if impl.Batch {
				return s.ChunkSize
			}
			return 0
		}
	}
	return 0
}

// toolParamsFor is the tool's mapping restricted to the capability's params.
func toolParamsFor(tool string, params []Param) map[string]string {
	m := toolParams[tool]
	out := map[string]string{}
	for _, p := range params {
		if k, ok := m[p.Name]; ok {
			out[p.Name] = k
		}
	}
	return out
}

// ID is the capability's versioned id ("scan.ports@1").
func (s Stage) ID() string { return fmt.Sprintf("%s@%d", s.Key, s.Version) }

// TakesPort reports whether the capability has an input port of type t.
func (s Stage) TakesPort(t PortType) bool { return slices.Contains(s.InPorts, t) }

// EmitsPort reports whether the capability has an output port of type t.
func (s Stage) EmitsPort(t PortType) bool { return slices.Contains(s.OutPorts, t) }

// Available reports whether the platform can run the capability today: it
// has at least one implementation the planner routes.
func (s Stage) Available() bool { return len(s.Implementations) > 0 }

// AcceptsTargetList reports whether a tool takes a list of targets in one
// task. Unknown tools take one target per task.
func AcceptsTargetList(tool string) bool { return batchTools[normalizeTool(tool)] }

// planned are taxonomy v1 capabilities with a contract but no routed
// implementation yet. They are listed (so the editor can show them as
// coming) and never planned: Lookup, ForTool and ForCapabilities do not see
// them, so no step can run one.
var planned []Stage

// plannedFields are the planned capabilities, in display order, with the
// display names of their required fields.
var plannedFields = []struct {
	key      Key
	required []string
}{
	{"intel.passive", []string{"discovery_method", "source"}},
	{"check.takeover", []string{"host", "provider", "evidence"}},
	{"detect.services", []string{"port", "protocol", "service_name"}},
	{"fingerprint.tech", []string{"technologies"}},
	{"check.tls", []string{"fingerprint", "not_after", "issuer"}},
	{"capture.screenshot", []string{"artifact_sha256", "media_type"}},
	{"host.credentialed", []string{"host", "plugin_id"}},
	{"cloud.posture", []string{"rule_id", "resource_id", "severity"}},
	{"verify.finding", []string{"finding_id", "status"}},
	{"discover.cloud", []string{"provider", "resource_id"}},
	{"sbom.generate", []string{"name", "version"}},
	{"import.file", []string{"assets", "findings", "dependencies"}},
}

// Taxonomy returns every capability of taxonomy v1: the routed catalog
// stages, then the planned ones, in display order.
func Taxonomy() []Stage {
	out := All()
	for _, s := range planned {
		out = append(out, s.clone())
	}
	return out
}
