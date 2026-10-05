package sensor

// Tool contracts in the sensor manifest (sdk-go docs/rfcs/sensor-sdk-v2.md,
// "tools[].contract"): a tool ported to the tool contract names its
// tool.yaml manifest by digest, with the fields the platform plans and
// binds output with (class, tier, network, consumes, produces).
//
// A contract is a claim from an untrusted process. It is validated whole
// (one bad member drops the contract and records why), bounded, and stored
// only inside the sensor's own manifest version (tenant-scoped,
// content-addressed per sensor by the manifest digest), so a digest a sensor
// of one tenant reports is never visible to, or reused for, another tenant.
// It can only narrow what the platform accepts from the tool: ingest keeps a
// report's records only when both the scan-stage catalog (where it knows the
// tool) and the contract's produces allow them.

import (
	"regexp"
	"slices"
	"strings"
)

// ToolContractAPIVersion is the tool manifest format the platform reads.
const ToolContractAPIVersion = "openctem.io/tool/v1"

// Tool contract limits.
const (
	// MaxToolContractTypes bounds a contract's consumes and produces lists.
	MaxToolContractTypes = 64
	maxToolContractEntry = 128
	maxToolContractVer   = 64
)

// IgnoredInvalidContract is the reason a tool's contract was dropped.
const IgnoredInvalidContract = "invalid-contract"

// Produce kinds of a tool contract.
const (
	ProduceAsset      = "asset"
	ProduceFinding    = "finding"
	ProduceDependency = "dependency"
)

// ToolContract is a tool's tool-contract manifest as the sensor names it.
type ToolContract struct {
	APIVersion string   `json:"api_version"`
	Digest     string   `json:"digest"`
	Version    string   `json:"version"`
	Class      string   `json:"class" enums:"target-scan,connector,parser,enricher"`
	Tier       string   `json:"tier" enums:"T0,T1,T2"`
	Network    string   `json:"network,omitempty" enums:"none,targets,egress-proxy,vendor"`
	Consumes   []string `json:"consumes,omitempty"`
	Produces   []string `json:"produces"`
}

var (
	contractDigestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	contractVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*$`)
	contractTypeRe    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	// consumes: an asset type, "file:<media type>" or "finding:<type>".
	contractConsumeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(:[A-Za-z0-9][A-Za-z0-9.+/_-]*)?$`)

	contractClasses  = []string{"target-scan", "connector", "parser", "enricher"}
	contractTiers    = []string{"T0", "T1", "T2"}
	contractNetworks = []string{"", "none", "targets", "egress-proxy", "vendor"}
)

// SanitizeToolContract returns the contract as it is stored, or nil and the
// reason it is refused. Lists are deduplicated; nothing is guessed.
func SanitizeToolContract(c *ToolContract) (*ToolContract, string) {
	if c == nil {
		return nil, ""
	}
	switch {
	case c.APIVersion != ToolContractAPIVersion:
		return nil, "unsupported api_version"
	case !contractDigestRe.MatchString(c.Digest):
		return nil, "digest is not sha256:<64 hex>"
	case len(c.Version) > maxToolContractVer || !contractVersionRe.MatchString(c.Version):
		return nil, "invalid version"
	case !slices.Contains(contractClasses, c.Class):
		return nil, "unknown class"
	case !slices.Contains(contractTiers, c.Tier):
		return nil, "unknown tier"
	case !slices.Contains(contractNetworks, c.Network):
		return nil, "unknown network"
	case c.Tier == "T2" && c.Class != "target-scan":
		return nil, "T2 is for target-scan tools only"
	case len(c.Consumes) > MaxToolContractTypes || len(c.Produces) > MaxToolContractTypes:
		return nil, "too many consumes or produces entries"
	}
	out := &ToolContract{APIVersion: c.APIVersion, Digest: c.Digest, Version: c.Version, Class: c.Class,
		Tier: c.Tier, Network: c.Network, Produces: []string{}}
	for _, v := range c.Consumes {
		if len(v) > maxToolContractEntry || !contractConsumeRe.MatchString(v) {
			return nil, "invalid consumes entry"
		}
		if !slices.Contains(out.Consumes, v) {
			out.Consumes = append(out.Consumes, v)
		}
	}
	for _, v := range c.Produces {
		if len(v) > maxToolContractEntry || !validProduce(v) {
			return nil, "invalid produces entry"
		}
		if !slices.Contains(out.Produces, v) {
			out.Produces = append(out.Produces, v)
		}
	}
	return out, ""
}

func validProduce(v string) bool {
	if v == ProduceDependency {
		return true
	}
	kind, typ, ok := strings.Cut(v, ":")
	return ok && (kind == ProduceAsset || kind == ProduceFinding) && contractTypeRe.MatchString(typ)
}

// Declares reports whether the contract produces records of kind
// (ProduceAsset, ProduceFinding, ProduceDependency) and type typ (ignored
// for dependencies). Types compare case-insensitively.
func (c *ToolContract) Declares(kind, typ string) bool {
	if c == nil {
		return false
	}
	want := ProduceDependency
	if kind != ProduceDependency {
		want = kind + ":" + strings.ToLower(strings.TrimSpace(typ))
	}
	return slices.Contains(c.Produces, want)
}

// ToolContract returns the contract the manifest's tool named name (case
// insensitive) reported, or nil.
func (m Manifest) ToolContract(name string) *ToolContract {
	name = strings.ToLower(strings.TrimSpace(name))
	for i := range m.Tools {
		if m.Tools[i].Name == name {
			return m.Tools[i].Contract
		}
	}
	return nil
}
