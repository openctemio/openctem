package sensor

// The tier and trust level the platform assigns a job's tool (RFC-055 §6.3,
// decisions TC1, TC8 and TC16). A tool's own tier is a request; the
// platform takes the highest of:
//
//   - the floor of the capability the job runs (ctis/capability), or, for a
//     job that names none, the highest floor of the capabilities the tool's
//     contract implements;
//   - the tier the tool's descriptor declares;
//   - T2 when the descriptor declares a side effect;
//   - T2 for a tool the operator installed (origin adapter): it is
//     unverified until the platform classifies it;
//   - T2 for out-of-band callbacks or custom templates.
//
// A job that names no capability, of a tool that reports no contract, is
// T2 (fail closed).

import (
	"encoding/json"
	"strings"

	"github.com/openctemio/ctis/capability"
)

// Trust levels of a tool (RFC-055 §6.3).
const (
	// ToolTrustBuiltin: compiled into the sensor binary.
	ToolTrustBuiltin = "builtin"
	// ToolTrustUnverified: installed by the sensor's operator and not
	// classified; it runs only as T2.
	ToolTrustUnverified = "unverified"
)

// builtinTools are the tools compiled into a released sensor (the sensor's
// "tools manifests") and the SDK's file importer. Keep in step with the
// sensor's built-in tool list.
var builtinTools = map[string]bool{
	"betterleaks": true, "codeql": true, "dnsx": true, "httpx": true, "katana": true,
	"naabu": true, "nuclei": true, "nuclei-validate": true, "opengrep": true, "semgrep": true,
	"subfinder": true, "trivy": true, "file-import": true, "rdap": true, "asn": true,
}

// IsBuiltinTool reports whether name is a tool the platform knows a
// released sensor compiles in.
func IsBuiltinTool(name string) bool {
	return builtinTools[strings.ToLower(strings.TrimSpace(CanonicalTool(name)))]
}

// builtinOrigin reports whether the platform honors a contract's
// "builtin" origin for the tool name: the origin is a sensor claim, so it
// counts only for a tool a released sensor compiles in. Any other tool that
// claims it is treated as operator-installed (unverified, T2).
func builtinOrigin(name string, c *ToolContract) bool {
	return c != nil && c.Origin == ToolOriginBuiltin && IsBuiltinTool(name)
}

// ToolTrust is the trust level of the tool name from its reported
// contract; "" for a tool without a contract (a sensor older than the tool
// contract).
func ToolTrust(name string, c *ToolContract) string {
	switch {
	case c == nil:
		return ""
	case builtinOrigin(name, c):
		return ToolTrustBuiltin
	default:
		return ToolTrustUnverified
	}
}

// tierOfLabel is the rank of "T0".."T2"; -1 when unknown.
func tierOfLabel(t string) int {
	switch t {
	case "T0":
		return TierPassive
	case "T1":
		return TierActive
	case "T2":
		return TierIntrusive
	}
	return -1
}

// declaresSideEffects reports whether a contract's descriptor names a side
// effect (safety.side_effects).
func declaresSideEffects(c *ToolContract) bool {
	if c == nil || len(c.Descriptor) == 0 {
		return false
	}
	var d struct {
		Safety *struct {
			SideEffects []string `json:"side_effects"`
		} `json:"safety"`
	}
	if err := json.Unmarshal(c.Descriptor, &d); err != nil {
		return true // a descriptor we cannot read: assume the worst
	}
	return d.Safety != nil && len(d.Safety.SideEffects) > 0
}

// contractTier is the tier of a scan job of the tool: the floor of the
// capability the job names, else the highest floor among the capabilities
// the tool's contract implements, raised to the tier its descriptor
// declares; T2 for a capability the taxonomy does not know, for a tool
// without a contract whose job names no capability, and for a contract
// that is not a verified built-in or declares a side effect.
func contractTier(job Job, c *ToolContract) int {
	tier := -1
	if job.Capability != "" {
		cp, ok := capability.Lookup(job.Capability)
		if !ok {
			return TierIntrusive
		}
		tier = cp.TierFloor
	}
	if c == nil {
		if tier < 0 {
			return TierIntrusive
		}
		return min(tier, TierIntrusive)
	}
	if !builtinOrigin(job.Tool, c) || declaresSideEffects(c) {
		return TierIntrusive
	}
	if tier < 0 {
		for _, ref := range c.Implements {
			if cp, ok := capability.Lookup(ref); ok {
				tier = max(tier, cp.TierFloor)
			}
		}
		if tier < 0 {
			return TierIntrusive
		}
	}
	if d := tierOfLabel(c.Tier); d > tier {
		tier = d
	}
	return min(tier, TierIntrusive)
}
