package sensor

// The tier and trust level the platform assigns a job's tool (RFC-055 §6.3,
// decisions TC1, TC8 and TC16). A tool's own tier is a request; the
// platform takes the highest of:
//
//   - the floor of the capability the job runs (ctis/capability), or, for a
//     job that names none, the lowest tier of the catalog stages the tool
//     implements (the rule before the tool contract);
//   - the tier the tool's descriptor declares;
//   - T2 when the descriptor declares a side effect;
//   - T2 for a tool the operator installed (origin adapter): it is
//     unverified until the platform classifies it;
//   - T2 for out-of-band callbacks or custom templates.
//
// A tool neither the catalog nor a built-in contract knows is T2 (fail
// closed).

import (
	"encoding/json"

	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Trust levels of a tool (RFC-055 §6.3).
const (
	// ToolTrustBuiltin: compiled into the sensor binary.
	ToolTrustBuiltin = "builtin"
	// ToolTrustUnverified: installed by the sensor's operator and not
	// classified; it runs only as T2.
	ToolTrustUnverified = "unverified"
)

// ToolTrust is the trust level of a tool from its reported contract; ""
// for a tool without a contract (a sensor older than the tool contract).
func ToolTrust(c *ToolContract) string {
	switch {
	case c == nil:
		return ""
	case c.Origin == ToolOriginBuiltin:
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

// contractTier applies the tool's reported contract to a scan's tier.
func contractTier(tier int, job Job, c *ToolContract) int {
	known := len(stage.ForTool(job.Tool)) > 0
	if job.Capability != "" {
		if cp, ok := capability.Lookup(job.Capability); ok {
			tier = max(tier, cp.TierFloor)
		} else {
			return TierIntrusive
		}
	}
	if c == nil {
		if !known {
			return TierIntrusive
		}
		return tier
	}
	if c.Origin != ToolOriginBuiltin || declaresSideEffects(c) {
		return TierIntrusive
	}
	if !known {
		// A built-in tool the catalog does not route: the floors of the
		// capabilities it implements.
		floor := -1
		for _, ref := range c.Implements {
			if cp, ok := capability.Lookup(ref); ok {
				floor = max(floor, cp.TierFloor)
			}
		}
		if floor < 0 {
			return TierIntrusive
		}
		tier = max(tier, floor)
	}
	if d := tierOfLabel(c.Tier); d > tier {
		tier = d
	}
	return min(tier, TierIntrusive)
}
