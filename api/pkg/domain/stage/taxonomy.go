package stage

// The capability contracts come from the OpenCTEM capability taxonomy
// (github.com/openctemio/ctis/capability), the one copy the platform, the
// SDK and the sensor read (RFC-055). This package keeps only what is
// platform data: the stored asset pairs each port carries, the default and
// alternative implementations, the fan-out caps and the display names of the
// required fields.

import (
	"fmt"

	"github.com/openctemio/ctis/capability"
)

// lookupCapability is the taxonomy entry of a stage key at the contract
// version. A stage the taxonomy does not know is a programming error.
func lookupCapability(k Key) capability.Capability {
	c, ok := capability.Lookup(fmt.Sprintf("%s@%d", k, ContractVersion))
	if !ok {
		panic(fmt.Sprintf("stage %s: not in the capability taxonomy", k))
	}
	return c
}

// contractOf is the contract of a capability, from the taxonomy.
func contractOf(k Key, required []string) contract {
	c := lookupCapability(k)
	out := contract{
		in: portsOf(k, c.InPorts), out: portsOf(k, c.OutPorts), params: paramsOf(c.Params),
		required: required, tier: Tier(c.TierFloor), phase: string(c.Phase), ctemStage: c.CTEMStage(),
		attack: c.ATTACK, d3fend: c.D3FEND, rules: c.Outputs,
	}
	if out.required == nil {
		out.required = []string{}
	}
	return out
}

// portsOf converts taxonomy port types; every one must be a platform port
// type (the platform knows which stored pairs it carries).
func portsOf(k Key, in []capability.PortType) []PortType {
	out := make([]PortType, 0, len(in))
	for _, p := range in {
		if _, ok := LookupPortType(PortType(p)); !ok {
			panic(fmt.Sprintf("stage %s: port type %s has no platform carries", k, p))
		}
		out = append(out, PortType(p))
	}
	return out
}

func paramsOf(in []capability.Param) []Param {
	if len(in) == 0 {
		return nil
	}
	out := make([]Param, 0, len(in))
	for _, p := range in {
		out = append(out, Param{Name: p.Name, Type: ParamType(p.Type), Description: p.Description,
			Enum: p.Enum, Min: p.Min, Max: p.Max})
	}
	return out
}

// plannedStages are the planned capabilities with their contracts from the
// taxonomy: listed so the editor can show them as coming, never planned.
func plannedStages() []Stage {
	out := make([]Stage, 0, len(plannedFields))
	for _, f := range plannedFields {
		c := lookupCapability(f.key)
		ct := contractOf(f.key, f.required)
		s := Stage{Key: f.key, Name: c.Name, Description: c.Description, Tier: ct.tier,
			Findings: !c.CrossCutting && (c.MayEmit("finding:vulnerability") || c.MayEmit("finding:misconfiguration")), CrossCutting: c.CrossCutting}
		s.applyContract(ct)
		out = append(out, s)
	}
	return out
}
