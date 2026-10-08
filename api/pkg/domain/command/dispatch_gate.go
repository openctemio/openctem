package command

// DispatchGate is what the dispatch gate checked a command's targets with
// when the command was created. The claim re-applies the gate with the same
// inputs, because scope can change while the job waits in the queue
// (docs/architecture/active-probe-gate.md, "Re-check at claim"). The
// platform writes it on create; it is never read from or sent to a sensor.
type DispatchGate struct {
	// Tier is the probe tier the targets were checked at (scope.Tier:
	// 0 passive, 1 safe active, 2 intrusive). 0 checks no tier ceiling.
	Tier int `json:"tier"`
	// Passive: the ownership check refuses only rejected names (a passive
	// stage may resolve names nobody confirmed yet).
	Passive bool `json:"passive,omitempty"`
	// ActScope: the targets are limited to what Actor may scan. Actor is
	// the user the job acts for ("" with ActScope is the system).
	ActScope bool   `json:"act_scope,omitempty"`
	Actor    string `json:"actor,omitempty"`
	// Validated: the targets passed the scan target validator at dispatch
	// (validate, retest and connector commands), so the claim applies it
	// again. Off, only its private-range rule applies (scan targets include
	// repositories by asset name, which the validator refuses).
	Validated bool `json:"validated,omitempty"`
	// NoZoneRouting: the dispatch did not route the targets over the scan
	// zones (a connector scan runs outside every zone, on its pinned
	// sensor), so the claim does not either.
	NoZoneRouting bool `json:"no_zone_routing,omitempty"`
}

// ProbeDispatchGate is the record of a validate or retest command: the
// probe's target passed the full gate at the safe active tier (t1), with no
// act scope (validation.CheckTarget).
var ProbeDispatchGate = DispatchGate{Tier: 1, Validated: true}

// BaselineDispatchGate is the gate a scan command created without a record
// is re-checked with: what every dispatch path applies (exclusions,
// rejected names, the private-address and zone rules), and nothing a path
// may have left out, so the re-check never refuses what a dispatch allowed
// for a reason other than a change.
var BaselineDispatchGate = DispatchGate{Tier: 0, Passive: true}
