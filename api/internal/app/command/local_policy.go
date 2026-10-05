package command

// The sensor-local policy on the platform side (RFC-040 §5.7, research/25
// §3.6): the jobs a sensor refused under its policy are reported (detection
// A11), and the platform does not dispatch a job to a sensor whose reported
// local policy would refuse it (sensordom.Accepts), including the tenant's
// "private targets need a local policy" switch (owner decision Q3 (a)).
// Withholding only ever narrows what a sensor gets: a withheld command stays
// pending for a sensor that accepts it.

import (
	"context"
	"encoding/json"
	"fmt"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RefusalObserver is told about every command a sensor failed; it acts on
// those its local policy refused. Satisfied by the sensor service.
type RefusalObserver interface {
	ObserveLocalPolicyRefusal(ctx context.Context, tenantID, sensorID shared.ID, commandID, errorMessage string)
}

// WithRefusalObserver reports failed commands to o (sensor timeline and
// audit for local-policy refusals).
func WithRefusalObserver(o RefusalObserver) Option {
	return func(s *Service) { s.refusals = o }
}

// PrivateTargetPolicy says whether a tenant keeps jobs with private targets
// away from sensors that report no enforced local policy. Satisfied by the
// tenant service.
type PrivateTargetPolicy interface {
	RequiresLocalPolicyForPrivateTargets(ctx context.Context, tenantID shared.ID) (bool, error)
}

// WithPrivateTargetPolicy makes Poll, Claim and Acknowledge apply p.
func WithPrivateTargetPolicy(p PrivateTargetPolicy) Option {
	return func(s *Service) { s.privatePolicy = p }
}

// OptInPolicy returns the tenant's interactsh and custom-template switches
// (research/25 D3). Satisfied by the tenant service.
type OptInPolicy interface {
	SensorOptIns(ctx context.Context, tenantID shared.ID) (sensordom.OptIns, error)
}

// WithOptInPolicy makes Poll, Claim and Acknowledge withhold, from every
// sensor, commands that ask for an opt-in the tenant has not enabled. They
// are refused when scans are created and triggered; this is the backstop
// for commands queued before the switch or created another way.
func WithOptInPolicy(p OptInPolicy) Option {
	return func(s *Service) { s.optIns = p }
}

// ErrOptInDisabled: the command asks for interactsh or carries custom
// templates and the tenant has not enabled them. It reads as "claimed";
// the command stays pending until it expires or the tenant enables it.
var ErrOptInDisabled = fmt.Errorf("%w (%w): the organization has not enabled this sensor opt-in", ErrCommandClaimed, shared.ErrConflict)

// ErrLocalPolicyRequired: the command names private targets, the tenant
// requires a local policy for them, and the claiming sensor enforces none.
// It wraps ErrCommandClaimed and shared.ErrConflict, so a sensor is told
// "claimed" (v2 command-claimed, v1 409) and the command stays pending for
// one that qualifies.
var ErrLocalPolicyRequired = fmt.Errorf("%w (%w): private targets need a sensor with a local policy", ErrCommandClaimed, shared.ErrConflict)

// ErrSensorPolicyRefuses: the claiming sensor's reported local policy
// refuses the command. Like ErrLocalPolicyRequired it reads as "claimed",
// and the command stays pending for a sensor that accepts it.
var ErrSensorPolicyRefuses = fmt.Errorf("%w (%w): the sensor's local policy refuses this command", ErrCommandClaimed, shared.ErrConflict)

// GrantReader reads a sensor's grant (RFC-052 §5). Satisfied by the grant
// repository.
type GrantReader interface {
	Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, error)
}

// GrantRefusalObserver is told about a claim by id the grant refused
// (audit and sensor timeline). Satisfied by the sensor service.
type GrantRefusalObserver interface {
	ObserveGrantRefusal(ctx context.Context, tenantID, sensorID shared.ID, commandID string, r *sensordom.GrantRefusal)
}

// WithGrants makes Poll, Claim and Acknowledge enforce each sensor's grant
// before anything else: a command outside it is never offered, and a claim
// by id of one fails like a lost claim and is reported to o (nil: not
// reported).
func WithGrants(g GrantReader, o GrantRefusalObserver) Option {
	return func(s *Service) { s.grants, s.grantRefusals = g, o }
}

// RefusalLayerGrant names the platform's per-sensor grant in a refusal.
const RefusalLayerGrant = "grant"

// ErrOutOfGrant: the command lies outside the claiming sensor's grant. It
// reads as "claimed" (v2 command-claimed, v1 409), so a deployed sensor
// drops the command instead of treating the answer as a lost key, and the
// command stays pending for a sensor whose grant covers it. The refusal is
// audited (sensor.claim_refused_grant) with the dimension.
var ErrOutOfGrant = fmt.Errorf("%w (%w): the command is outside the sensor's grant", ErrCommandClaimed, shared.ErrConflict)

// dispatchGate is what the pre-check knows about one polling sensor: its
// grant, its last local-policy report and the tenant's platform-side
// settings. A nil gate (no sensor identity, no lookup wired) withholds
// nothing.
type dispatchGate struct {
	grant  *sensordom.Grant
	report *sensordom.LocalPolicyReport
	opts   sensordom.DispatchOptions
	// closed: the sensor or the tenant setting could not be read; every
	// command is withheld (fail closed) until a later poll can read them.
	closed bool
}

// gateFor loads the dispatch gate of sensorID. The tenant's private-target
// switch is read only when a candidate names a private target.
func (s *Service) gateFor(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, cmds []*commanddom.Command) *dispatchGate {
	if sensorID == nil || len(cmds) == 0 || (s.sensors == nil && s.privatePolicy == nil && s.optIns == nil && s.grants == nil) {
		return nil
	}
	var grant *sensordom.Grant
	if s.grants != nil {
		g, err := s.grants.Get(ctx, tenantID, *sensorID)
		if err != nil || g == nil {
			// Every sensor has a grant (migration backfill + insert trigger):
			// none, or a read error, withholds everything (fail closed).
			s.logger.Warn("cannot read the polling sensor's grant; withholding commands",
				"tenant_id", tenantID.String(), "sensor_id", sensorID.String(), "error", err)
			return &dispatchGate{closed: true}
		}
		grant = g
	}
	opts, err := s.dispatchOptions(ctx, tenantID, cmds)
	if err != nil {
		s.logger.Warn("cannot read the tenant's dispatch settings; withholding commands",
			"tenant_id", tenantID.String(), "error", err)
		return &dispatchGate{closed: true}
	}
	g := &dispatchGate{opts: opts, grant: grant}
	if s.sensors == nil {
		// No report to read: only the private-target switch applies, and
		// no sensor qualifies for it.
		return g
	}
	a, err := s.sensors.GetByTenantAndID(ctx, tenantID, *sensorID)
	if err != nil || a == nil {
		s.logger.Warn("cannot read the polling sensor's local policy; withholding commands",
			"tenant_id", tenantID.String(), "sensor_id", sensorID.String(), "error", err)
		return &dispatchGate{closed: true}
	}
	g.report = a.LocalPolicy
	return g
}

// dispatchOptions reads the tenant settings the pre-check needs for cmds:
// the opt-ins when a command asks for one, the private-target switch when
// a command names a private target. An error means "withhold".
func (s *Service) dispatchOptions(ctx context.Context, tenantID shared.ID, cmds []*commanddom.Command) (sensordom.DispatchOptions, error) {
	var opts sensordom.DispatchOptions
	if s.optIns != nil && anyOptIn(cmds) {
		o, err := s.optIns.SensorOptIns(ctx, tenantID)
		if err != nil {
			return opts, err
		}
		opts.OptIns = &o
	}
	if s.privatePolicy != nil && anyPrivateTarget(cmds) {
		required, err := s.privatePolicy.RequiresLocalPolicyForPrivateTargets(ctx, tenantID)
		if err != nil {
			return opts, err
		}
		opts.RequireLocalPolicyForPrivate = required
	}
	return opts, nil
}

// refusal is why the gate withholds c, or nil.
func (g *dispatchGate) refusal(c *commanddom.Command) *sensordom.DispatchRefusal {
	if g == nil {
		return nil
	}
	if g.closed {
		return &sensordom.DispatchRefusal{Layer: sensordom.RefusalLayerManaged, Rule: "unavailable",
			Detail: "the sensor's policy could not be read"}
	}
	if r := g.grantRefusal(c); r != nil {
		return &sensordom.DispatchRefusal{Layer: RefusalLayerGrant, Rule: r.Dimension, Detail: r.Detail}
	}
	return sensordom.Accepts(g.report, sensordom.JobOf(string(c.Type), c.Payload), g.opts)
}

// grantRefusal is the grant's refusal of c, or nil (also without a grant
// read: enforcement not wired).
func (g *dispatchGate) grantRefusal(c *commanddom.Command) *sensordom.GrantRefusal {
	if g == nil || g.grant == nil {
		return nil
	}
	return g.grant.Admit(string(c.Type), c.Payload, c.ScanZoneID)
}

// accepted keeps the commands the gate does not withhold, in order.
func (g *dispatchGate) accepted(cmds []*commanddom.Command) []*commanddom.Command {
	if g == nil {
		return cmds
	}
	out := cmds[:0:0]
	for _, c := range cmds {
		if g.refusal(c) == nil {
			out = append(out, c)
		}
	}
	return out
}

// claimError is the error a claim by id of c gets from a sensor the gate
// refuses: ErrLocalPolicyRequired for the private-target switch, else
// ErrSensorPolicyRefuses. nil when the sensor may claim it.
func (g *dispatchGate) claimError(c *commanddom.Command) error {
	r := g.refusal(c)
	switch {
	case r == nil:
		return nil
	case r.Layer == RefusalLayerGrant:
		return ErrOutOfGrant
	case r.Rule == sensordom.RulePrivateNeedsLocalPlcy:
		return ErrLocalPolicyRequired
	case r.Layer == sensordom.RefusalLayerManaged && (r.Rule == sensordom.RuleAllowInteractsh || r.Rule == sensordom.RuleAllowCustomTemplates):
		return ErrOptInDisabled
	default:
		return ErrSensorPolicyRefuses
	}
}

// candidateLimit is how many pending commands a poll reads when it may
// withhold some: more than it returns, so commands the sensor refuses at
// the head of the queue do not starve it of the ones it accepts.
func candidateLimit(limit int) int {
	return min(max(limit*2, limit+10), 100)
}

// anyOptIn reports whether a command of cmds asks for interactsh or carries
// custom templates.
func anyOptIn(cmds []*commanddom.Command) bool {
	for _, c := range cmds {
		j := sensordom.JobOf(string(c.Type), c.Payload)
		if j.Interactsh || j.CustomTemplates > 0 {
			return true
		}
	}
	return false
}

// anyPrivateTarget reports whether a command of cmds names private targets.
func anyPrivateTarget(cmds []*commanddom.Command) bool {
	for _, c := range cmds {
		if HasPrivateTarget(c.Payload) {
			return true
		}
	}
	return false
}

// HasPrivateTarget reports whether a command payload names a private
// target (sensordom.HasPrivateTarget).
func HasPrivateTarget(payload json.RawMessage) bool {
	return sensordom.HasPrivateTarget(payload)
}
