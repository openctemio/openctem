package validation

// The active-probe gate for validate commands. Architecture:
// docs/architecture/active-probe-gate.md.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TargetGate is the one fail-closed gate every path that sends traffic at a
// tenant's target goes through outside a scan trigger
// (*scan.Service.ResolveDispatchTargets): the scan target validator with the
// private-range policy, active scope exclusions, the asset's attribution
// (only confirmed assets are probed) and scan-zone routing.
type TargetGate interface {
	ResolveDispatchTargets(ctx context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error)
}

// ErrProbeGateUnavailable is returned when no target gate is wired. Nothing
// is dispatched then.
var ErrProbeGateUnavailable = errors.New("active-probe gate is not configured; nothing dispatched")

// ErrTargetRefused wraps every refusal of the gate: the target is excluded,
// out of every scan zone, private without a zone, or an asset whose ownership
// is not confirmed. It is a validation error (HTTP 400 with the reason).
var ErrTargetRefused = fmt.Errorf("%w: the target may not be probed", shared.ErrValidation)

// CheckTarget runs one probe target through gate. It returns the scan zone
// the probe must stay in (nil when the target is unzoned), ErrTargetRefused
// with the reason when the gate refuses it, or another error when the gate
// cannot decide; nothing may be dispatched unless the error is nil.
func CheckTarget(ctx context.Context, gate TargetGate, tenantID shared.ID, t Target) (*scanzone.Zone, error) {
	if gate == nil {
		return nil, ErrProbeGateUnavailable
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: a probe needs a tenant", shared.ErrValidation)
	}
	address := strings.TrimSpace(t.Address)
	if address == "" {
		return nil, fmt.Errorf("%w: the target has no address", ErrTargetRefused)
	}
	in := scanapp.DispatchTargetsInput{TenantID: tenantID, Targets: []string{address}}
	if !t.AssetID.IsZero() {
		in.Assets = map[string]scanapp.DispatchAsset{address: {IDs: []string{t.AssetID.String()}, AlsoMatch: []string{t.AssetName}}}
	}
	gated, err := gate.ResolveDispatchTargets(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("active-probe gate, nothing dispatched: %w", err)
	}
	for _, a := range gated.Allowed {
		if strings.EqualFold(a, address) {
			return gated.Zone(a), nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrTargetRefused, refusalReason(gated))
}

// refusalReason is the gate's reason for refusing the single target.
func refusalReason(d *scanapp.DispatchTargets) string {
	if d == nil {
		return "the target was not allowed"
	}
	if len(d.Excluded) > 0 {
		return "the target matches an active scope exclusion"
	}
	if len(d.Refused) > 0 && d.Refused[0].Reason != "" {
		return d.Refused[0].Reason
	}
	return "the target was not allowed"
}
