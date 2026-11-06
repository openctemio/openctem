package handler

// The sensor-local policy prefill of the install commands: the sensor's scan
// zones, else the organization's scope, with the scope's exclusions as the
// deny list (sensorapp.PolicyFromZones, sensorapp.PolicyFromScope). It only
// proposes text a person reviews; the sensor host writes the file.

import (
	"context"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeTargetLister lists a tenant's scope targets in effect. Satisfied by
// the scope target repository.
type ScopeTargetLister interface {
	ListActive(ctx context.Context, tenantID shared.ID) ([]*scope.Target, error)
}

// ScopeExclusionLister lists a tenant's active scope exclusions. Satisfied by
// the scope exclusion repository.
type ScopeExclusionLister interface {
	ListActive(ctx context.Context, tenantID shared.ID) ([]*scope.Exclusion, error)
}

// SensorPolicyPrefill builds the policy prefill for a tenant. Every source is
// optional: a nil lister leaves its part out.
type SensorPolicyPrefill struct {
	Zones      ZoneLister
	Targets    ScopeTargetLister
	Exclusions ScopeExclusionLister
	Log        *logger.Logger
}

// For returns the prefill for sensorID (zero for a sensor that does not
// exist yet) of tenantID. The organization's scope is read only for a
// caller who may read it (attack_surface:scope:read): the prefill must not
// show the scope to a member whose role hides it; such a caller gets the
// zones only. Read errors leave that part out (best effort: the template
// then asks the owner to list the targets).
func (p *SensorPolicyPrefill) For(ctx context.Context, tenantID, sensorID shared.ID) sensorapp.PolicyTemplateData {
	var out sensorapp.PolicyTemplateData
	if p == nil || tenantID.IsZero() {
		return out
	}
	if p.Zones != nil && !sensorID.IsZero() {
		if zones, err := p.Zones.List(ctx, tenantID); err == nil {
			out = sensorapp.PolicyFromZones(zones, sensorID)
		} else {
			p.warn("scan zones not read for the policy template", err)
		}
	}
	if !middleware.HasPermission(ctx, permission.ScopeRead.String()) {
		return out
	}
	var exclusions []*scope.Exclusion
	if p.Exclusions != nil {
		var err error
		if exclusions, err = p.Exclusions.ListActive(ctx, tenantID); err != nil {
			p.warn("scope exclusions not read for the policy template", err)
		}
	}
	if out.Open || out.HasAllow() {
		out.Deny = sensorapp.DenyFromExclusions(exclusions)
		return out
	}
	if p.Targets == nil {
		out.Deny = sensorapp.DenyFromExclusions(exclusions)
		return out
	}
	targets, err := p.Targets.ListActive(ctx, tenantID)
	if err != nil {
		p.warn("scope targets not read for the policy template", err)
		out.Deny = sensorapp.DenyFromExclusions(exclusions)
		return out
	}
	return sensorapp.PolicyFromScope(targets, exclusions)
}

func (p *SensorPolicyPrefill) warn(msg string, err error) {
	if p.Log != nil {
		p.Log.Warn(msg, "error", logger.SanitizeError(err))
	}
}
