package feedrelay

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/threatsource"
)

// ThreatSourcePolicy is the KEV and EPSS source policy with relay mode on
// top: in relay mode the signed release (relayed) is the only supplier and
// the platform never calls CISA or FIRST, whatever threat_intel.source says.
type ThreatSourcePolicy struct {
	Inner interface {
		Policy(ctx context.Context) (threatsource.Policy, error)
	}
	Relay *Service
}

// Policy implements threat.SourcePolicy.
func (p ThreatSourcePolicy) Policy(ctx context.Context) (threatsource.Policy, error) {
	if p.Relay.RelayMode(ctx) {
		return threatsource.Policy{PreferBundle: true, DirectAllowed: false}, nil
	}
	if p.Inner == nil {
		return threatsource.Policy{DirectAllowed: true}, nil
	}
	return p.Inner.Policy(ctx)
}
