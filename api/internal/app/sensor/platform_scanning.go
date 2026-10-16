package sensor

import (
	"context"
	"fmt"
	"sort"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Platform scanning is how a tenant sees the shared platform sensors: a
// managed service with regions, a state per region, the tools it offers and
// the tenant's own platform jobs. Never a node: no sensor id, name, host,
// address or version, no node count, capacity or load, and nothing about
// other tenants. Managing platform sensors belongs to the platform admin
// console (RFC-022); on the tenant plane they are not found.
//
// The one operator detail it shows is the egress addresses the instance
// administrator published for allowlisting (docs/rfcs/RFC-100-shared-sensors.md
// §9): public addresses or ranges per region, the same for every
// organization, never tied to a sensor.

// PlatformScanningStore reads the summary (the postgres sensor repository).
type PlatformScanningStore interface {
	PlatformScanningSummary(ctx context.Context, tenantID shared.ID) (*sensordom.PlatformScanningSummary, error)
}

// PlatformScanningPolicy says whether the tenant may send scans to platform
// sensors, and why not when it may not (the scan trigger's own rule).
type PlatformScanningPolicy func(ctx context.Context, tenantID shared.ID) (bool, string)

// Platform scanning states, for the service as a whole and for one region.
const (
	// PlatformScanningAvailable: online, with a free job slot now.
	PlatformScanningAvailable = "available"
	// PlatformScanningBusy: online, every slot taken; new jobs wait.
	PlatformScanningBusy = "busy"
	// PlatformScanningUnavailable: nothing online; new jobs wait.
	PlatformScanningUnavailable = "unavailable"
)

// PlatformQueueLimitMinutes is how long a platform job waits for a slot
// before it fails (cmd/server workers.go MaxQueueMinutes).
const PlatformQueueLimitMinutes = 60

// PlatformRegion is one region of the service and its state.
type PlatformRegion struct {
	// Name is the operator's region label; empty when sensors carry none.
	Name   string `json:"name"`
	Status string `json:"status"`
}

// PlatformJobs counts the tenant's own platform jobs.
type PlatformJobs struct {
	Queued  int `json:"queued"`
	Running int `json:"running"`
}

// PlatformEgress is a set of egress addresses (IP or CIDR): Region empty
// for every region.
type PlatformEgress struct {
	Region    string   `json:"region"`
	Addresses []string `json:"addresses"`
}

// PlatformEgressSource reads the published egress addresses: the global
// list first (Region ""), then one entry per region, sorted.
type PlatformEgressSource func(ctx context.Context) ([]PlatformEgress, error)

// EgressFromLists orders published egress lists for the view: the global
// list first (Region ""), then each non-empty region, sorted by label.
func EgressFromLists(global []string, regions map[string][]string) []PlatformEgress {
	out := make([]PlatformEgress, 0, len(regions)+1)
	if len(global) > 0 {
		out = append(out, PlatformEgress{Addresses: global})
	}
	names := make([]string, 0, len(regions))
	for r, l := range regions {
		if len(l) > 0 {
			names = append(names, r)
		}
	}
	sort.Strings(names)
	for _, r := range names {
		out = append(out, PlatformEgress{Region: r, Addresses: regions[r]})
	}
	return out
}

// PlatformScanning is the tenant's view of platform scanning.
type PlatformScanning struct {
	// Offered: the organization may send scans to platform scanning and the
	// platform runs it. False says nothing else (not whether platform
	// sensors exist).
	Offered bool `json:"offered"`
	// Status is the best region's state; empty when not offered.
	Status  string           `json:"status,omitempty"`
	Regions []PlatformRegion `json:"regions"`
	// Tools are the tools platform scanning can run now.
	Tools []string `json:"tools"`
	// YourJobs are the organization's own platform jobs.
	YourJobs          PlatformJobs `json:"your_jobs"`
	QueueLimitMinutes int          `json:"queue_limit_minutes,omitempty"`
	// Egress are the addresses shared sensors send traffic from, to
	// allowlist; empty when the administrator published none.
	Egress []PlatformEgress `json:"egress"`
}

// PlatformScanningService builds the tenant's view of platform scanning.
type PlatformScanningService struct {
	store  PlatformScanningStore
	policy PlatformScanningPolicy
	egress PlatformEgressSource
}

// WithEgress sets where the published egress addresses come from.
func (s *PlatformScanningService) WithEgress(src PlatformEgressSource) *PlatformScanningService {
	s.egress = src
	return s
}

// NewPlatformScanningService builds the service. A nil policy offers
// platform scanning to no tenant.
func NewPlatformScanningService(store PlatformScanningStore, policy PlatformScanningPolicy) *PlatformScanningService {
	return &PlatformScanningService{store: store, policy: policy}
}

// Get returns the tenant's view of platform scanning.
func (s *PlatformScanningService) Get(ctx context.Context, tenantID shared.ID) (*PlatformScanning, error) {
	none := &PlatformScanning{Regions: []PlatformRegion{}, Tools: []string{}, Egress: []PlatformEgress{}}
	if s.policy == nil {
		return none, nil
	}
	if ok, _ := s.policy(ctx, tenantID); !ok {
		return none, nil
	}
	sum, err := s.store.PlatformScanningSummary(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to read platform scanning: %w", err)
	}
	if len(sum.Regions) == 0 {
		// No platform sensor at all: not offered, like a tenant without the
		// right to use it.
		return none, nil
	}
	out := &PlatformScanning{
		Offered:           true,
		Status:            PlatformScanningUnavailable,
		Regions:           make([]PlatformRegion, 0, len(sum.Regions)),
		Tools:             sum.Tools,
		YourJobs:          PlatformJobs{Queued: sum.Queued, Running: sum.Running},
		QueueLimitMinutes: PlatformQueueLimitMinutes,
		Egress:            []PlatformEgress{},
	}
	if s.egress != nil {
		eg, err := s.egress(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read the egress addresses: %w", err)
		}
		for _, e := range eg {
			if len(e.Addresses) > 0 {
				out.Egress = append(out.Egress, PlatformEgress{Region: e.Region, Addresses: append([]string(nil), e.Addresses...)})
			}
		}
	}
	if out.Tools == nil {
		out.Tools = []string{}
	}
	for _, r := range sum.Regions {
		st := regionStatus(r)
		out.Regions = append(out.Regions, PlatformRegion{Name: r.Region, Status: st})
		if rank(st) > rank(out.Status) {
			out.Status = st
		}
	}
	return out, nil
}

func regionStatus(r sensordom.PlatformRegionState) string {
	switch {
	case r.Online && r.FreeSlot:
		return PlatformScanningAvailable
	case r.Online:
		return PlatformScanningBusy
	default:
		return PlatformScanningUnavailable
	}
}

func rank(status string) int {
	switch status {
	case PlatformScanningAvailable:
		return 2
	case PlatformScanningBusy:
		return 1
	default:
		return 0
	}
}
