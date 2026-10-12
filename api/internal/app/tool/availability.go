package tool

// Tool availability (docs/architecture/tool-availability.md): the catalog
// joined with the tools the tenant's sensors report in their manifests.
//
// Security: every source is read for the caller's tenant only (its sensors,
// their grants and zones, its catalog: platform tools plus its own custom
// tools); shared platform sensors are left out, as on the Sensors page, since
// a tenant's scans never run on them in this edition. What a sensor reports
// is untrusted display data: claim-time gates stay authoritative.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// SensorLister lists every sensor of a tenant (the tenant's own, no platform
// sensors), as the Sensors page does.
type SensorLister interface {
	ListAllSensors(ctx context.Context, tenantID string) ([]*sensor.Sensor, error)
}

// ZoneLister lists a tenant's scan zones with their sensors.
type ZoneLister interface {
	List(ctx context.Context, tenantID shared.ID) ([]*scanzone.Zone, error)
}

// GrantLister lists the grants of a tenant's sensors by sensor id.
type GrantLister interface {
	ListByTenant(ctx context.Context, tenantID shared.ID) (map[shared.ID]*sensor.Grant, error)
}

// ManifestLister reads the current manifests of a tenant's sensors, keyed
// by sensor id (sensor.ManifestStore).
type ManifestLister interface {
	CurrentManifestsByTenant(ctx context.Context, tenantID shared.ID) (map[shared.ID]*sensor.ManifestVersion, error)
}

// SetManifestSource wires the sensors' manifests: their tool contracts give
// each tool's trust and platform-assigned tier in the view (RFC-055 §5).
func (s *Service) SetManifestSource(m ManifestLister) { s.availManifests = m }

// SetAvailabilitySources wires what the availability view reads. Without
// them availability is unknown and every tool counts as available (the
// is_available flag never blocks a picker on a misconfigured server).
func (s *Service) SetAvailabilitySources(sensors SensorLister, zones ZoneLister, grants GrantLister) {
	s.availSensors, s.availZones, s.availGrants = sensors, zones, grants
}

// catalogPageSize is the page size the catalog is read in.
const catalogPageSize = 100

// maxCatalogTools bounds the catalog the view reads (platform tools plus
// the tenant's custom tools).
const maxCatalogTools = 2000

// AvailableTool is one tool of the availability view: the computed
// availability plus the catalog entry (nil for a tool a sensor reports that
// the catalog does not list).
type AvailableTool struct {
	sensor.ToolAvailability
	Tool     *tooldom.Tool
	Category *tooldom.EmbeddedCategory
}

// ToolAvailabilityResult is the availability view of one tenant.
type ToolAvailabilityResult struct {
	Tools   []AvailableTool
	Summary map[sensor.ToolStatus]int
	// Zones names the zones the listed sensors are assigned to.
	Zones map[shared.ID]string
	// ZoneID is the zone the view was limited to (nil: all sensors).
	ZoneID     *shared.ID
	ComputedAt time.Time
}

// ErrZoneNotFound: the scan zone the availability view was asked for is
// not the tenant's (or does not exist).
var ErrZoneNotFound = fmt.Errorf("%w: scan zone", shared.ErrNotFound)

// ToolAvailability computes the tenant's tool availability. zoneID ("" for
// none) limits it to the sensors of one of the tenant's scan zones; a zone
// of another tenant is not found.
func (s *Service) ToolAvailability(ctx context.Context, tenantID, zoneID string) (*ToolAvailabilityResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	var zone *shared.ID
	if zoneID != "" {
		z, err := shared.IDFromString(zoneID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid zone id", shared.ErrValidation)
		}
		zone = &z
	}

	catalog, err := s.tenantCatalog(ctx, tid)
	if err != nil {
		return nil, err
	}
	inv, zoneNames, err := s.sensorInventories(ctx, tid)
	if err != nil {
		return nil, err
	}
	if zone != nil {
		if _, ok := zoneNames[*zone]; !ok {
			return nil, ErrZoneNotFound
		}
	}

	now := time.Now()
	entries := make([]sensor.CatalogTool, 0, len(catalog))
	byName := make(map[string]*tooldom.ToolWithConfig, len(catalog))
	for _, twc := range catalog {
		if _, dup := byName[twc.Tool.Name]; dup {
			continue
		}
		byName[twc.Tool.Name] = twc
		entries = append(entries, sensor.CatalogTool{
			Name:          twc.Tool.Name,
			Enabled:       twc.Tool.IsActive && twc.IsEnabled,
			MinVersion:    twc.Tool.MinVersion,
			LatestVersion: twc.Tool.LatestVersion,
		})
	}

	computed := sensor.ComputeToolAvailability(entries, inv, zone, now)
	out := &ToolAvailabilityResult{
		Tools:      make([]AvailableTool, 0, len(computed)),
		Summary:    sensor.SummarizeToolStatuses(computed),
		Zones:      map[shared.ID]string{},
		ZoneID:     zone,
		ComputedAt: now,
	}
	for _, ta := range computed {
		at := AvailableTool{ToolAvailability: ta}
		if twc := byName[ta.Name]; twc != nil {
			at.Tool, at.Category = twc.Tool, twc.Category
		}
		for _, ts := range ta.Sensors {
			for _, z := range ts.ZoneIDs {
				out.Zones[z] = zoneNames[z]
			}
		}
		out.Tools = append(out.Tools, at)
	}
	if zone != nil {
		out.Zones[*zone] = zoneNames[*zone]
	}
	return out, nil
}

// RunnableToolNames returns the tools a scan job can be dispatched for now
// (enabled, on an online sensor that may run them); nil without the
// availability sources (unknown).
func (s *Service) RunnableToolNames(ctx context.Context, tenantID string) (map[string]bool, error) {
	if s.availSensors == nil {
		return nil, nil
	}
	res, err := s.ToolAvailability(ctx, tenantID, "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(res.Tools))
	for _, t := range res.Tools {
		if t.Runnable() {
			out[t.Name] = true
		}
	}
	return out, nil
}

// ToolAvailabilityFor returns one tool's availability for the tenant, in
// zoneID when set; nil when the tool is not listed or availability is not
// wired (unknown).
func (s *Service) ToolAvailabilityFor(ctx context.Context, tenantID shared.ID, zoneID *shared.ID, name string) (*sensor.ToolAvailability, error) {
	if s.availSensors == nil {
		return nil, nil
	}
	zone := ""
	if zoneID != nil {
		zone = zoneID.String()
	}
	res, err := s.ToolAvailability(ctx, tenantID.String(), zone)
	if err != nil {
		return nil, err
	}
	for i := range res.Tools {
		if res.Tools[i].Name == name {
			ta := res.Tools[i].ToolAvailability
			return &ta, nil
		}
	}
	return nil, nil
}

// tenantCatalog reads the tenant's catalog (platform tools and its own
// custom tools, active or not) with its enable switches.
func (s *Service) tenantCatalog(ctx context.Context, tenantID shared.ID) ([]*tooldom.ToolWithConfig, error) {
	var all []*tooldom.ToolWithConfig
	for page := 1; len(all) < maxCatalogTools; page++ {
		res, err := s.configRepo.ListToolsWithConfig(ctx, tenantID, tooldom.ToolFilter{}, pagination.New(page, catalogPageSize))
		if err != nil {
			return nil, fmt.Errorf("failed to read the tool catalog: %w", err)
		}
		all = append(all, res.Data...)
		if len(res.Data) < catalogPageSize || int64(len(all)) >= res.Total {
			break
		}
	}
	return all, nil
}

// sensorInventories reads the tenant's sensors with their grants and zones,
// and the names of the tenant's zones. Without the sources the inventory is
// empty.
func (s *Service) sensorInventories(ctx context.Context, tenantID shared.ID) ([]sensor.SensorInventory, map[shared.ID]string, error) {
	zoneNames := map[shared.ID]string{}
	if s.availSensors == nil {
		return nil, zoneNames, nil
	}
	sensors, err := s.availSensors.ListAllSensors(ctx, tenantID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list sensors: %w", err)
	}
	zonesBySensor := map[shared.ID][]shared.ID{}
	if s.availZones != nil {
		zones, err := s.availZones.List(ctx, tenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list scan zones: %w", err)
		}
		for _, z := range zones {
			zoneNames[z.ID] = z.Name
			for _, sid := range z.SensorIDs {
				zonesBySensor[sid] = append(zonesBySensor[sid], z.ID)
			}
		}
	}
	var grants map[shared.ID]*sensor.Grant
	if s.availGrants != nil {
		if grants, err = s.availGrants.ListByTenant(ctx, tenantID); err != nil {
			return nil, nil, fmt.Errorf("failed to list sensor grants: %w", err)
		}
	}
	var manifests map[shared.ID]*sensor.ManifestVersion
	if s.availManifests != nil {
		if manifests, err = s.availManifests.CurrentManifestsByTenant(ctx, tenantID); err != nil {
			return nil, nil, fmt.Errorf("failed to read sensor manifests: %w", err)
		}
	}
	inv := make([]sensor.SensorInventory, 0, len(sensors))
	for _, a := range sensors {
		if a.TenantID == nil || *a.TenantID != tenantID {
			continue // defense in depth: the lister is tenant-scoped
		}
		item := sensor.SensorInventory{Sensor: a, Grant: grants[a.ID], ZoneIDs: zonesBySensor[a.ID]}
		if v := manifests[a.ID]; v != nil && v.TenantID != nil && *v.TenantID == tenantID {
			item.Manifest = &v.Manifest
		}
		inv = append(inv, item)
	}
	return inv, zoneNames, nil
}
