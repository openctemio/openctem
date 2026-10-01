// Package scanzone is the application service for scan zones: CRUD, sensor
// assignment and the coverage view. Design: docs/rfcs/RFC-023-scan-zones-and-scanners.md;
// architecture: docs/architecture/scan-zones.md.
package scanzone

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/api/internal/app/audit"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
	zonedom "github.com/openctemio/api/pkg/domain/scanzone"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service manages a tenant's scan zones.
type Service struct {
	repo   zonedom.Repository
	audit  AuditLogger
	logger *logger.Logger
}

// NewService creates the scan zone service. audit may be nil (tests).
func NewService(repo zonedom.Repository, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{repo: repo, audit: audit, logger: log.With("service", "scan_zone")}
}

// CreateInput is the input of CreateZone.
type CreateInput struct {
	TenantID    string
	Name        string
	Description string
	IsDefault   bool
	Ranges      []string
	CreatedBy   string
}

// UpdateInput is the input of UpdateZone; nil fields are left unchanged.
type UpdateInput struct {
	TenantID    string
	ZoneID      string
	Name        *string
	Description *string
	IsDefault   *bool
	Ranges      *[]string
}

func parseIDs(tenantID, id string) (shared.ID, shared.ID, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if id == "" {
		return tid, shared.ID{}, nil
	}
	zid, err := shared.IDFromString(id)
	if err != nil {
		// A malformed id cannot name a zone of this tenant.
		return tid, shared.ID{}, zonedom.ErrZoneNotFound
	}
	return tid, zid, nil
}

// CreateZone validates and stores a new zone.
func (s *Service) CreateZone(ctx context.Context, in CreateInput, actx auditapp.AuditContext) (*zonedom.Zone, error) {
	tenantID, _, err := parseIDs(in.TenantID, "")
	if err != nil {
		return nil, err
	}
	var createdBy *shared.ID
	if in.CreatedBy != "" {
		if id, err := shared.IDFromString(in.CreatedBy); err == nil {
			createdBy = &id
		}
	}
	z, err := zonedom.NewZone(tenantID, in.Name, in.Description, in.IsDefault, in.Ranges, createdBy)
	if err != nil {
		return nil, err
	}
	n, err := s.repo.Count(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if n >= zonedom.MaxZonesPerTenant {
		return nil, zonedom.ErrTooManyZones
	}
	if err := s.repo.Create(ctx, z); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanZoneCreated, auditdom.ResourceTypeScanZone, z.ID.String()).
		WithResourceName(z.Name).
		WithMessage(fmt.Sprintf("Scan zone '%s' created", z.Name)).
		WithMetadata("ranges", z.RangeStrings()).
		WithMetadata("is_default", z.IsDefault).
		WithSeverity(auditdom.SeverityMedium))
	return z, nil
}

// UpdateZone changes a zone. Changing ranges takes effect for the next
// trigger; commands already routed keep their zone.
func (s *Service) UpdateZone(ctx context.Context, in UpdateInput, actx auditapp.AuditContext) (*zonedom.Zone, error) {
	tenantID, zoneID, err := parseIDs(in.TenantID, in.ZoneID)
	if err != nil {
		return nil, err
	}
	z, err := s.repo.GetByID(ctx, tenantID, zoneID)
	if err != nil {
		return nil, err
	}
	before := z.RangeStrings()
	beforeName, beforeDefault := z.Name, z.IsDefault
	if err := z.Update(in.Name, in.Description, in.IsDefault, in.Ranges); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, z); err != nil {
		return nil, err
	}
	changes := auditdom.NewChanges()
	if beforeName != z.Name {
		changes.Set("name", beforeName, z.Name)
	}
	if beforeDefault != z.IsDefault {
		changes.Set("is_default", beforeDefault, z.IsDefault)
	}
	if after := z.RangeStrings(); strings.Join(before, ",") != strings.Join(after, ",") {
		changes.Set("ranges", before, after)
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanZoneUpdated, auditdom.ResourceTypeScanZone, z.ID.String()).
		WithResourceName(z.Name).
		WithChanges(changes).
		WithMessage(fmt.Sprintf("Scan zone '%s' updated", z.Name)).
		WithSeverity(auditdom.SeverityMedium))
	return z, nil
}

// DeleteZone deletes a zone that has no active commands.
func (s *Service) DeleteZone(ctx context.Context, tenantID, id string, actx auditapp.AuditContext) error {
	tid, zid, err := parseIDs(tenantID, id)
	if err != nil {
		return err
	}
	z, err := s.repo.GetByID(ctx, tid, zid)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tid, zid); err != nil {
		return err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanZoneDeleted, auditdom.ResourceTypeScanZone, z.ID.String()).
		WithResourceName(z.Name).
		WithMessage(fmt.Sprintf("Scan zone '%s' deleted", z.Name)).
		WithMetadata("ranges", z.RangeStrings()).
		WithSeverity(auditdom.SeverityHigh))
	return nil
}

// GetZone returns one zone.
func (s *Service) GetZone(ctx context.Context, tenantID, id string) (*zonedom.Zone, error) {
	tid, zid, err := parseIDs(tenantID, id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, tid, zid)
}

// ListZones returns every zone of the tenant.
func (s *Service) ListZones(ctx context.Context, tenantID string) ([]*zonedom.Zone, error) {
	tid, _, err := parseIDs(tenantID, "")
	if err != nil {
		return nil, err
	}
	return s.repo.List(ctx, tid)
}

// AssignSensor assigns a sensor of the tenant to a zone (idempotent).
func (s *Service) AssignSensor(ctx context.Context, tenantID, zoneID, sensorID string, actx auditapp.AuditContext) (*zonedom.Zone, error) {
	tid, zid, err := parseIDs(tenantID, zoneID)
	if err != nil {
		return nil, err
	}
	sid, err := shared.IDFromString(sensorID)
	if err != nil {
		return nil, zonedom.ErrSensorNotFound
	}
	z, err := s.repo.GetByID(ctx, tid, zid)
	if err != nil {
		return nil, err
	}
	already := z.HasSensor(sid)
	var by *shared.ID
	if id, err := shared.IDFromString(actx.ActorID); err == nil {
		by = &id
	}
	if err := s.repo.AssignSensor(ctx, tid, zid, sid, by); err != nil {
		return nil, err
	}
	if !already {
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanZoneSensorAssigned, auditdom.ResourceTypeScanZone, z.ID.String()).
			WithResourceName(z.Name).
			WithMessage(fmt.Sprintf("Sensor %s assigned to scan zone '%s'", sid, z.Name)).
			WithMetadata("sensor_id", sid.String()).
			WithSeverity(auditdom.SeverityMedium))
	}
	return s.repo.GetByID(ctx, tid, zid)
}

// UnassignSensor removes a sensor from a zone. Its pending commands in the
// zone return to the zone's pool for another assigned sensor.
func (s *Service) UnassignSensor(ctx context.Context, tenantID, zoneID, sensorID string, actx auditapp.AuditContext) error {
	tid, zid, err := parseIDs(tenantID, zoneID)
	if err != nil {
		return err
	}
	sid, err := shared.IDFromString(sensorID)
	if err != nil {
		return zonedom.ErrSensorNotFound
	}
	z, err := s.repo.GetByID(ctx, tid, zid)
	if err != nil {
		return err
	}
	removed, err := s.repo.UnassignSensor(ctx, tid, zid, sid)
	if err != nil {
		return err
	}
	if !removed {
		return zonedom.ErrSensorNotFound
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanZoneSensorUnassigned, auditdom.ResourceTypeScanZone, z.ID.String()).
		WithResourceName(z.Name).
		WithMessage(fmt.Sprintf("Sensor %s removed from scan zone '%s'", sid, z.Name)).
		WithMetadata("sensor_id", sid.String()).
		WithSeverity(auditdom.SeverityMedium))
	return nil
}

// Warning codes on the coverage view.
const (
	WarnNoSensors              = "no_sensors_assigned"
	WarnPrivateWithoutHealthy  = "private_ranges_without_healthy_sensor" // RFC-023 V3
	WarnDefaultWithoutHealthy  = "default_zone_without_healthy_sensor"
	WarnUnzonedPrivate         = "private_addresses_outside_zones"
	WarnPublicWithoutDefault   = "public_addresses_without_default_zone"
	warnNoHealthySensorMessage = "no assigned sensor is online: jobs for this zone wait until one is"
)

// CoverageWarning is one actionable finding of the coverage view.
type CoverageWarning struct {
	Code    string `json:"code"`
	ZoneID  string `json:"zone_id,omitempty"`
	Message string `json:"message"`
}

// CoverageView is the coverage of a tenant's inventory and zones.
type CoverageView struct {
	*zonedom.Coverage
	Warnings []CoverageWarning
}

// Coverage reports how inventory addresses fall into zones, and zones that
// cannot be served (RFC-023 §7 and V3).
func (s *Service) Coverage(ctx context.Context, tenantID string) (*CoverageView, error) {
	tid, _, err := parseIDs(tenantID, "")
	if err != nil {
		return nil, err
	}
	cov, err := s.repo.Coverage(ctx, tid)
	if err != nil {
		return nil, err
	}
	return &CoverageView{Coverage: cov, Warnings: coverageWarnings(cov)}, nil
}

func coverageWarnings(cov *zonedom.Coverage) []CoverageWarning {
	var out []CoverageWarning
	for _, z := range cov.Zones {
		switch {
		case z.AssignedSensors == 0:
			out = append(out, CoverageWarning{Code: WarnNoSensors, ZoneID: z.ZoneID.String(),
				Message: fmt.Sprintf("zone %q has no sensors: its targets are skipped", z.Name)})
		case z.HealthySensors == 0 && z.HasPrivateRange:
			out = append(out, CoverageWarning{Code: WarnPrivateWithoutHealthy, ZoneID: z.ZoneID.String(),
				Message: fmt.Sprintf("zone %q has private ranges and %s", z.Name, warnNoHealthySensorMessage)})
		case z.HealthySensors == 0 && z.IsDefault:
			out = append(out, CoverageWarning{Code: WarnDefaultWithoutHealthy, ZoneID: z.ZoneID.String(),
				Message: fmt.Sprintf("default zone %q: %s", z.Name, warnNoHealthySensorMessage)})
		}
	}
	if len(cov.Zones) > 0 && cov.OutsidePrivate > 0 {
		out = append(out, CoverageWarning{Code: WarnUnzonedPrivate,
			Message: fmt.Sprintf("%d private inventory addresses are in no zone and are skipped by scans", cov.OutsidePrivate)})
	}
	if len(cov.Zones) > 0 && !cov.HasDefaultZone && cov.OutsidePublic > 0 {
		out = append(out, CoverageWarning{Code: WarnPublicWithoutDefault,
			Message: fmt.Sprintf("%d public inventory addresses are in no zone and the tenant has no default zone: they are dispatched to any tenant sensor, as before zones", cov.OutsidePublic)})
	}
	return out
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to write scan zone audit event", "action", string(ev.Action), "error", err)
	}
}
