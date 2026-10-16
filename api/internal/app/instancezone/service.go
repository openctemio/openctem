// Package instancezone manages instance scan zones
// (docs/rfcs/RFC-100-shared-sensors.md §6.1): private ranges an instance
// administrator lets shared sensors scan, the shared sensors that serve
// each zone and the organizations it is assigned to, and the lookup the
// scan trigger uses to route an organization's internal target to a shared
// sensor.
//
// Threat model: a zone lets shared sensors, which serve every allowed
// organization from the operator's network, reach private ranges. So:
//
//   - only a super admin with a fresh authenticator code (route step-up) and
//     a reason changes a zone; every change is a critical admin audit row;
//   - every change goes to the job signer's zone ledger first, and the
//     database changes only when the signer recorded it: a narrowing
//     (unassign, delete, fewer ranges) takes effect at the signer before
//     the platform stops routing, a widening is refused when the signer is
//     unreachable;
//   - the lookup reads only the zones assigned to the asking organization,
//     so overlapping private ranges of two organizations never mix, and it
//     answers nothing while "shared sensors may scan internal zones" is off
//     or unreadable (fail closed);
//   - the zone's ranges reach a shared sensor only inside the signed job
//     statement, never as an unsigned command field.
package instancezone

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	zonedom "github.com/openctemio/openctem/api/pkg/domain/instancezone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions.
const (
	ActionZoneCreated       = "platform.instance_scan_zone_created"
	ActionZoneUpdated       = "platform.instance_scan_zone_updated"
	ActionZoneDeleted       = "platform.instance_scan_zone_deleted"
	ActionZoneSensorsSet    = "platform.instance_scan_zone_sensors_changed"
	ActionZoneTenantsSet    = "platform.instance_scan_zone_organizations_changed"
	resourceInstanceScanZon = "instance_scan_zone"
)

// ErrSignerRefused: the job signer did not record the change, so it was
// not made.
var ErrSignerRefused = fmt.Errorf("%w: the job signer did not record the zone change; nothing was changed", shared.ErrConflict)

// ZoneLedger records zone changes with the job signer (*signer.Client).
type ZoneLedger interface {
	ApplyZone(ctx context.Context, ch jobsign.ZoneChange) (jobsign.ZoneChangeResult, error)
}

// InternalZonesPolicy says whether shared sensors may scan internal zones
// now (*scanpolicy.Service; an unreadable setting answers false).
type InternalZonesPolicy interface {
	SharedSensorsInternalZonesAllowed(ctx context.Context) bool
}

// AuditWriter writes admin audit rows.
type AuditWriter interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// Change is who changes a zone and why. The handler checked super_admin and
// a fresh authenticator code.
type Change struct {
	Actor     *admin.AdminUser
	Reason    string
	IP        string
	UserAgent string
}

func (c Change) check() error {
	if c.Actor == nil {
		return fmt.Errorf("%w: an instance administrator changes zones", shared.ErrForbidden)
	}
	if strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 1000 {
		return fmt.Errorf("%w: a reason (at most 1000 characters) is required", shared.ErrValidation)
	}
	return nil
}

// Service manages instance scan zones.
type Service struct {
	repo   zonedom.Repository
	ledger ZoneLedger
	policy InternalZonesPolicy
	audit  AuditWriter
	log    *logger.Logger
}

// NewService creates the service. Without a ledger (no job signer) zones
// can be stored, but no shared job is ever signed for them; without a
// policy the lookup answers nothing.
func NewService(repo zonedom.Repository, ledger ZoneLedger, policy InternalZonesPolicy, audit AuditWriter, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, ledger: ledger, policy: policy, audit: audit, log: log.With("service", "instance_scan_zones")}
}

// List returns every zone.
func (s *Service) List(ctx context.Context) ([]*zonedom.Zone, error) { return s.repo.List(ctx) }

// Get returns one zone.
func (s *Service) Get(ctx context.Context, id shared.ID) (*zonedom.Zone, error) {
	return s.repo.Get(ctx, id)
}

// Create adds a zone with no sensors and no organizations.
func (s *Service) Create(ctx context.Context, name, description string, ranges []string, c Change) (*zonedom.Zone, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	z, err := zonedom.New(name, description, ranges)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, c, jobsign.ZoneChange{Put: ptr(z.LedgerZone())}); err != nil {
		return nil, err
	}
	by := c.Actor.ID()
	if err := s.repo.Create(ctx, z, &by); err != nil {
		return nil, err
	}
	s.auditRow(ctx, c, ActionZoneCreated, z, map[string]any{"ranges": z.Ranges})
	return z, nil
}

// Update changes the name, description and ranges.
func (s *Service) Update(ctx context.Context, id shared.ID, name, description string, ranges []string, c Change) (*zonedom.Zone, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	z, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	prev := z.Ranges
	if err := z.Set(name, description, ranges); err != nil {
		return nil, err
	}
	if err := s.record(ctx, c, jobsign.ZoneChange{Put: ptr(z.LedgerZone())}); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, z); err != nil {
		return nil, err
	}
	s.auditRow(ctx, c, ActionZoneUpdated, z, map[string]any{"from_ranges": prev, "to_ranges": z.Ranges})
	return z, nil
}

// Delete removes a zone. Queued jobs of the zone are never signed again.
func (s *Service) Delete(ctx context.Context, id shared.ID, c Change) error {
	if err := c.check(); err != nil {
		return err
	}
	z, err := s.repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.record(ctx, c, jobsign.ZoneChange{DeleteID: id.String()}); err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.auditRow(ctx, c, ActionZoneDeleted, z, map[string]any{"ranges": z.Ranges})
	return nil
}

// SetSensors replaces the shared sensors that serve the zone.
func (s *Service) SetSensors(ctx context.Context, id shared.ID, sensorIDs []shared.ID, c Change) (*zonedom.Zone, error) {
	if len(sensorIDs) > zonedom.MaxSensorsPerZone {
		return nil, fmt.Errorf("%w: at most %d sensors", shared.ErrValidation, zonedom.MaxSensorsPerZone)
	}
	return s.setMembers(ctx, id, c, ActionZoneSensorsSet, func(z *zonedom.Zone) { z.SensorIDs = dedupe(sensorIDs) },
		func(z *zonedom.Zone, by *shared.ID) error { return s.repo.SetSensors(ctx, id, z.SensorIDs, by) })
}

// SetTenants replaces the organizations the zone is assigned to.
func (s *Service) SetTenants(ctx context.Context, id shared.ID, tenantIDs []shared.ID, c Change) (*zonedom.Zone, error) {
	if len(tenantIDs) > zonedom.MaxTenantsPerZone {
		return nil, fmt.Errorf("%w: at most %d organizations", shared.ErrValidation, zonedom.MaxTenantsPerZone)
	}
	return s.setMembers(ctx, id, c, ActionZoneTenantsSet, func(z *zonedom.Zone) { z.TenantIDs = dedupe(tenantIDs) },
		func(z *zonedom.Zone, by *shared.ID) error { return s.repo.SetTenants(ctx, id, z.TenantIDs, by) })
}

func (s *Service) setMembers(ctx context.Context, id shared.ID, c Change, action string,
	edit func(*zonedom.Zone), save func(*zonedom.Zone, *shared.ID) error,
) (*zonedom.Zone, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	z, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	before := z.LedgerZone()
	edit(z)
	after := z.LedgerZone()
	if err := s.record(ctx, c, jobsign.ZoneChange{Put: &after}); err != nil {
		return nil, err
	}
	by := c.Actor.ID()
	if err := save(z, &by); err != nil {
		// Put the signer back to what the database still holds.
		if rerr := s.record(ctx, c, jobsign.ZoneChange{Put: &before}); rerr != nil {
			s.log.Error("zone change failed and the signer could not be restored; re-save the zone", "zone_id", id.String(), "error", rerr)
		}
		return nil, err
	}
	s.auditRow(ctx, c, action, z, map[string]any{
		"from_sensors": before.Sensors, "to_sensors": after.Sensors,
		"from_organizations": before.Tenants, "to_organizations": after.Tenants,
	})
	return z, nil
}

// record sends a change to the signer's zone ledger. Without a signer the
// change is stored only (no shared job is signed without one).
func (s *Service) record(ctx context.Context, c Change, ch jobsign.ZoneChange) error {
	if s.ledger == nil {
		return nil
	}
	ch.Requester = c.Actor.Email()
	if _, err := s.ledger.ApplyZone(ctx, ch); err != nil {
		s.log.Warn("job signer did not record the zone change", "error", logger.SanitizeError(err))
		return ErrSignerRefused
	}
	return nil
}

func (s *Service) auditRow(ctx context.Context, c Change, action string, z *zonedom.Zone, body map[string]any) {
	s.log.Warn("instance scan zone changed", "alert", strings.TrimPrefix(action, "platform."),
		"admin_id", c.Actor.ID().String(), "zone_id", z.ID.String())
	if s.audit == nil {
		return
	}
	body["reason"] = strings.TrimSpace(c.Reason)
	entry := admin.NewAuditLogBuilder(c.Actor, action).
		Resource(resourceInstanceScanZon, &z.ID, z.Name).
		Context(c.IP, c.UserAgent).
		Request("PUT", "", body).
		Critical().
		Build()
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.audit.Create(actx, entry); err != nil {
		s.log.Error("write admin audit for instance scan zone change", "error", err)
	}
}

// ZoneFor returns the instance scan zone that lets a shared sensor reach the
// organization's internal targets: the one zone assigned to the
// organization that contains every internal target, or nil. It answers nil
// while shared sensors may not scan internal zones, when an internal target
// is a name (names are never routed into a zone), and when no single zone
// contains them all. A failed lookup is the error (callers refuse).
func (s *Service) ZoneFor(ctx context.Context, tenantID shared.ID, internalTargets []string) (*zonedom.Zone, error) {
	if len(internalTargets) == 0 || s.policy == nil || !s.policy.SharedSensorsInternalZonesAllowed(ctx) {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(internalTargets))
	for _, t := range internalTargets {
		p, ok := zonedom.TargetPrefix(t)
		if !ok {
			return nil, nil
		}
		prefixes = append(prefixes, p)
	}
	zones, err := s.repo.ListForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list instance scan zones: %w", err)
	}
	// Defense in depth: the repository filters by assignment; keep only
	// zones that name the organization.
	own := zones[:0]
	for _, z := range zones {
		if z.AssignedTo(tenantID) && len(z.SensorIDs) > 0 {
			own = append(own, z)
		}
	}
	return zonedom.Covering(own, prefixes), nil
}

// StatementZone returns the zone a shared job's signed statement names
// (id and ranges), or an error when the zone is gone.
func (s *Service) StatementZone(ctx context.Context, id shared.ID) (*jobsign.StatementZone, error) {
	z, err := s.repo.Get(ctx, id)
	if errors.Is(err, zonedom.ErrNotFound) {
		return nil, fmt.Errorf("instance scan zone %s no longer exists", id)
	}
	if err != nil {
		return nil, err
	}
	return &jobsign.StatementZone{ID: z.ID.String(), Ranges: z.Ranges}, nil
}

func ptr[T any](v T) *T { return &v }

func dedupe(ids []shared.ID) []shared.ID {
	seen := make(map[shared.ID]bool, len(ids))
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
