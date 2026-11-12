package sensorpairing

// What an approval can set up besides the sensor itself (research/466 D3,
// D4; docs/architecture/sensor-pairing.md "Approve with trust and
// networks"): trust for active scanning, and the private networks the
// sensor scans as a scan zone. Each is its own decision with its own
// permission, made in the form the approver is already in, and each is
// audited as if it had been made on its own page.
//
//   - Trusted: only for a request that attached to a console expectation of
//     this organization (the admin made the code and put it in the command),
//     never for a sensor-started code (/activate), an enrollment token, a
//     shared sensor or a re-pair; only for profiles without credentials and
//     push ingest (sensordom.TrustableAtApproval); needs sensors:grant:widen
//     and the widening approver; the approval's verified step-up is the
//     re-authentication. Audited as sensor.grant_changed, high, every
//     administrator notified, like a promotion.
//   - Networks: private ranges only (scanzone.ParseLANRanges); needs
//     sensors:zones:write; an existing zone of the organization with exactly
//     these ranges gets the sensor, else a new zone "<sensor> networks" is
//     created with the sensor assigned, in the approval's transaction.
//
// Scope is never written here: the console adds the ranges to scope after
// the approval, through the scope service and its approvals.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var (
	// ErrTrustNotAllowed: the approval asked for Trusted where the request
	// or the profile does not allow it (see TrustEligible).
	ErrTrustNotAllowed = errors.New("this sensor cannot be trusted at approval; promote it after approval")
	// ErrZonesForbidden: the approval stated networks without
	// sensors:zones:write.
	ErrZonesForbidden = errors.New("setting up a sensor's networks needs the sensors:zones:write permission")
	// ErrRangesInvalid wraps why the stated networks were refused.
	ErrRangesInvalid = errors.New("invalid networks")
)

// ZoneStore reads the organization's zones and creates one with its
// sensor inside the approval transaction.
type ZoneStore interface {
	List(ctx context.Context, tenantID shared.ID) ([]*scanzone.Zone, error)
	CreateWithSensorTx(ctx context.Context, tx *sql.Tx, z *scanzone.Zone, sensorID shared.ID, assignedBy *shared.ID) error
}

// SetZones wires the zone store (nil: approvals cannot state networks).
func (s *Service) SetZones(z ZoneStore) { s.zones = z }

// zoneProfiles are the profiles whose grant scans zone targets: stating
// networks for any other profile would set up a zone the sensor never
// scans.
var zoneProfiles = []string{sensordom.ProfileInternalScanner, sensordom.ProfileAuthenticatedScanner, sensordom.ProfileScanConnector}

// TrustEligible reports whether an approval of p may make the new sensor
// Trusted: p attached to a console expectation of the actor's
// organization, and is not a token's, a shared sensor's or a re-pair.
func TrustEligible(p *sensordom.Pairing, tenantID shared.ID) bool {
	return p != nil && p.Mode == sensordom.PairingReverse && p.CreatedBy != nil &&
		p.TenantID != nil && *p.TenantID == tenantID &&
		!p.IsEnrollment() && !p.IsInstance() && p.RepairSensorID == nil
}

// zonePlan is what the approval does with the stated networks.
type zonePlan struct {
	existing *scanzone.Zone // a zone with exactly these ranges
	create   *scanzone.Zone // else a new zone
}

// authorizeTrust checks a Trusted approval before anything is written.
func (s *Service) authorizeTrust(ctx context.Context, actor Actor, p *sensordom.Pairing, profile string, stepUpVerified bool) error {
	if s.hook == nil || !TrustEligible(p, actor.TenantID) || !sensordom.TrustableAtApproval(profile) {
		return ErrTrustNotAllowed
	}
	return s.hook.AuthorizeTrust(ctx, grantActor(actor, stepUpVerified))
}

// planZone validates the stated networks and finds or prepares the zone.
func (s *Service) planZone(ctx context.Context, actor Actor, ranges []string, profile, sensorName string) (*zonePlan, error) {
	if !actor.CanWriteZones {
		return nil, ErrZonesForbidden
	}
	if s.zones == nil {
		return nil, ErrInvalid
	}
	base, _, _ := strings.Cut(profile, ":")
	if !slices.Contains(zoneProfiles, base) {
		return nil, fmt.Errorf("%w: profile %s does not scan zone networks", ErrRangesInvalid, profile)
	}
	ps, err := scanzone.ParseLANRanges(ranges)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRangesInvalid, strings.TrimPrefix(err.Error(), shared.ErrValidation.Error()+": "))
	}
	zones, err := s.zones.List(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(zones))
	for _, z := range zones {
		names[strings.ToLower(z.Name)] = true
		if !z.IsDefault && slices.Equal(z.Ranges, ps) {
			return &zonePlan{existing: z}, nil
		}
	}
	if len(zones) >= scanzone.MaxZonesPerTenant {
		return nil, fmt.Errorf("%w: the organization already has %d scan zones", ErrRangesInvalid, scanzone.MaxZonesPerTenant)
	}
	strs := make([]string, len(ps))
	for i, p := range ps {
		strs[i] = p.String()
	}
	uid := actor.UserID
	z, err := scanzone.NewZone(actor.TenantID, zoneName(sensorName, names), "Networks stated when the sensor was approved", false, strs, &uid)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRangesInvalid, strings.TrimPrefix(err.Error(), shared.ErrValidation.Error()+": "))
	}
	return &zonePlan{create: z}, nil
}

// zoneName is "<sensor> networks", numbered when the name is taken.
func zoneName(sensor string, taken map[string]bool) string {
	sensor = truncate(strings.TrimSpace(sensor), scanzone.MaxNameLength-16)
	base := sensor + " networks"
	name := base
	for i := 2; taken[strings.ToLower(name)] && i < 1000; i++ {
		name = fmt.Sprintf("%s %d", base, i)
	}
	return name
}

// withZone runs the zone creation (and the sensor's assignment) before the
// grant step, inside the approval transaction.
func (s *Service) withZone(plan *zonePlan, actor Actor, next func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error) func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error {
	return func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error {
		if plan.create != nil && !repair {
			uid := actor.UserID
			if err := s.zones.CreateWithSensorTx(ctx, tx, plan.create, sensorID, &uid); err != nil {
				return err
			}
		}
		if next == nil {
			return nil
		}
		return next(ctx, tx, sensorID, repair)
	}
}

// auditZone records the zone the approval created or the assignment it
// made, as the Zones page would.
func (s *Service) auditZone(ctx context.Context, actor Actor, plan *zonePlan, sensorID shared.ID, sensorName string) {
	actx := s.auditContext(actor)
	if plan.create != nil {
		z := plan.create
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanZoneCreated, auditdom.ResourceTypeScanZone, z.ID.String()).
			WithResourceName(z.Name).WithMessage(fmt.Sprintf("Scan zone '%s' created while approving sensor %q", z.Name, sensorName)).
			WithMetadata("ranges", z.RangeStrings()).WithMetadata("is_default", false).
			WithMetadata("sensor_id", sensorID.String()).WithSeverity(auditdom.SeverityMedium))
	}
	z := plan.existing
	if z == nil {
		z = plan.create
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanZoneSensorAssigned, auditdom.ResourceTypeScanZone, z.ID.String()).
		WithResourceName(z.Name).WithMessage(fmt.Sprintf("Sensor %q assigned to scan zone '%s' at its approval", sensorName, z.Name)).
		WithMetadata("sensor_id", sensorID.String()).WithSeverity(auditdom.SeverityMedium))
}

// grantActor is the approver as the grant service sees it. stepUpVerified is
// true only from Approve, after VerifyStepUp accepted the proof in this
// request; any other caller passes false.
func grantActor(a Actor, stepUpVerified bool) sensorgrant.Actor {
	return sensorgrant.Actor{TenantID: a.TenantID, UserID: a.UserID, Email: a.Email, IP: a.IP, UserAgent: a.UserAgent,
		SessionID: a.SessionID, CanWiden: a.CanWiden, StepUpVerified: stepUpVerified}
}
