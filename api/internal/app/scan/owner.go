package scan

// Scan ownership: a scheduled run acts as the scan's owner (created_by) and
// never as the system (docs/architecture/scan-ownership.md). A scan whose
// owner is missing (the account was deleted, or it was saved without one) or
// no longer an active member is paused at its next due run, the
// organization's administrators are told once, and an administrator takes
// ownership in one click.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Owner states of a scan, as the API reports them.
const (
	OwnerStateOK       = "ok"
	OwnerStateMissing  = "missing"
	OwnerStateInactive = "inactive"
	// OwnerStateManaged: a platform policy owns the scan; it has no owner
	// and nobody takes it over (ErrScanManagedByPolicy).
	OwnerStateManaged = "managed"
)

// ErrScanManagedByPolicy refuses a change to, or a run of, a scan a platform
// policy owns (continuous coverage, automatic enrichment): its definition is
// changed through that policy, never through the scan API.
var ErrScanManagedByPolicy = shared.NewDomainError("SCAN_MANAGED_BY_POLICY",
	"This scan is managed by the platform. Its settings and runs are controlled by the policy that owns it; clone it to get a scan you own.",
	shared.ErrConflict)

// refuseManaged refuses a member's change to a managed scan.
func refuseManaged(sc *scan.Scan) error {
	if sc.IsManaged() {
		return ErrScanManagedByPolicy
	}
	return nil
}

// ErrScanOwnerActive refuses a take-over of a scan whose owner is an active
// member: ownership moves only away from a missing or departed owner.
var ErrScanOwnerActive = shared.NewDomainError("SCAN_OWNER_ACTIVE",
	"This scan's owner is an active member. Ownership is taken only from a scan whose owner is missing or left the organization.",
	shared.ErrConflict)

// ErrScheduledScanNeedsOwner refuses a scheduled scan created without a
// person who owns it (an API key that belongs to no user).
var ErrScheduledScanNeedsOwner = shared.NewDomainError("SCAN_OWNER_REQUIRED",
	"A scheduled scan needs an owner: its scheduled runs act as that person. Create it as a member, or with an API key that belongs to a user.",
	shared.ErrValidation)

// AdminDirectory lists the active owners and administrators of a tenant
// (postgres.MemberLifecycleRepository).
type AdminDirectory interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// InAppNotifier sends one in-app notification.
type InAppNotifier interface {
	Notify(ctx context.Context, p notificationdom.NotificationParams) error
}

// ownerWriter changes a scan's owner, compare-and-swap on the previous one
// (postgres.ScanRepository).
type ownerWriter interface {
	SetOwner(ctx context.Context, tenantID, scanID shared.ID, prev *shared.ID, owner shared.ID) (bool, error)
}

// SetOwnerNotifications wires the notice an ownerless pause sends to the
// organization's administrators.
func (s *Service) SetOwnerNotifications(d AdminDirectory, n InAppNotifier) {
	s.ownerAdmins, s.ownerNotifier = d, n
}

// OwnerState reports whether sc has an owner who is an active member. A
// lookup error reports ok: the state is advisory, the scheduled-run gate
// checks again and fails closed.
func (s *Service) OwnerState(ctx context.Context, sc *scan.Scan) string {
	if sc.IsManaged() {
		return OwnerStateManaged
	}
	if sc.CreatedBy == nil || sc.CreatedBy.IsZero() {
		return OwnerStateMissing
	}
	if s.ownerActivity == nil {
		return OwnerStateOK
	}
	active, err := s.ownerActivity.IsActiveTenantMember(ctx, sc.TenantID, *sc.CreatedBy)
	if err != nil {
		s.logger.Warn("check scan owner state", "scan_id", sc.ID.String(), "error", err)
		return OwnerStateOK
	}
	if !active {
		return OwnerStateInactive
	}
	return OwnerStateOK
}

// pauseForOwner pauses sc after a scheduled run was refused for its owner.
// The administrators are told once: when this call moved the scan from
// active to paused. A paused scan has no due runs, so no further refusal
// (and no further notice) follows until someone resumes it.
func (s *Service) pauseForOwner(ctx context.Context, sc *scan.Scan, state string) {
	if sc.Status != scan.StatusActive {
		return
	}
	if err := sc.Pause(); err != nil {
		return
	}
	if err := s.scanRepo.Update(ctx, sc); err != nil {
		s.logger.Warn("failed to pause a scan without an active owner", "scan_id", sc.ID.String(), "error", err)
		return
	}
	s.notifyOwnerlessPause(ctx, sc, state)
}

func (s *Service) notifyOwnerlessPause(ctx context.Context, sc *scan.Scan, state string) {
	if s.ownerAdmins == nil || s.ownerNotifier == nil {
		return
	}
	ids, err := s.ownerAdmins.ActiveAdminIDs(ctx, sc.TenantID)
	if err != nil {
		s.logger.Warn("list admins for the scan owner notice", "error", err)
		return
	}
	why := "has no owner (the account that created it no longer exists)"
	if state == OwnerStateInactive {
		why = "belongs to someone who is no longer an active member"
	}
	body := fmt.Sprintf("Scheduled scan '%s' %s, so its scheduled runs are refused and it was paused. An administrator can take ownership on the scan's page and resume it.", sc.Name, why)
	scanID := sc.ID
	for _, id := range ids {
		uid := id
		if err := s.ownerNotifier.Notify(ctx, notificationdom.NotificationParams{
			TenantID: sc.TenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeScanFailed, Title: "Scan paused: no active owner", Body: body,
			Severity: "high", ResourceType: "scan", ResourceID: &scanID, URL: "/scans/" + sc.ID.String(),
		}); err != nil {
			s.logger.Warn("notify admin of an ownerless scan", "error", err)
		}
	}
}

// TakeOwnershipInput is an administrator taking ownership of a scan.
type TakeOwnershipInput struct {
	TenantID string
	ScanID   string
	ActorID  string
}

// TakeOwnership makes the acting administrator the owner of a scan whose
// owner is missing or no longer an active member. The scan's scheduled runs
// then act with the administrator's scope, so their act scope must cover
// the scan's direct targets, as on a clone. It does not resume the scan.
func (s *Service) TakeOwnership(ctx context.Context, in TakeOwnershipInput) (*scan.Scan, error) {
	actor, err := shared.IDFromString(in.ActorID)
	if err != nil || actor.IsZero() {
		return nil, ErrScanActorRequired
	}
	sc, err := s.GetScan(ctx, in.TenantID, in.ScanID)
	if err != nil {
		return nil, err
	}
	if err := refuseManaged(sc); err != nil {
		return nil, err
	}
	state := s.OwnerState(ctx, sc)
	if state == OwnerStateOK {
		// An active owner keeps the scan; a lookup error also refuses
		// (OwnerState reports ok then), so a take-over fails closed.
		return nil, ErrScanOwnerActive
	}
	if err := s.refuseOutOfActScope(ctx, sc.TenantID, &actor, sc.Targets); err != nil {
		return nil, err
	}
	w, ok := s.scanRepo.(ownerWriter)
	if !ok {
		return nil, errors.New("scan owner change is not supported by the repository")
	}
	prev := sc.CreatedBy
	changed, err := w.SetOwner(ctx, sc.TenantID, sc.ID, prev, actor)
	if err != nil {
		return nil, fmt.Errorf("set scan owner: %w", err)
	}
	if !changed {
		return nil, shared.NewDomainError("SCAN_OWNER_CHANGED",
			"The scan's owner changed meanwhile. Reload the scan and try again.", shared.ErrConflict)
	}
	sc.SetCreatedBy(actor)
	ev := NewSuccessEvent(audit.ActionScanConfigOwnerTaken, audit.ResourceTypeScanConfig, sc.ID.String()).
		WithResourceName(sc.Name).
		WithMessage(fmt.Sprintf("Took ownership of scan '%s' (previous owner %s)", sc.Name, state)).
		WithMetadata("previous_owner_state", state)
	if prev != nil {
		ev = ev.WithMetadata("previous_owner_id", prev.String())
	}
	s.logAudit(ctx, AuditContext{TenantID: in.TenantID, ActorID: in.ActorID}, ev)
	return sc, nil
}
