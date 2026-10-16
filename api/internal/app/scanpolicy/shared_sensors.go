package scanpolicy

// Shared sensor access (docs/rfcs/RFC-100-shared-sensors.md §5, §11). An
// organization may send scans to shared sensors only when every layer
// allows:
//
//  1. the instance switch shared_sensors.enabled (console, super admin,
//     fresh authenticator code, reason; off by default everywhere);
//  2. the instance administrator's decision for the organization (allow or
//     deny, tenants.shared_sensors_access), or, without one, the instance
//     default shared_sensors.new_orgs, which the administrator must choose
//     (allow or deny) in the same action that turns the switch on; unset,
//     an organization without a decision is refused; a deny wins;
//  3. the organization owner's choice (opt out; default: use them).
//
// Above all three sits the rollout gate: until the shared claim path and
// per-job isolation have landed, no deployment may use shared sensors and
// the console refuses to turn the switch on (sharedSensorsReady).
//
// Threat model: a shared sensor sends the operator's packets on an
// organization's behalf and runs its jobs on shared infrastructure, so access
// fails closed: an unreadable setting, decision or opt-out refuses. Only a
// super admin with a fresh code changes the instance setting or an
// organization's decision (critical admin audit row, the other administrators
// emailed); only the organization's owner changes the opt-out (tenant audit
// row). Each refusal names its real reason.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// sharedSensorsReady is the rollout gate of RFC-100 §11: false until the
// shared claim path (S5) and per-job isolation on shared sensors (S11) have
// landed. While false, SharedSensorsAllowed refuses every organization
// whatever the settings say, and the instance switch cannot be turned on.
// Flipping it is a reviewed code change, never a setting.
const sharedSensorsReady = false

// SharedSensorsSettingKey is the platform_settings key of the instance
// setting.
const SharedSensorsSettingKey = "shared_sensors"

// Admin audit actions of shared sensor access.
const (
	ActionSharedSensorsChanged       = "platform.shared_sensors_changed"
	ActionSharedSensorsAccessChanged = "organization.shared_sensors_access_changed"
)

// Refusal reasons: what the organization is told, never an edition.
const (
	ReasonSharedSensorsNotReady    = "shared sensors are not available yet"
	ReasonSharedSensorsOff         = "shared sensors are turned off on this instance"
	ReasonSharedSensorsNotEnabled  = "the instance administrator has not enabled shared sensors for your organization"
	ReasonSharedSensorsOptedOut    = "your organization opted out of shared sensors"
	ReasonSharedSensorsUnavailable = "shared sensors are unavailable right now"
)

// Organization decisions of the instance administrator.
const (
	SharedSensorsAllow = "allow"
	SharedSensorsDeny  = "deny"
)

// ErrSharedSensorsNotReady refuses turning the instance switch on before the
// rollout gate opens.
var ErrSharedSensorsNotReady = fmt.Errorf("%w: %s", shared.ErrConflict, ReasonSharedSensorsNotReady)

// SharedSensorsSetting is the instance setting.
type SharedSensorsSetting struct {
	// Enabled is the instance switch (default false).
	Enabled bool `json:"enabled"`
	// NewOrgs is whether an organization without an administrator's
	// decision may use shared sensors. nil (unset, the default) refuses
	// such an organization: turning the switch on alone never grants
	// shared sensors to every organization, the administrator chooses
	// allow or deny in the same action (ErrNewOrgsChoiceRequired).
	NewOrgs *bool `json:"new_orgs"`
}

// DefaultSharedSensorsSetting is the setting before anything is stored: off,
// no default for organizations.
func DefaultSharedSensorsSetting() SharedSensorsSetting {
	return SharedSensorsSetting{Enabled: false}
}

// ErrNewOrgsChoiceRequired refuses turning the switch on without choosing,
// in the same action, whether organizations without a decision may use
// shared sensors.
var ErrNewOrgsChoiceRequired = fmt.Errorf("%w: turning shared sensors on needs an explicit choice for organizations without a decision (new_orgs true or false)", shared.ErrValidation)

// SharedSensorsStore persists the instance setting (platform_settings) and
// the per-organization decision (tenants.shared_sensors_access).
type SharedSensorsStore interface {
	// GetSharedSensors returns ErrNotFound when nothing is stored.
	GetSharedSensors(ctx context.Context) (SharedSensorsSetting, int, error)
	SetSharedSensors(ctx context.Context, v SharedSensorsSetting, expectedVersion int, by string, at time.Time) (int, error)
	// GetSharedSensorsAccess returns "", allow or deny; shared.ErrNotFound
	// for an unknown organization.
	GetSharedSensorsAccess(ctx context.Context, tenantID shared.ID) (string, error)
	SetSharedSensorsAccess(ctx context.Context, tenantID shared.ID, decision string) error
}

// SharedSensorsOptOut reads the organization owner's choice
// (*tenant.TenantService).
type SharedSensorsOptOut interface {
	SharedSensorsOptedOut(ctx context.Context, tenantID shared.ID) (bool, error)
}

// SetSharedSensorsOptOut wires the organization's opt-out. Without it every
// organization is refused (fail closed).
func (s *Service) SetSharedSensorsOptOut(o SharedSensorsOptOut) { s.optOut = o }

func (s *Service) sharedStore() (SharedSensorsStore, error) {
	st, ok := s.repo.(SharedSensorsStore)
	if !ok || st == nil {
		return nil, errors.New("the shared sensor setting store is not wired")
	}
	return st, nil
}

// SharedSensorsReady reports whether the rollout gate is open.
func SharedSensorsReady() bool { return sharedSensorsReady }

// SharedSensorsSetting returns the instance setting and its version (0:
// nothing stored, the defaults apply).
func (s *Service) SharedSensorsSetting(ctx context.Context) (SharedSensorsSetting, int, error) {
	st, err := s.sharedStore()
	if err != nil {
		return SharedSensorsSetting{}, 0, err
	}
	v, ver, err := st.GetSharedSensors(ctx)
	if errors.Is(err, ErrNotFound) {
		return DefaultSharedSensorsSetting(), 0, nil
	}
	if err != nil {
		return SharedSensorsSetting{}, 0, err
	}
	return v, ver, nil
}

// SharedSensorsAccess returns the administrator's decision for the
// organization ("" when none).
func (s *Service) SharedSensorsAccess(ctx context.Context, tenantID shared.ID) (string, error) {
	st, err := s.sharedStore()
	if err != nil {
		return "", err
	}
	return st.GetSharedSensorsAccess(ctx, tenantID)
}

// SharedSensorsAllowed says whether the organization may send scans to
// shared sensors, and if not, why. It is the one rule the scan trigger, the
// pipeline and the organization's platform scanning view use.
func (s *Service) SharedSensorsAllowed(ctx context.Context, tenantID shared.ID) (bool, string) {
	if !sharedSensorsReady {
		return false, ReasonSharedSensorsNotReady
	}
	return s.sharedSensorsPolicy(ctx, tenantID)
}

// sharedSensorsPolicy is the three layers of RFC-100 §5, below the rollout
// gate. Any read error refuses.
func (s *Service) sharedSensorsPolicy(ctx context.Context, tenantID shared.ID) (bool, string) {
	setting, _, err := s.SharedSensorsSetting(ctx)
	if err != nil {
		s.log.Warn("shared sensor setting unreadable; refusing", "error", err)
		return false, ReasonSharedSensorsUnavailable
	}
	if !setting.Enabled {
		return false, ReasonSharedSensorsOff
	}
	decision, err := s.SharedSensorsAccess(ctx, tenantID)
	if err != nil {
		s.log.Warn("shared sensor decision unreadable; refusing", "tenant_id", tenantID.String(), "error", err)
		return false, ReasonSharedSensorsUnavailable
	}
	switch decision {
	case SharedSensorsDeny:
		return false, ReasonSharedSensorsNotEnabled
	case SharedSensorsAllow:
	case "":
		if setting.NewOrgs == nil || !*setting.NewOrgs {
			return false, ReasonSharedSensorsNotEnabled
		}
	default:
		return false, ReasonSharedSensorsUnavailable
	}
	if s.optOut == nil {
		return false, ReasonSharedSensorsUnavailable
	}
	out, err := s.optOut.SharedSensorsOptedOut(ctx, tenantID)
	if err != nil {
		s.log.Warn("shared sensor opt-out unreadable; refusing", "tenant_id", tenantID.String(), "error", err)
		return false, ReasonSharedSensorsUnavailable
	}
	if out {
		return false, ReasonSharedSensorsOptedOut
	}
	return true, ""
}

// UpdateSharedSensors changes the instance setting. The caller checked
// super_admin and a fresh authenticator code. Turning the switch on is
// refused while the rollout gate is closed.
func (s *Service) UpdateSharedSensors(ctx context.Context, next SharedSensorsSetting, expectedVersion int, c Change) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if next.Enabled && next.NewOrgs == nil {
		return 0, ErrNewOrgsChoiceRequired
	}
	if next.Enabled && !sharedSensorsReady {
		return 0, ErrSharedSensorsNotReady
	}
	st, err := s.sharedStore()
	if err != nil {
		return 0, err
	}
	prev, _, err := s.SharedSensorsSetting(ctx)
	if err != nil {
		return 0, err
	}
	v, err := st.SetSharedSensors(ctx, next, expectedVersion, c.Actor.ID().String(), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	from, to := sharedSettingText(prev), sharedSettingText(next)
	s.recordKey(ctx, c, ActionSharedSensorsChanged, SharedSensorsSettingKey, from, to)
	s.mailOthers(ctx, c, "[Scans] Shared sensor setting changed",
		fmt.Sprintf("%s changed the shared sensor setting from %s to %s. Reason: %s",
			c.Actor.Email(), from, to, strings.TrimSpace(c.Reason)))
	return v, nil
}

// UpdateSharedSensorsAccess sets the administrator's decision for the
// organization: allow, deny or "" (follow the instance default). The caller
// checked super_admin, a fresh authenticator code and that the organization
// exists.
func (s *Service) UpdateSharedSensorsAccess(ctx context.Context, tenantID shared.ID, decision string, c Change) error {
	if err := c.check(); err != nil {
		return err
	}
	if decision != "" && decision != SharedSensorsAllow && decision != SharedSensorsDeny {
		return fmt.Errorf("%w: decision must be allow, deny or empty", shared.ErrValidation)
	}
	st, err := s.sharedStore()
	if err != nil {
		return err
	}
	prev, err := st.GetSharedSensorsAccess(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := st.SetSharedSensorsAccess(ctx, tenantID, decision); err != nil {
		return err
	}
	s.recordFor(ctx, c, ActionSharedSensorsAccessChanged, &tenantID, SharedSensorsSettingKey, decisionText(prev), decisionText(decision))
	s.mailOthers(ctx, c, "[Scans] Shared sensor access changed for an organization",
		fmt.Sprintf("%s changed the shared sensor access of organization %s from %s to %s. Reason: %s",
			c.Actor.Email(), tenantID, decisionText(prev), decisionText(decision), strings.TrimSpace(c.Reason)))
	return nil
}

func sharedSettingText(v SharedSensorsSetting) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func decisionText(d string) string {
	if d == "" {
		return "instance default"
	}
	return d
}
