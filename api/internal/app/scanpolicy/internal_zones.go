package scanpolicy

// "Shared sensors may scan internal zones" (docs/rfcs/RFC-100-shared-sensors.md
// §6, §6.1): an instance setting. When on, the instance administrator may
// assign instance scan zones (ranges plus the shared sensors that serve them)
// to organizations, and an organization's internal target may go to a shared
// sensor inside a zone assigned to it. When off, shared sensors scan public
// targets only.
//
// Default off on every deployment, MANAGED_SERVICE or not, and not enforced
// yet: nothing routes an internal target to a shared sensor until instance
// scan zones and their signed zone ranges are wired (InternalZonesEnforced).
// Whether a self-hosted install gets an "on" default is decided when that
// lands. A value stored in the console always wins.
//
// Threat model: turning it on lets shared sensors, which serve every allowed
// organization, reach private ranges, so the change is the same as the proof
// requirement's: super_admin with a fresh console authenticator code (route
// step-up) and a reason, a critical admin audit row, and the other
// administrators emailed. No tenant route writes it. It never assigns a zone
// by itself: the administrator still assigns each zone to organizations. An
// unreadable stored value counts as off (fail closed).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// InternalZonesSettingKey is the platform_settings key of the setting.
const InternalZonesSettingKey = "shared_sensor_internal_zones"

// ActionInternalZonesChanged is the admin audit action of a change.
const ActionInternalZonesChanged = "platform.shared_sensor_internal_zones_changed"

// InternalZonesStore persists the setting (platform_settings). Get returns
// ErrNotFound when nothing is stored.
type InternalZonesStore interface {
	GetInternalZones(ctx context.Context) (bool, int, error)
	SetInternalZones(ctx context.Context, allowed bool, expectedVersion int, by string, at time.Time) (int, error)
}

func (s *Service) zonesStore() (InternalZonesStore, error) {
	st, ok := s.repo.(InternalZonesStore)
	if !ok || st == nil {
		return nil, errors.New("the internal zones setting store is not wired")
	}
	return st, nil
}

// internalZonesEnforced is false until instance scan zones route internal
// targets to shared sensors with the zone ranges in the signed job: until
// then the setting is stored but nothing reads it, and the console says so.
const internalZonesEnforced = false

// InternalZonesEnforced reports whether the setting has an effect yet.
func InternalZonesEnforced() bool { return internalZonesEnforced }

// InternalZonesDefault is the setting while nothing is stored: off on every
// deployment.
func (s *Service) InternalZonesDefault() bool { return false }

// InternalZonesSetting returns the setting and its version (0: nothing
// stored, InternalZonesDefault applies).
func (s *Service) InternalZonesSetting(ctx context.Context) (bool, int, error) {
	s.mu.Lock()
	if s.zonesCached != nil && time.Since(s.zonesAt) < cacheTTL {
		v, ver := *s.zonesCached, s.zonesVer
		s.mu.Unlock()
		return v, ver, nil
	}
	s.mu.Unlock()
	st, err := s.zonesStore()
	if err != nil {
		return false, 0, err
	}
	v, ver, err := st.GetInternalZones(ctx)
	if errors.Is(err, ErrNotFound) {
		v, ver, err = s.InternalZonesDefault(), 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	s.mu.Lock()
	s.zonesCached, s.zonesVer, s.zonesAt = &v, ver, time.Now()
	s.mu.Unlock()
	return v, ver, nil
}

// SharedSensorsInternalZonesAllowed reports whether shared sensors may scan
// internal zones now. An unreadable setting answers false.
func (s *Service) SharedSensorsInternalZonesAllowed(ctx context.Context) bool {
	v, _, err := s.InternalZonesSetting(ctx)
	if err != nil {
		s.log.Warn("shared sensor internal zones setting unreadable; refusing internal zones", "error", err)
		return false
	}
	return v
}

// UpdateInternalZones changes the setting. The caller checked super_admin
// and a fresh authenticator code.
func (s *Service) UpdateInternalZones(ctx context.Context, allowed bool, expectedVersion int, c Change) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	st, err := s.zonesStore()
	if err != nil {
		return 0, err
	}
	prev, _, err := s.InternalZonesSetting(ctx)
	if err != nil {
		return 0, err
	}
	v, err := st.SetInternalZones(ctx, allowed, expectedVersion, c.Actor.ID().String(), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.zonesCached, s.zonesVer, s.zonesAt = &allowed, v, time.Now()
	s.mu.Unlock()
	s.recordKey(ctx, c, ActionInternalZonesChanged, InternalZonesSettingKey, onOff(prev), onOff(allowed))
	s.mailOthers(ctx, c, "[Scans] Internal zones on shared sensors changed",
		fmt.Sprintf("%s changed \"Shared sensors may scan internal zones\" from %s to %s. Reason: %s",
			c.Actor.Email(), onOff(prev), onOff(allowed), strings.TrimSpace(c.Reason)))
	return v, nil
}
