package versioncheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The daily online check is switched on and off in the platform console
// (System > Software updates) instead of by editing VERSION_CHECK_ENABLED and
// restarting. The environment value stays a ceiling: an operator who set
// VERSION_CHECK_ENABLED=false (an air-gapped or no-egress installation) has
// forbidden the outbound request, and no console session can turn it back
// on. With the environment on (the default), the console value decides, and
// nothing stored means on.

// SettingKey is the platform_settings key of the console switch.
const SettingKey = "version_check"

// ErrLockedByEnvironment: VERSION_CHECK_ENABLED=false forbids turning the
// online check on from the console.
var ErrLockedByEnvironment = errors.New("version check: turned off by VERSION_CHECK_ENABLED")

// Setting is the stored console switch.
type Setting struct {
	Enabled bool `json:"enabled"`
}

// SetSettings wires the console switch's store (nil: the environment alone).
func (s *Service) SetSettings(repo platformsetting.Repository) { s.settings = repo }

// LockedByEnvironment reports whether VERSION_CHECK_ENABLED=false pins the
// online check off.
func (s *Service) LockedByEnvironment() bool { return !s.cfg.Enabled }

// enabled is the effective switch: the environment ceiling, then the console
// value. A store that cannot be read skips this run (no request is made on
// an unknown answer); the next run asks again.
func (s *Service) enabled(ctx context.Context) bool {
	if !s.cfg.Enabled {
		return false
	}
	st, ok, err := s.stored(ctx)
	if err != nil {
		s.logger.Warn("version check: read the console switch", "error", err)
		return false
	}
	return !ok || st.Enabled
}

func (s *Service) stored(ctx context.Context) (Setting, bool, error) {
	if s.settings == nil {
		return Setting{}, false, nil
	}
	row, err := s.settings.Get(ctx, SettingKey)
	if errors.Is(err, platformsetting.ErrNotFound) {
		return Setting{}, false, nil
	}
	if err != nil {
		return Setting{}, false, err
	}
	var st Setting
	if err := json.Unmarshal(row.Value, &st); err != nil {
		return Setting{}, false, fmt.Errorf("decode %s: %w", SettingKey, err)
	}
	return st, true, nil
}

// UpdateEnabled stores the console switch for the administrator by. Turning it
// on is refused while the environment forbids it.
func (s *Service) UpdateEnabled(ctx context.Context, enabled bool, by shared.ID) error {
	if s.settings == nil {
		return errors.New("version check: console setting store is not configured")
	}
	if enabled && !s.cfg.Enabled {
		return ErrLockedByEnvironment
	}
	value, err := json.Marshal(Setting{Enabled: enabled})
	if err != nil {
		return err
	}
	now := s.cfg.Now()
	created, err := s.settings.CreateIfAbsent(ctx, SettingKey, platformsetting.State{
		Value: value, Version: 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: now,
	})
	if err != nil || created {
		return err
	}
	// One retry on a concurrent change: the switch has no other field to
	// merge, so the last writer wins.
	for attempt := 0; attempt < 2; attempt++ {
		row, err := s.settings.Get(ctx, SettingKey)
		if err != nil {
			return err
		}
		if _, err = s.settings.Update(ctx, SettingKey, value, row.Version, by, now); !errors.Is(err, platformsetting.ErrVersionConflict) {
			return err
		}
	}
	return platformsetting.ErrVersionConflict
}
