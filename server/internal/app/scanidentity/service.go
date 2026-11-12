// Package scanidentity is the platform layer of the scan identification
// markers: an instance-wide User-Agent and up to four request headers every
// organization's scan jobs carry, each optionally enforced (no organization,
// program or sensor-local layer replaces it). The organization's own layer
// is merged over it at delivery (scanident.Merge).
//
// A change applies on every replica within the console setting cache time.
// Design: docs/architecture/scan-identification.md, RFC-079.
package scanidentity

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/scanident"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SettingKey is the platform_settings key.
const SettingKey = "scanning.identification"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.scan_identification_changed"

// ErrNoActor refuses a change without an administrator.
var ErrNoActor = errors.New("a scan identification change needs an administrator")

// Settings is what an administrator sees.
type Settings struct {
	Layer     scanident.PlatformLayer
	Stored    bool
	Version   int
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Service reads and changes the setting.
type Service struct {
	store    *consolesetting.Store[scanident.PlatformLayer]
	recorder *consolesetting.Recorder
}

// NewService creates the service. repo may be nil (nothing set, always).
func NewService(repo platformsetting.Repository, recorder *consolesetting.Recorder) *Service {
	return &Service{store: consolesetting.NewStore[scanident.PlatformLayer](repo, SettingKey), recorder: recorder}
}

// Get returns the setting (an empty layer while nothing is stored).
func (s *Service) Get(ctx context.Context) (Settings, error) {
	l, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	return Settings{Layer: l.Normalized(), Stored: m.Stored, Version: m.Version, UpdatedAt: m.UpdatedAt, UpdatedBy: m.UpdatedBy}, nil
}

// PlatformLayer answers the delivery of a job (command.PlatformIdentitySource).
// A stored value that no longer validates is not sent (and logged by the
// caller through the error): a job never carries a header the sensor refuses.
func (s *Service) PlatformLayer(ctx context.Context) (scanident.PlatformLayer, error) {
	g, err := s.Get(ctx)
	if err != nil {
		return scanident.PlatformLayer{}, err
	}
	if err := g.Layer.Validate(); err != nil {
		return scanident.PlatformLayer{}, err
	}
	return g.Layer, nil
}

// Update stores the layer. The caller checked the actor's permission and
// the step-up. expectedVersion is the version read (0: nothing stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, layer scanident.PlatformLayer, reason string,
	expectedVersion int, ip, userAgent string,
) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return Settings{}, err
	}
	layer = layer.Normalized()
	if err := layer.Validate(); err != nil {
		return Settings{}, err
	}
	prev, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if _, err := s.store.Put(ctx, layer, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	// The values are markers every target receives, never secrets (the
	// credential headers are refused), so the audit row carries them.
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Scan identification",
		Method: "PUT", Path: "/api/v1/admin/settings/scan-identification", Reason: reason, Notify: true,
		Details: map[string]any{"previous": prev.Layer, "current": layer},
	}, ip, userAgent)
	return s.Get(ctx)
}
