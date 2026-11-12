// Package storagequota is the storage quota of organizations: how many MiB
// of uploaded files (evidence, attachments) one organization may hold.
//
//   - An organization's own limit (limit key storage_mb, set on its Limits
//     tab or by the control plane) wins.
//   - Otherwise the platform default applies: set in the console
//     (Settings > Limits) instead of STORAGE_TENANT_QUOTA_MB and a restart.
//     The environment value is the default until the console stores one.
//
// A default of 0 means no quota. A change applies to the next upload on
// every replica within the console setting cache time.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md and
// docs/architecture/limits.md.
package storagequota

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SettingKey is the platform_settings key.
const SettingKey = "storage.tenant_quota_mb"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.storage_quota_changed"

// EnvVar is the environment default.
const EnvVar = "STORAGE_TENANT_QUOTA_MB"

// MaxMB bounds the default (10 TiB).
const MaxMB = 10 << 20

// Sources of the default in force.
const (
	SourceConsole     = "console"
	SourceEnvironment = "environment"
)

// Errors of the service.
var (
	ErrInvalid = fmt.Errorf("%w: the storage quota must be between 0 (no quota) and %d MiB", shared.ErrValidation, MaxMB)
	ErrNoActor = errors.New("a storage quota change needs an administrator")
)

// LimitReader reads an organization's own limit (entitlement.Service).
type LimitReader interface {
	Limit(ctx context.Context, tenantID shared.ID, key limits.Key) (int, error)
}

type stored struct {
	TenantQuotaMB int64 `json:"tenant_quota_mb"`
}

// Settings is what an administrator sees.
type Settings struct {
	DefaultMB     int64
	Source        string
	EnvironmentMB int64
	Version       int
	UpdatedAt     time.Time
	UpdatedBy     *shared.ID
}

// Service answers quotas and changes the platform default.
type Service struct {
	store    *consolesetting.Store[stored]
	limits   LimitReader
	recorder *consolesetting.Recorder
	envMB    int64
}

// NewService creates the service. envMB is STORAGE_TENANT_QUOTA_MB (0 or
// less: no quota). lims may be nil (no per-organization limits).
func NewService(repo platformsetting.Repository, lims LimitReader, recorder *consolesetting.Recorder, envMB int64) *Service {
	if envMB < 0 {
		envMB = 0
	}
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), limits: lims, recorder: recorder, envMB: envMB}
}

// Get returns the platform default and where it comes from.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{DefaultMB: s.envMB, Source: SourceEnvironment, EnvironmentMB: s.envMB}
	if m.Stored {
		out.DefaultMB, out.Source = st.TenantQuotaMB, SourceConsole
		out.Version, out.UpdatedAt, out.UpdatedBy = m.Version, m.UpdatedAt, m.UpdatedBy
	}
	return out, nil
}

// QuotaBytes is the organization's quota in bytes, or unlimited. Any read
// error is returned (the caller refuses the upload).
func (s *Service) QuotaBytes(ctx context.Context, tenantID shared.ID) (int64, bool, error) {
	if s.limits != nil {
		v, err := s.limits.Limit(ctx, tenantID, limits.StorageMB)
		if err != nil {
			return 0, false, err
		}
		if v != limits.Unlimited {
			return int64(v) << 20, false, nil
		}
	}
	d, err := s.Get(ctx)
	if err != nil {
		return 0, false, err
	}
	if d.DefaultMB <= 0 {
		return 0, true, nil
	}
	return d.DefaultMB << 20, false, nil
}

// Update stores the platform default. The caller checked the actor's role
// and the step-up. expectedVersion is the version read (0: nothing stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, mb int64, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if mb < 0 || mb > MaxMB {
		return Settings{}, ErrInvalid
	}
	prev, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if _, err := s.store.Put(ctx, stored{TenantQuotaMB: mb}, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Default storage quota",
		Method: "PUT", Path: "/api/v1/admin/settings/storage-quota",
		Details: map[string]any{"previous_mb": prev.DefaultMB, "previous_source": prev.Source, "mb": mb},
	}, ip, userAgent)
	return s.Get(ctx)
}
