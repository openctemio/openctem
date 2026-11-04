// Package leakedsecretpolicy decides whether an imported leaked secret value
// (the password, token or key of a leaked credential) is kept.
//
// Two layers:
//
//	platform  credentials.leaked_secret_storage (platform_settings): the
//	          default for organizations that never chose. While nothing is
//	          stored: kept on a self-managed install (one owner, the
//	          behavior before the setting), not kept on a managed service
//	          (MANAGED_SERVICE).
//	tenant    tenants.settings.credentials.store_secret_values: the
//	          organization's own choice, which wins over the default.
//
// When a value is not kept, the import stores only the mask, the credential
// type and the organization's keyed fingerprint (credential.SecretProtector
// Seal with store=false). An unreadable setting keeps nothing (fail closed).
//
// A platform change is made by a super admin with a fresh step-up and a
// reason, audited critical and told to every administrator.
//
// Design: docs/architecture/credential-leaks.md.
package leakedsecretpolicy

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "credentials.leaked_secret_storage"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.leaked_secret_storage_changed"

// Sources of the platform default.
const (
	SourceConsole = "console"
	SourceDefault = "default"
)

// ErrNoActor refuses a change without an administrator.
var ErrNoActor = errors.New("a leaked secret storage change needs an administrator")

type stored struct {
	StoreByDefault bool `json:"store_by_default"`
}

// Settings is what an administrator sees.
type Settings struct {
	// StoreByDefault is the platform default in force.
	StoreByDefault bool
	Source         string
	// Default is the value while nothing is stored.
	Default   bool
	Version   int
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Service answers the platform default and changes it.
type Service struct {
	store    *consolesetting.Store[stored]
	recorder *consolesetting.Recorder
	def      bool
	log      *logger.Logger
}

// NewService creates the service. managed is MANAGED_SERVICE.
func NewService(repo platformsetting.Repository, recorder *consolesetting.Recorder, managed bool, log *logger.Logger) *Service {
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), recorder: recorder, def: !managed, log: log}
}

// Get returns the platform default and where it comes from.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{StoreByDefault: s.def, Source: SourceDefault, Default: s.def}
	if m.Stored {
		out.StoreByDefault, out.Source = st.StoreByDefault, SourceConsole
		out.Version, out.UpdatedAt, out.UpdatedBy = m.Version, m.UpdatedAt, m.UpdatedBy
	}
	return out, nil
}

// PlatformDefault is the default in force. An unreadable setting answers
// false (keep nothing).
func (s *Service) PlatformDefault(ctx context.Context) bool {
	v, err := s.Get(ctx)
	if err != nil {
		if s.log != nil {
			s.log.Warn(SettingKey+" unreadable; leaked secret values are not kept", "error", err)
		}
		return false
	}
	return v.StoreByDefault
}

// Update stores the platform default. The caller checked super_admin and the
// fresh step-up. expectedVersion is the version read (0: nothing stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, storeByDefault bool, reason string, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return Settings{}, err
	}
	prev, err := s.Get(ctx)
	if err != nil {
		// A broken stored value must still be replaceable.
		prev = Settings{Source: "unreadable"}
	}
	if _, err := s.store.Put(ctx, stored{StoreByDefault: storeByDefault}, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Leaked secret value storage default",
		Method: "PUT", Path: "/api/v1/admin/settings/leaked-secret-storage", Reason: reason, Critical: true, Notify: true,
		Details: map[string]any{"previous_store_by_default": prev.StoreByDefault, "previous_source": prev.Source,
			"store_by_default": storeByDefault},
	}, ip, userAgent)
	return s.Get(ctx)
}

// TenantReader reads an organization.
type TenantReader interface {
	GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error)
}

// Resolver answers, per organization, whether leaked secret values are kept.
type Resolver struct {
	platform *Service
	tenants  TenantReader
	log      *logger.Logger
}

// NewResolver creates the resolver.
func NewResolver(platform *Service, tenants TenantReader, log *logger.Logger) *Resolver {
	return &Resolver{platform: platform, tenants: tenants, log: log}
}

// StoresSecretValues reports whether tenantID keeps leaked secret values:
// its own choice, else the platform default. Any read failure (and a nil
// resolver) answers false.
func (r *Resolver) StoresSecretValues(ctx context.Context, tenantID shared.ID) bool {
	if r == nil || r.tenants == nil || tenantID.IsZero() {
		return false
	}
	t, err := r.tenants.GetByID(ctx, tenantID)
	if err != nil || t == nil {
		if r.log != nil {
			r.log.Warn("organization unreadable; leaked secret values are not kept", "tenant_id", tenantID.String(), "error", err)
		}
		return false
	}
	if v := t.TypedSettings().Credentials.StoreSecretValues; v != nil {
		return *v
	}
	if r.platform == nil {
		return false
	}
	return r.platform.PlatformDefault(ctx)
}
