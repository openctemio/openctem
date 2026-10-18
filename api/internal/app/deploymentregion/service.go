// Package deploymentregion is the installation's data region: the region
// every new organization is stamped with at creation (tenants.region, never
// changed afterwards). It replaces DEPLOYMENT_REGION and a restart with a
// one-time console setting (Settings > Configuration):
//
//   - DEPLOYMENT_REGION, when set, pins the region; the console cannot
//     change it.
//   - Otherwise a super admin may set it once, and only while no
//     organization exists. Afterwards it is immutable: organizations already
//     carry the old value, and a region that silently differed between
//     organizations would break the data-residency statement they rely on.
//
// The write holds a lock on the organization table, so an organization
// created at the same moment cannot slip in without the region.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package deploymentregion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "deployment.region"

// ActionSet is the admin audit action.
const ActionSet = "platform.deployment_region_set"

// EnvVar pins the region.
const EnvVar = "DEPLOYMENT_REGION"

// Sources of the region in force.
const (
	SourceNone        = "none"
	SourceConsole     = "console"
	SourceEnvironment = "environment"
)

// Errors of the service.
var (
	ErrLockedByEnvironment = errors.New("the deployment region is set by the server configuration (DEPLOYMENT_REGION)")
	ErrAlreadySet          = errors.New("the deployment region is already set and cannot be changed")
	ErrOrganizationsExist  = errors.New("the deployment region can only be set before the first organization is created")
	ErrInvalid             = fmt.Errorf("%w: the region must be 1-32 lowercase letters, digits or hyphens (e.g. eu-central)", shared.ErrValidation)
	ErrNoActor             = errors.New("setting the region needs an administrator")
)

// regionRE is the shape of a region (the tenants.region check in the
// database and the DEPLOYMENT_REGION check are the same).
var regionRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// OnceStore stores the region in the same transaction that proves no
// organization exists (postgres.PlatformSettingRepository).
type OnceStore interface {
	platformsetting.Repository
	CreateIfAbsentBeforeFirstTenant(ctx context.Context, key string, s platformsetting.State) (created, tenantsExist bool, err error)
}

// OrganizationCounter says whether any organization exists (for the page's
// "can be set" state).
type OrganizationCounter interface {
	AnyOrganization(ctx context.Context) (bool, error)
}

type stored struct {
	Region string `json:"region"`
}

// Settings is what an administrator sees.
type Settings struct {
	Region              string
	Source              string
	LockedByEnvironment bool
	// Settable: nothing pins or stores a region and no organization exists.
	Settable  bool
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Service reads and sets the region.
type Service struct {
	store    *consolesetting.Store[stored]
	once     OnceStore
	orgs     OrganizationCounter
	recorder *consolesetting.Recorder
	env      string
	now      func() time.Time
	log      *logger.Logger
}

// NewService creates the service. env is DEPLOYMENT_REGION (validated at
// start).
func NewService(repo OnceStore, orgs OrganizationCounter, recorder *consolesetting.Recorder, env string, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), once: repo, orgs: orgs,
		recorder: recorder, env: strings.TrimSpace(env), now: time.Now, log: log.With("service", "deployment_region")}
}

// Region is the region new organizations get; "" when none is set. An
// unreadable setting answers "" and is logged: the organization is then
// created without a region, as on an installation that never set one.
func (s *Service) Region(ctx context.Context) string {
	if s.env != "" {
		return s.env
	}
	st, _, err := s.store.Get(ctx)
	if err != nil {
		s.log.Warn("deployment region unreadable", "error", err)
		return ""
	}
	return st.Region
}

// Get returns the region and whether it can still be set.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	if s.env != "" {
		return Settings{Region: s.env, Source: SourceEnvironment, LockedByEnvironment: true}, nil
	}
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if st.Region != "" {
		return Settings{Region: st.Region, Source: SourceConsole, UpdatedAt: m.UpdatedAt, UpdatedBy: m.UpdatedBy}, nil
	}
	out := Settings{Source: SourceNone}
	if s.orgs != nil {
		exist, err := s.orgs.AnyOrganization(ctx)
		if err != nil {
			return Settings{}, err
		}
		out.Settable = !exist
	}
	return out, nil
}

// Set stores the region once. The caller checked the actor's role and a
// fresh confirmation.
func (s *Service) Set(ctx context.Context, actor *admin.AdminUser, region, reason, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if s.env != "" {
		return Settings{}, ErrLockedByEnvironment
	}
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return Settings{}, err
	}
	region = strings.TrimSpace(region)
	if !regionRE.MatchString(region) {
		return Settings{}, ErrInvalid
	}
	raw, err := json.Marshal(stored{Region: region})
	if err != nil {
		return Settings{}, err
	}
	by := actor.ID()
	created, tenantsExist, err := s.once.CreateIfAbsentBeforeFirstTenant(ctx, SettingKey, platformsetting.State{
		Value: raw, Version: 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: s.now().UTC(),
	})
	switch {
	case err != nil:
		return Settings{}, err
	case tenantsExist:
		return Settings{}, ErrOrganizationsExist
	case !created:
		return Settings{}, ErrAlreadySet
	}
	if _, _, err := s.store.Fresh(ctx); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionSet, Key: SettingKey, Title: "Deployment region",
		Method: "PUT", Path: "/api/v1/admin/settings/region", Reason: reason,
		Details: map[string]any{"region": region}, Critical: true, Notify: true,
	}, ip, userAgent)
	return s.Get(ctx)
}
