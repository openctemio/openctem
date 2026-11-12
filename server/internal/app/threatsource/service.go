// Package threatsource is the platform setting that decides where KEV and
// EPSS come from.
//
// The signed vulnerability release carries both feeds (side manifest, see
// docs/architecture/feed-transfer.md). Two choices belong to the operator:
//
//   - Source: "direct" (default) keeps the platform's own scheduled fetch from
//     CISA and FIRST as the supplier, the release copy being applied only when
//     it is newer. "bundle" makes the release the supplier and the platform's
//     own fetch a fallback that runs only when the release's copy is stale (KEV
//     older than 6 hours, EPSS older than 48 hours). Switch to "bundle" once
//     the publisher has released hourly for seven days.
//   - DirectFetch: "auto" (default) lets the platform call CISA and FIRST when
//     the Source rule says so; "off" forbids it (strict-egress installs), so
//     the release is the only supplier and a stale copy shows as stale.
//
// A change applies on every replica within the console setting cache time.
// Design: research on threat intel feeds (batch 6), RFC-079.
package threatsource

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SettingKey is the platform_settings key.
const SettingKey = "threat_intel.source"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.threat_intel_source_changed"

// Values.
const (
	SourceDirect = "direct"
	SourceBundle = "bundle"
	FetchAuto    = "auto"
	FetchOff     = "off"
)

// Errors of the service.
var (
	ErrInvalid = fmt.Errorf("%w: source must be direct or bundle and direct_fetch must be auto or off", shared.ErrValidation)
	ErrNoActor = errors.New("a threat intel source change needs an administrator")
)

type stored struct {
	Source      string `json:"source"`
	DirectFetch string `json:"direct_fetch"`
}

// Settings is what an administrator sees.
type Settings struct {
	Source      string
	DirectFetch string
	// Stored: false while the defaults are in force.
	Stored    bool
	Version   int
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Policy is what the feed sync asks.
type Policy struct {
	// PreferBundle: the release is the supplier, the direct fetch a fallback.
	PreferBundle bool
	// DirectAllowed: the platform may call CISA and FIRST.
	DirectAllowed bool
}

// Service reads and changes the setting.
type Service struct {
	store    *consolesetting.Store[stored]
	recorder *consolesetting.Recorder
}

// NewService creates the service. repo may be nil (defaults always).
func NewService(repo platformsetting.Repository, recorder *consolesetting.Recorder) *Service {
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), recorder: recorder}
}

func normalize(st stored) stored {
	if st.Source != SourceBundle {
		st.Source = SourceDirect
	}
	if st.DirectFetch != FetchOff {
		st.DirectFetch = FetchAuto
	}
	return st
}

// Get returns the setting (defaults while nothing is stored).
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	st = normalize(st)
	return Settings{Source: st.Source, DirectFetch: st.DirectFetch, Stored: m.Stored, Version: m.Version,
		UpdatedAt: m.UpdatedAt, UpdatedBy: m.UpdatedBy}, nil
}

// Policy answers the feed sync.
func (s *Service) Policy(ctx context.Context) (Policy, error) {
	g, err := s.Get(ctx)
	if err != nil {
		return Policy{DirectAllowed: true}, err
	}
	return Policy{PreferBundle: g.Source == SourceBundle, DirectAllowed: g.DirectFetch != FetchOff}, nil
}

// Update stores the setting. The caller checked the actor's role and the
// step-up. expectedVersion is the version read (0: nothing stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, source, directFetch string, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if (source != SourceDirect && source != SourceBundle) || (directFetch != FetchAuto && directFetch != FetchOff) {
		return Settings{}, ErrInvalid
	}
	prev, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if _, err := s.store.Put(ctx, stored{Source: source, DirectFetch: directFetch}, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Threat intelligence source",
		Method: "PUT", Path: "/api/v1/admin/settings/threat-intel-source",
		Details: map[string]any{"previous_source": prev.Source, "previous_direct_fetch": prev.DirectFetch,
			"source": source, "direct_fetch": directFetch},
	}, ip, userAgent)
	return s.Get(ctx)
}
