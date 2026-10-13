package sensorgrant

// Leaving the legacy grant (docs/architecture/sensor-pairing.md, "Leaving
// the legacy grant"): suggest, per sensor, the narrowest profile that
// admits every job of the last SuggestWindow, and apply it in one click.
//
// Threat model: the apply path must never widen a grant (the suggestion is
// re-computed on the server at apply time, the client only names the
// profile it saw, and Widened is checked again before the write); it needs
// a grant permission and a recent sign-in or step-up (a stolen idle session
// cannot reshape the fleet); a sensor of another tenant reads as not found;
// the change is audited with its diff and the usage it was based on.

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SuggestWindow is how far back the suggestion looks.
const SuggestWindow = 30 * 24 * time.Hour

// MaxSuggestJobs bounds the distinct jobs read; a busier window gets no
// suggestion (coverage cannot be proved).
const MaxSuggestJobs = 5000

// Errors of the suggestion.
var (
	// ErrSuggestionChanged: the profile the caller saw is no longer the
	// suggestion (new activity, a grant change).
	ErrSuggestionChanged = fmt.Errorf("%w: the suggested grant changed since it was read; reload and retry", shared.ErrConflict)
	// ErrStepUpUnavailable: step-up is not wired (fail closed).
	ErrStepUpUnavailable = errors.New("step-up re-authentication is not available")
	// ErrSuggestionUnavailable: usage cannot be read (not wired).
	ErrSuggestionUnavailable = fmt.Errorf("%w: grant suggestions are not available", shared.ErrNotFound)
)

// UsageReader reads what a sensor did in a window.
type UsageReader interface {
	GrantUsage(ctx context.Context, tenantID, sensorID shared.ID, since time.Time, maxJobs int) (sensordom.GrantUsage, error)
}

// ManifestReader reads a sensor's current manifest (its tool contracts set
// the tier each job is checked at, as at claim).
type ManifestReader interface {
	CurrentManifest(ctx context.Context, tenantID *shared.ID, sensorID shared.ID) (*sensordom.ManifestVersion, error)
}

// SetUsage wires the usage and manifest readers the suggestion needs, and
// SetStepUpGate the re-authentication applying one needs.
func (s *Service) SetUsage(u UsageReader, m ManifestReader) { s.usage, s.manifests = u, m }
func (s *Service) SetStepUpGate(g shared.RecentAuthGate)    { s.stepUp = g }

// SuggestionView is the suggestion as the console shows it.
type SuggestionView struct {
	SensorID string `json:"sensor_id"`
	// Available: Profile can be applied now.
	Available bool `json:"available"`
	// Profile is the suggested profile ("" when there is none).
	Profile string `json:"profile"`
	// Reason says why there is no suggestion, or that the sensor was idle.
	Reason string `json:"reason,omitempty" enums:"usage_incomplete,no_profile_fits,no_activity,already_narrowest"`
	// CurrentProfile and CurrentVersion are the grant the suggestion was
	// computed against; apply sends the version back.
	CurrentProfile string `json:"current_profile"`
	CurrentVersion int    `json:"current_version"`
	// Changed lists the dimensions that would narrow.
	Changed []string `json:"changed"`
	// Grant is the grant applying would store.
	Grant      *View            `json:"grant,omitempty"`
	WindowDays int              `json:"window_days"`
	Usage      UsageSummaryView `json:"usage"`
} // @name SensorGrantSuggestion

// UsageSummaryView is what the sensor did in the window.
type UsageSummaryView struct {
	JobCount       int      `json:"job_count"`
	JobTypes       []string `json:"job_types"`
	Tools          []string `json:"tools"`
	MaxTier        int      `json:"max_tier"`
	PrivateTargets bool     `json:"private_targets"`
	PublicTargets  bool     `json:"public_targets"`
	ZoneCount      int      `json:"zone_count"`
	PushIngest     bool     `json:"push_ingest"`
	Complete       bool     `json:"complete"`
} // @name SensorGrantUsageSummary

// Suggest returns the grant suggestion of a sensor of the tenant.
func (s *Service) Suggest(ctx context.Context, tenantID, sensorID shared.ID) (*SuggestionView, error) {
	cur, sug, err := s.suggest(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}
	return suggestionView(*cur, sug), nil
}

func (s *Service) suggest(ctx context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, sensordom.GrantSuggestion, error) {
	if s.usage == nil || s.sensors == nil {
		return nil, sensordom.GrantSuggestion{}, ErrSuggestionUnavailable
	}
	cur, err := s.Get(ctx, tenantID, sensorID)
	if err != nil {
		return nil, sensordom.GrantSuggestion{}, err
	}
	sen, err := s.sensors.GetByTenantAndID(ctx, tenantID, sensorID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, sensordom.GrantSuggestion{}, ErrNotFound
		}
		return nil, sensordom.GrantSuggestion{}, err
	}
	u, err := s.usage.GrantUsage(ctx, tenantID, sensorID, time.Now().Add(-SuggestWindow), MaxSuggestJobs)
	if err != nil {
		return nil, sensordom.GrantSuggestion{}, err
	}
	var manifest *sensordom.Manifest
	if s.manifests != nil {
		if v, err := s.manifests.CurrentManifest(ctx, &tenantID, sensorID); err == nil && v != nil {
			manifest = &v.Manifest
		}
	}
	contracts := func(tool string) *sensordom.ToolContract {
		if manifest == nil || tool == "" {
			return nil
		}
		return manifest.ToolContract(tool)
	}
	return cur, sensordom.SuggestGrant(*cur, sen.Type, u, contracts), nil
}

// ApplySuggestion stores the suggested grant of a sensor of the actor's
// tenant. profile and version are what the caller saw: when the suggestion
// or the grant changed since, nothing is written (409). It needs a grant
// permission and a recent sign-in or step-up, never widens (checked again
// here) and is audited with the usage it was based on.
func (s *Service) ApplySuggestion(ctx context.Context, actor Actor, sensorID shared.ID, version int, profile string) (*sensordom.Grant, error) {
	if !actor.CanNarrow && !actor.CanWiden {
		return nil, ErrNarrowForbidden
	}
	if s.stepUp == nil {
		return nil, ErrStepUpUnavailable
	}
	if err := s.stepUp.RequireRecentAuth(ctx, actor.UserID.String()); err != nil {
		return nil, err
	}
	cur, sug, err := s.suggest(ctx, actor.TenantID, sensorID)
	if err != nil {
		return nil, err
	}
	if version != cur.Version {
		return nil, ErrVersionConflict
	}
	if sug.Grant == nil || sug.Profile != profile {
		return nil, ErrSuggestionChanged
	}
	next := *sug.Grant
	if widened := sensordom.Widened(*cur, next); len(widened) > 0 {
		// Unreachable by construction; refuse rather than trust it.
		s.logAudit(ctx, actor, auditapp.NewFailureEvent(audit.ActionSensorGrantChanged, audit.ResourceTypeSensor, sensorID.String(), ErrWidenForbidden).
			WithMessage("Applying a suggested sensor grant refused: it would widen the grant").
			WithSeverity(audit.SeverityHigh).WithMetadata("widened", widened))
		return nil, ErrWidenForbidden
	}
	uid := actor.UserID
	next.UpdatedBy = &uid
	next.Version = cur.Version
	ok, err := s.repo.Update(ctx, &next)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrVersionConflict
	}
	next.Version = cur.Version + 1
	s.onChangedWith(ctx, actor, *cur, next, sensordom.Changed(*cur, next), nil, map[string]any{
		"source": "suggestion", "window_days": int(SuggestWindow / (24 * time.Hour)),
		"usage": usageView(sug.Usage), "suggestion_reason": sug.Reason,
	})
	return &next, nil
}

func suggestionView(cur sensordom.Grant, sug sensordom.GrantSuggestion) *SuggestionView {
	v := &SuggestionView{
		SensorID: cur.SensorID.String(), Profile: sug.Profile, Reason: sug.Reason, Available: sug.Grant != nil,
		CurrentProfile: cur.Profile, CurrentVersion: cur.Version, Changed: sug.Changed,
		WindowDays: int(SuggestWindow / (24 * time.Hour)), Usage: usageView(sug.Usage),
	}
	if v.Changed == nil {
		v.Changed = []string{}
	}
	if sug.Grant != nil {
		g := GrantView(*sug.Grant)
		v.Grant = &g
	}
	return v
}

func usageView(u sensordom.UsageSummary) UsageSummaryView {
	return UsageSummaryView{JobCount: u.JobCount, JobTypes: u.JobTypes, Tools: u.Tools, MaxTier: u.MaxTier,
		PrivateTargets: u.PrivateTargets, PublicTargets: u.PublicTargets, ZoneCount: u.ZoneCount,
		PushIngest: u.PushIngest, Complete: u.Complete}
}
