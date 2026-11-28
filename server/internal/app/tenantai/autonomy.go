package tenantai

// The organization's switch and limits on changes AI agents make without a
// person (docs/architecture/ai-autonomy.md).
//
// Security model: reading needs settings:read; writing needs an owner or
// administrator with settings:write (route). A loosening (resume, a limit
// raised or removed) is a person's decision on a fresh sign-in: it needs a
// recent re-authentication, is audited critical and every owner and
// administrator is told. Pausing or lowering a limit needs neither, so it is
// one click in an incident, and it applies at once to runs already in
// flight: the executors ask at the moment they would change a finding. An
// unreadable setting or count holds the change (fail closed).

import (
	"context"
	"fmt"
	"strings"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// ErrAutonomyUnavailable: the store cannot read or write the setting.
var ErrAutonomyUnavailable = fmt.Errorf("%w: AI autonomy store not wired", shared.ErrInternal)

// ErrAutonomyChanged: the setting changed after it was read for this
// change; nothing was written (409, reload and try again).
var ErrAutonomyChanged = fmt.Errorf("%w: the AI autonomy setting changed meanwhile", shared.ErrConflict)

// AutonomyView is the setting as an administrator sees it.
type AutonomyView struct {
	aidom.Autonomy
	// Loosened (answer of a change) lists why the change was a loosening.
	Loosened []string
}

// AutonomyInput is a change of the setting. A nil limit is unlimited.
type AutonomyInput struct {
	Paused  bool
	PerHour *int
	PerDay  *int
}

func (s *Service) autonomyStore() (aidom.AutonomyRepository, bool) {
	r, ok := s.repo.(aidom.AutonomyRepository)
	return r, ok
}

func (s *Service) autonomy(ctx context.Context, tenantID shared.ID) (aidom.Autonomy, error) {
	store, ok := s.autonomyStore()
	if !ok {
		return aidom.Autonomy{}, ErrAutonomyUnavailable
	}
	a, found, err := store.GetAutonomy(ctx, tenantID)
	if err != nil {
		return aidom.Autonomy{}, err
	}
	if !found {
		return aidom.DefaultAutonomy(), nil
	}
	return a, nil
}

// GetAutonomy returns the setting in force (the defaults when none was saved).
func (s *Service) GetAutonomy(ctx context.Context, tenantID string) (AutonomyView, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return AutonomyView{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	a, err := s.autonomy(ctx, tid)
	if err != nil {
		return AutonomyView{}, err
	}
	return AutonomyView{Autonomy: a}, nil
}

// SaveAutonomy changes the setting. A loosening needs a recent sign-in.
func (s *Service) SaveAutonomy(ctx context.Context, tenantID string, in AutonomyInput, actx auditapp.AuditContext) (AutonomyView, error) {
	store, ok := s.autonomyStore()
	if !ok {
		return AutonomyView{}, ErrAutonomyUnavailable
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return AutonomyView{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	stored, found, err := store.GetAutonomy(ctx, tid)
	if err != nil {
		return AutonomyView{}, err
	}
	before, expected := aidom.DefaultAutonomy(), (*aidom.Autonomy)(nil)
	if found {
		before, expected = stored, &stored
	}
	next := before
	next.Paused, next.PerHour, next.PerDay = in.Paused, in.PerHour, in.PerDay
	if err := next.Validate(); err != nil {
		return AutonomyView{}, err
	}
	loosened := aidom.AutonomyLoosened(before, next)
	if len(loosened) > 0 {
		// A loosening is a person's decision, never on a stale sign-in.
		if actx.ActorID == "" {
			return AutonomyView{}, ErrNoActor
		}
		if err := s.requireLooseningStepUp(ctx, actx.ActorID); err != nil {
			return AutonomyView{}, err
		}
	}
	now := s.stamp()
	switch {
	case next.Paused && !before.Paused:
		next.PausedAt, next.PausedBy = &now, actx.ActorID
	case !next.Paused:
		next.PausedAt, next.PausedBy = nil, ""
	}
	next.UpdatedAt, next.UpdatedBy = &now, actx.ActorID
	// Written only over the setting this decision was made on: a change
	// that landed meanwhile could make a loosening look like a tightening
	// (and skip the recent sign-in), so the caller reloads instead.
	saved, err := store.SaveAutonomy(ctx, tid, expected, next)
	if err != nil {
		return AutonomyView{}, err
	}
	if !saved {
		return AutonomyView{}, ErrAutonomyChanged
	}

	actx.TenantID = tenantID
	changes := auditapp.DiffChanges(autonomyAuditMap(before), autonomyAuditMap(next))
	if before.Paused != next.Paused {
		action, sev, msg := audit.ActionAIAutonomyPaused, audit.SeverityHigh, "Changes by AI agents without a person were paused"
		if !next.Paused {
			action, sev, msg = audit.ActionAIAutonomyResumed, audit.SeverityCritical, "Changes by AI agents without a person were resumed"
		}
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(action, audit.ResourceTypeTenant, tenantID).
			WithChanges(changes).WithMessage(msg).WithSeverity(sev))
	}
	if !sameLimit(before.PerHour, next.PerHour) || !sameLimit(before.PerDay, next.PerDay) {
		sev := audit.SeverityMedium
		if len(loosened) > 0 {
			sev = audit.SeverityCritical
		}
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionAIAutonomyUpdated, audit.ResourceTypeTenant, tenantID).
			WithChanges(changes).WithMetadata("loosened", loosened).
			WithMessage("Limits on changes by AI agents without a person changed").WithSeverity(sev))
	}
	if len(loosened) > 0 && s.notifier != nil {
		s.notifier.NotifyPolicyLoosenedWith(ctx, tenantID, actx, "settings.ai_autonomy_widened", "AI agents may change more without a person",
			strings.Join(autonomyLoosenedText(loosened, next), "; "), "/settings/ai?tab=autonomy",
			"changes", autonomyLoosenedMessage(loosened, next))
	}
	return AutonomyView{Autonomy: next, Loosened: loosened}, nil
}

func sameLimit(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func limitText(v *int) any {
	if v == nil {
		return "unlimited"
	}
	return *v
}

func autonomyAuditMap(a aidom.Autonomy) map[string]any {
	return map[string]any{"paused": a.Paused, "per_hour": limitText(a.PerHour), "per_day": limitText(a.PerDay)}
}

// autonomyLoosenedMessage is the language-neutral form of autonomyLoosenedText:
// one coded line per change; an unset limit is the nested "unlimited" message.
func autonomyLoosenedMessage(reasons []string, next aidom.Autonomy) *notificationdom.Message {
	items := make([]*notificationdom.Message, 0, len(reasons))
	for _, r := range reasons {
		switch r {
		case aidom.LoosenResumed:
			items = append(items, notificationdom.Msg("settings.ai_autonomy.resumed"))
		case aidom.LoosenLimitRaised, aidom.LoosenLimitRemoved:
			items = append(items, notificationdom.Msg("settings.ai_autonomy.limit_raised",
				"per_hour", limitParam(next.PerHour), "per_day", limitParam(next.PerDay)))
		}
	}
	return notificationdom.Lines("settings.ai_autonomy.changes", items)
}

func limitParam(v *int) any {
	if v == nil {
		return notificationdom.Msg("settings.ai_autonomy.unlimited")
	}
	return *v
}

func autonomyLoosenedText(reasons []string, next aidom.Autonomy) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		switch r {
		case aidom.LoosenResumed:
			out = append(out, "AI agents may again change findings without a person")
		case aidom.LoosenLimitRaised, aidom.LoosenLimitRemoved:
			out = append(out, fmt.Sprintf("up to %v changes an hour and %v a day without a person", limitText(next.PerHour), limitText(next.PerDay)))
		}
	}
	return out
}

// AllowAutomaticChange is asked by the AI executors right before an AI
// agent changes a finding without a person. It reports false with the
// reason (aidom.HoldAutonomyPaused, aidom.HoldLimitReached) when the
// organization paused such changes or reached a limit; otherwise the change
// is counted. Any error holds the change (fail closed).
func (s *Service) AllowAutomaticChange(ctx context.Context, tenantID shared.ID) (bool, string) {
	a, err := s.autonomy(ctx, tenantID)
	if err != nil {
		s.log.Warn("AI autonomy unreadable; the change is held", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return false, aidom.HoldAutonomyPaused
	}
	if a.Paused {
		return false, aidom.HoldAutonomyPaused
	}
	store, _ := s.autonomyStore()
	ok, err := store.ReserveAutoChange(ctx, tenantID, a.PerHour, a.PerDay, s.now())
	if err != nil {
		s.log.Warn("AI change count unavailable; the change is held", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return false, aidom.HoldLimitReached
	}
	if !ok {
		return false, aidom.HoldLimitReached
	}
	return true, ""
}
