package finding

// Telling the assignee and the watchers about what happened to a finding
// (RFC-120, docs/architecture/participants-and-watchers.md). One path for
// comments, status changes (a fix claim is one), assignments: the shared
// recipient decision lives in participation.Service.Recipients, which
// re-checks membership, data scope and pentest visibility at send time.
// Without it wired the assignee alone is told, as before.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/participation"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	participationdom "github.com/openctemio/openctem/api/pkg/domain/participation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FindingParticipants is the watcher side of finding events
// (*participation.Service).
type FindingParticipants interface {
	AutoWatch(ctx context.Context, tenantID shared.ID, item participationdom.Item, userID shared.ID, reason participationdom.Reason)
	Recipients(ctx context.Context, tenantID shared.ID, ev participation.Event) ([]participation.Recipient, error)
}

// SetParticipants wires the watchers: events reach them, and people who take
// part in a finding are added as watchers.
func (s *VulnerabilityService) SetParticipants(p FindingParticipants) { s.participants = p }

// findingEvent is one thing that happened to a finding.
type findingEvent struct {
	// actorID is the person who did it; empty or not an id for a scanner, the
	// system, an integration or an AI: they are not watched and watchers are
	// not told about what they did.
	actorID string
	typ     string
	title   string
	// watcherTitle replaces title for a watcher when title speaks to the
	// assignee ("You have been assigned"); empty uses title.
	watcherTitle string
	body         string
	// teamOnly: shows team-only content that pentest clients never see.
	teamOnly bool
	// forceAssignee tells the assignee even if they stopped watching (the
	// assignment itself).
	forceAssignee bool
	// watchersToo tells the watchers although no person did it (a regression).
	watchersToo bool
	// actorWatches is why the actor starts watching ("" = they do not).
	actorWatches participationdom.Reason
	// assigneeWatches adds the assignee as a watcher (an assignment).
	assigneeWatches bool
}

// person parses an actor id; nil when no person did it.
func person(actorID string) *shared.ID {
	if actorID == "" {
		return nil
	}
	id, err := shared.IDFromString(actorID)
	if err != nil {
		return nil
	}
	return &id
}

// autoWatchFinding adds a person who took part as a watcher (best effort).
func (s *VulnerabilityService) autoWatchFinding(ctx context.Context, tenantID, findingID shared.ID, userID *shared.ID, reason participationdom.Reason) {
	if s.participants == nil || userID == nil || reason == "" {
		return
	}
	s.participants.AutoWatch(ctx, tenantID, participationdom.Item{Kind: participationdom.ItemFinding, ID: findingID}, *userID, reason)
}

// notifyFinding tells the people who should hear about an event on a finding.
func (s *VulnerabilityService) notifyFinding(ctx context.Context, f *vulnerability.Finding, ev findingEvent) {
	if s.participants == nil {
		s.notifyAssignee(ctx, f, ev.actorID, ev.typ, ev.title, ev.body)
		return
	}
	actor := person(ev.actorID)
	s.autoWatchFinding(ctx, f.TenantID(), f.ID(), actor, ev.actorWatches)
	if ev.assigneeWatches {
		s.autoWatchFinding(ctx, f.TenantID(), f.ID(), f.AssignedTo(), participationdom.ReasonAssigned)
	}
	if s.userNotificationService == nil {
		return
	}
	pe := participation.Event{
		Item:        participationdom.Item{Kind: participationdom.ItemFinding, ID: f.ID()},
		Actor:       actor,
		TeamOnly:    ev.teamOnly,
		WatchersToo: ev.watchersToo,
	}
	if a := f.AssignedTo(); a != nil {
		if ev.forceAssignee {
			pe.Forced = []shared.ID{*a}
		} else {
			pe.Direct = []shared.ID{*a}
		}
	}
	recipients, err := s.participants.Recipients(withLoadedFinding(ctx, f), f.TenantID(), pe)
	if err != nil {
		s.logger.Warn("finding event: recipients", "error", logger.SanitizeError(err), "type", ev.typ)
		return
	}
	findingID := f.ID()
	for _, r := range recipients {
		uid := r.UserID
		title := ev.title
		if r.Reason == notificationdom.ReasonWatching && ev.watcherTitle != "" {
			title = ev.watcherTitle
		}
		if err := s.userNotificationService.Notify(ctx, notificationdom.NotificationParams{
			TenantID:         f.TenantID(),
			Audience:         notificationdom.AudienceUser,
			AudienceID:       &uid,
			NotificationType: ev.typ,
			Severity:         f.Severity().String(),
			Title:            title,
			Body:             ev.body,
			ResourceType:     "finding",
			ResourceID:       &findingID,
			URL:              fmt.Sprintf("/findings/%s", f.ID().String()),
			ActorID:          actor,
			Reason:           r.Reason,
			Coalesce:         true,
		}); err != nil {
			s.logger.Warn("finding event: notify", "error", logger.SanitizeError(err), "type", ev.typ)
		}
	}
}

// NotifyRegression tells the assignee and the watchers that a finding closed
// as fixed was detected again and reopened (*retest.ChangeAnnouncer). A fix
// that a retest or a review had verified is worded as such. Who hears is
// decided as for any finding event (data scope re-checked at send time).
func (s *VulnerabilityService) NotifyRegression(ctx context.Context, tenantID, findingID shared.ID, verifiedFix bool, detail string) {
	f, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil || f == nil {
		return
	}
	title := "Regression: a fixed finding was detected again and reopened"
	if verifiedFix {
		title = "Verified fix regressed: a fixed and verified finding was detected again"
	}
	s.notifyFinding(ctx, f, findingEvent{
		typ:         notificationdom.TypeFindingStatusChange,
		title:       title,
		body:        detail,
		teamOnly:    isPentest(f),
		watchersToo: true,
	})
}
