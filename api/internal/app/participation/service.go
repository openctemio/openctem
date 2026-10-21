// Package participation serves the watchers of findings and remediation tasks
// (RFC-120, docs/architecture/participants-and-watchers.md). Watching grants
// nothing: a person is added only while they are an active member who can read
// the item, and every list re-checks it, so losing access hides a watcher
// (fail closed) without deleting the row.
package participation

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/participation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Access is what the request's caller may see of an item.
type Access struct {
	// ClientOnly: the caller is a pentest campaign client; they see counts,
	// never the names of the people on the item.
	ClientOnly bool
}

// ItemAccess answers the access questions of one item kind. The finding and
// task services implement it, so the rules (data scope, pentest campaign) are
// written once, where the item is read.
type ItemAccess interface {
	// CallerAccess checks that the request's caller can read the item
	// (shared.ErrNotFound otherwise) and says what they see of it.
	CallerAccess(ctx context.Context, tenantID, itemID shared.ID) (Access, error)
	// UserAccess reports whether the person could read the item on their own
	// account (data scope, pentest campaign) and, if so, what they see of it.
	// Membership is checked apart.
	UserAccess(ctx context.Context, tenantID, itemID, userID shared.ID) (Access, bool, error)
}

// MemberChecker says whether a user is an active member of the tenant
// (postgres.AccessControlRepository).
type MemberChecker interface {
	IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}

// AuditLogger writes audit events (*auditapp.AuditService).
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// AutoWatchPreference reads a person's "watch what I take part in" switch
// (postgres.NotificationRepository). No preferences row means on.
type AutoWatchPreference interface {
	AutoWatchEnabled(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}

// Service manages watchers.
type Service struct {
	repo    participation.Repository
	items   map[participation.ItemKind]ItemAccess
	members MemberChecker
	audit   AuditLogger
	prefs   AutoWatchPreference
	logger  *logger.Logger
}

// NewService creates the service. Without items or members wired it fails
// closed (nobody can be added, nothing is listed).
func NewService(repo participation.Repository, members MemberChecker, log *logger.Logger) *Service {
	return &Service{repo: repo, members: members, items: map[participation.ItemKind]ItemAccess{}, logger: log}
}

// SetItemAccess wires the access rules of one item kind.
func (s *Service) SetItemAccess(kind participation.ItemKind, a ItemAccess) { s.items[kind] = a }

// SetAutoWatchPreference wires the per-person switch for automatic watching.
// Without it automatic watching is off (fail closed: nobody is subscribed on a
// guess).
func (s *Service) SetAutoWatchPreference(p AutoWatchPreference) { s.prefs = p }

// SetAuditLogger wires the audit log.
func (s *Service) SetAuditLogger(a AuditLogger) { s.audit = a }

// Caller is the person making the request.
type Caller struct {
	UserID shared.ID
	// CanSeeNames: the caller may read the member list (team:members:read).
	CanSeeNames bool
}

// WatcherView is a watcher as the caller may see them.
type WatcherView struct {
	UserID    shared.ID
	Name      string
	AvatarURL string
	Reason    participation.Reason
	AddedBy   *shared.ID
	Since     string
}

// OwnerView is an asset owner shown as context.
type OwnerView struct {
	UserID    shared.ID
	Name      string
	AvatarURL string
	Type      string
}

// Me is the caller's own subscription.
type Me struct {
	// State is "subscribed", "unsubscribed" or "" (no row).
	State  participation.State
	Reason participation.Reason
}

// Participants is the People section of an item.
type Participants struct {
	// WatcherCount counts the watchers who can still read the item.
	WatcherCount int
	// NamesVisible: Watchers and AssetOwners are filled. Viewers, pentest
	// clients and anyone without the member list get the count only.
	NamesVisible bool
	Watchers     []WatcherView
	AssetOwners  []OwnerView
	Me           Me
}

func (s *Service) access(kind participation.ItemKind) (ItemAccess, error) {
	a, ok := s.items[kind]
	if !ok || a == nil {
		return nil, fmt.Errorf("%w: participation is not configured for %s", shared.ErrValidation, kind)
	}
	return a, nil
}

// canHear reports whether the person is an active member who can read the
// item now. Any lookup error counts as no (fail closed).
func (s *Service) canHear(ctx context.Context, a ItemAccess, tenantID shared.ID, item participation.Item, userID shared.ID) bool {
	_, ok := s.hearing(ctx, a, tenantID, item, userID)
	return ok
}

// hearing is canHear with what the person sees of the item.
func (s *Service) hearing(ctx context.Context, a ItemAccess, tenantID shared.ID, item participation.Item, userID shared.ID) (Access, bool) {
	if s.members == nil {
		return Access{}, false
	}
	ok, err := s.members.IsActiveTenantMember(ctx, tenantID, userID)
	if err != nil || !ok {
		return Access{}, false
	}
	acc, ok, err := a.UserAccess(ctx, tenantID, item.ID, userID)
	if err != nil {
		s.logger.Warn("participation: read check failed", "error", logger.SanitizeError(err))
		return Access{}, false
	}
	return acc, ok
}

// Participants returns the watchers the caller may see.
func (s *Service) Participants(ctx context.Context, tenantID shared.ID, item participation.Item, caller Caller) (*Participants, error) {
	a, err := s.access(item.Kind)
	if err != nil {
		return nil, err
	}
	acc, err := a.CallerAccess(ctx, tenantID, item.ID)
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListSubscribed(ctx, tenantID, item)
	if err != nil {
		return nil, err
	}
	out := &Participants{NamesVisible: caller.CanSeeNames && !acc.ClientOnly}
	for _, w := range rows {
		// A watcher who left or lost access is hidden, not deleted.
		if !s.canHear(ctx, a, tenantID, item, w.UserID) {
			continue
		}
		out.WatcherCount++
		if out.NamesVisible {
			out.Watchers = append(out.Watchers, WatcherView{
				UserID: w.UserID, Name: w.Name, AvatarURL: w.AvatarURL, Reason: w.Reason,
				AddedBy: w.AddedBy, Since: w.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			})
		}
	}
	if out.NamesVisible && item.Kind == participation.ItemFinding {
		owners, err := s.repo.AssetOwners(ctx, tenantID, item.ID)
		if err != nil {
			s.logger.Warn("participation: asset owners", "error", logger.SanitizeError(err))
		}
		for _, o := range owners {
			out.AssetOwners = append(out.AssetOwners, OwnerView{UserID: o.UserID, Name: o.Name, AvatarURL: o.AvatarURL, Type: o.Type})
		}
	}
	if !caller.UserID.IsZero() {
		mine, err := s.repo.Get(ctx, tenantID, item, caller.UserID)
		if err != nil {
			return nil, err
		}
		if mine != nil {
			out.Me = Me{State: mine.State, Reason: mine.Reason}
		}
	}
	return out, nil
}

// SetSelf records the caller's own choice (the bell). Reading the item is
// enough: a viewer may watch what they can read.
func (s *Service) SetSelf(ctx context.Context, tenantID shared.ID, item participation.Item, caller Caller, state participation.State) error {
	if caller.UserID.IsZero() {
		return shared.ErrForbidden
	}
	a, err := s.access(item.Kind)
	if err != nil {
		return err
	}
	if _, err := a.CallerAccess(ctx, tenantID, item.ID); err != nil {
		return err
	}
	return s.repo.SetState(ctx, tenantID, item, caller.UserID, state, participation.ReasonManual)
}

// AddWatchers subscribes people on the caller's behalf, all or none: each must
// be an active member of the tenant who can read the item, else the whole
// request is refused with one generic answer. The caller needs the item's
// write permission (checked by the route) and must be able to read the item.
func (s *Service) AddWatchers(ctx context.Context, tenantID shared.ID, item participation.Item, caller Caller, userIDs []shared.ID, actx auditapp.AuditContext) error {
	if len(userIDs) == 0 {
		return fmt.Errorf("%w: name at least one person", shared.ErrValidation)
	}
	if len(userIDs) > participation.MaxAddPerRequest {
		return participation.ErrTooManyPeople
	}
	a, err := s.access(item.Kind)
	if err != nil {
		return err
	}
	if _, err := a.CallerAccess(ctx, tenantID, item.ID); err != nil {
		return err
	}
	seen := map[shared.ID]bool{}
	targets := make([]shared.ID, 0, len(userIDs))
	for _, id := range userIDs {
		if id.IsZero() || seen[id] {
			continue
		}
		seen[id] = true
		if !s.canHear(ctx, a, tenantID, item, id) {
			return participation.ErrCannotAdd
		}
		targets = append(targets, id)
	}
	for _, id := range targets {
		if err := s.repo.Add(ctx, tenantID, item, id, caller.UserID); err != nil {
			return err
		}
		s.auditChange(ctx, actx, auditdom.ActionWorkItemWatcherAdded, item, id, "Added a watcher")
	}
	return nil
}

// RemoveWatcher deletes a person's row. Removing yourself needs only read
// access; removing someone else needs mayRemoveOthers (the item's write
// permission, checked by the caller of this method).
func (s *Service) RemoveWatcher(ctx context.Context, tenantID shared.ID, item participation.Item, caller Caller, target shared.ID, mayRemoveOthers bool, actx auditapp.AuditContext) error {
	a, err := s.access(item.Kind)
	if err != nil {
		return err
	}
	if _, err := a.CallerAccess(ctx, tenantID, item.ID); err != nil {
		return err
	}
	self := !caller.UserID.IsZero() && caller.UserID == target
	if !self && !mayRemoveOthers {
		return shared.ErrForbidden
	}
	removed, err := s.repo.Remove(ctx, tenantID, item, target)
	if err != nil {
		return err
	}
	if removed && !self {
		s.auditChange(ctx, actx, auditdom.ActionWorkItemWatcherRemoved, item, target, "Removed a watcher")
	}
	return nil
}

// AutoWatch subscribes a person who took part in the item (they commented,
// changed its status, were assigned, claimed a fix, took part in an approval).
// It never changes an existing row, so an unsubscribe wins, and it does nothing
// for a person who turned automatic watching off. Callers pass a person only:
// never a scanner, the system, an integration or an AI. Best effort.
func (s *Service) AutoWatch(ctx context.Context, tenantID shared.ID, item participation.Item, userID shared.ID, reason participation.Reason) {
	if userID.IsZero() || s.prefs == nil {
		return
	}
	on, err := s.prefs.AutoWatchEnabled(ctx, tenantID, userID)
	if err != nil {
		s.logger.Warn("participation: auto watch preference", "error", logger.SanitizeError(err))
		return
	}
	if !on {
		return
	}
	if _, err := s.repo.AutoSubscribe(ctx, tenantID, item, userID, reason); err != nil {
		s.logger.Warn("participation: auto watch", "error", logger.SanitizeError(err))
	}
}

func (s *Service) auditChange(ctx context.Context, actx auditapp.AuditContext, action auditdom.Action, item participation.Item, target shared.ID, msg string) {
	if s.audit == nil {
		return
	}
	rt := auditdom.ResourceTypeFinding
	if item.Kind == participation.ItemTask {
		rt = auditdom.ResourceTypeRemediationTask
	}
	ev := auditapp.NewSuccessEvent(action, rt, item.ID.String()).
		WithMessage(msg).
		WithMetadata("target_user_id", target.String())
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Warn("participation: audit", "error", logger.SanitizeError(err))
	}
}

// Event is something that happened to an item and who should hear about it.
type Event struct {
	Item participation.Item
	// Actor is the person who did it; nil when no person did (a scanner, the
	// system, an integration, an AI). The actor is never told, and watchers
	// hear only about what a person did.
	Actor *shared.ID
	// Direct are the people the event is for by their role (the assignee).
	Direct []shared.ID
	// Forced are told even if they stopped watching: the new assignee on an
	// assignment.
	Forced []shared.ID
	// TeamOnly: the event shows team-only content (a team comment on a pentest
	// finding), which pentest campaign clients never see.
	TeamOnly bool
}

// Recipient is a person to tell and why.
type Recipient struct {
	UserID shared.ID
	// Reason is "assigned" for a person told by their role, "watching" for a
	// watcher.
	Reason string
}

// Recipients is the one place that decides who hears about an event on an item
// (RFC-120 §4.4): the people it is for by role, plus the watchers when a person
// caused it; minus the actor; minus whoever stopped watching (except the forced
// ones); and then only people who are still active members who can read the
// item now, and, for team-only content, who are not pentest clients. Every read
// is re-checked here, at send time, so a watcher who lost scope hears nothing.
// The result has one entry per person.
func (s *Service) Recipients(ctx context.Context, tenantID shared.ID, ev Event) ([]Recipient, error) {
	a, err := s.access(ev.Item.Kind)
	if err != nil {
		return nil, err
	}
	subscribed, unsubscribed, err := s.repo.ListStates(ctx, tenantID, ev.Item)
	if err != nil {
		return nil, err
	}
	stopped := map[shared.ID]bool{}
	for _, id := range unsubscribed {
		stopped[id] = true
	}
	forced := map[shared.ID]bool{}
	for _, id := range ev.Forced {
		forced[id] = true
	}
	reasons := map[shared.ID]string{}
	order := make([]shared.ID, 0, len(ev.Direct)+len(ev.Forced)+len(subscribed))
	add := func(id shared.ID, reason string) {
		if id.IsZero() {
			return
		}
		if _, dup := reasons[id]; dup {
			return
		}
		reasons[id] = reason
		order = append(order, id)
	}
	for _, id := range ev.Forced {
		add(id, "assigned")
	}
	for _, id := range ev.Direct {
		add(id, "assigned")
	}
	if ev.Actor != nil {
		for _, id := range subscribed {
			add(id, "watching")
		}
	}
	out := make([]Recipient, 0, len(order))
	for _, id := range order {
		if ev.Actor != nil && id == *ev.Actor {
			continue
		}
		if stopped[id] && !forced[id] {
			continue
		}
		acc, ok := s.hearing(ctx, a, tenantID, ev.Item, id)
		if !ok || (ev.TeamOnly && acc.ClientOnly) {
			continue
		}
		out = append(out, Recipient{UserID: id, Reason: reasons[id]})
	}
	return out, nil
}
