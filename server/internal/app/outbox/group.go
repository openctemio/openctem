package outbox

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/google/uuid"

	notificationclient "github.com/openctemio/openctem/server/internal/infra/notifier"
	"github.com/openctemio/openctem/server/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/server/pkg/domain/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/notifymsg"
)

// Grouped alerts (docs/architecture/notification-system.md, "Grouped
// alerts"). A channel that groups (the default) does not get one message per
// finding event: the event's delivery to that channel is recorded in the
// open group of the channel and event type (status grouped, group id), and
// the group is sent as one outbox entry when its window ends, when it is
// full, or when a burst goes quiet. Every event keeps its own outbox entry
// and archive; only the delivery is grouped.

// groupItemsScanCap bounds how many items a grouped message looks at for
// its listed lines (private-program checks and facts are read per listed
// item).
const groupItemsScanCap = 3 * notifymsg.MaxGroupLines

// SetGroupRepository wires grouped delivery. Without it every event is sent
// on its own.
func (s *Service) SetGroupRepository(r outboxdom.GroupRepository) { s.groups = r }

// grouping returns the channel's grouping when entry may be grouped for it:
// an event of a groupable type about one finding, not a redelivery and not
// already the message of a group.
func (s *Service) grouping(intg *integration.IntegrationWithNotification, entry *outboxdom.Outbox) (integration.Grouping, bool) {
	if s.groups == nil || entry.AggregateType() != aggregateFinding || entry.AggregateID() == nil {
		return integration.Grouping{}, false
	}
	if !integration.Groupable(integration.EventType(entry.EventType())) {
		return integration.Grouping{}, false
	}
	md := entry.Metadata()
	if _, ok := md[MetaRedeliveryOf]; ok {
		return integration.Grouping{}, false
	}
	if _, ok := md[outboxdom.MetaGroupID]; ok {
		return integration.Grouping{}, false
	}
	g := integration.DefaultGrouping()
	if intg.Notification != nil {
		g = intg.Notification.Grouping()
	}
	return g, g.Enabled
}

const aggregateFinding = "finding"

// groupPasses hands the grouped deliveries of a batch of passes to their
// groups in one call. A delivery is grouped when its channel groups this
// kind of event and the item is not sent alone (urgent, within the
// budget); every other due delivery is sent as before. If a group cannot be
// written its deliveries are sent on their own: never lose an alert.
func (s *Service) groupPasses(ctx context.Context, passes []*entryPass, now time.Time) {
	if s.groups == nil {
		return
	}
	type ref struct {
		pass  *entryPass
		index int
	}
	var (
		reqs []outboxdom.GroupAddRequest
		refs []ref
	)
	for _, p := range passes {
		ds := p.entry.Deliveries()
		for i := range ds {
			if !ds[i].Due(now) {
				continue
			}
			intg, ok := p.byID[ds[i].IntegrationID]
			if !ok || !p.delivery.Allows(intg.ID()) {
				continue
			}
			g, ok := s.grouping(intg, p.entry)
			if !ok {
				continue
			}
			item := outboxdom.GroupItemFromOutbox(p.entry)
			// Critical is urgent here; the group store adds the findings
			// known to be exploited (KEV).
			item.Urgent = p.entry.Severity().String() == string(outboxdom.SeverityCritical)
			reqs = append(reqs, outboxdom.GroupAddRequest{
				TenantID: p.entry.TenantID(), IntegrationID: intg.ID(), Key: p.entry.EventType(),
				Window: g.Window(), Item: item, UrgentAtOnce: g.UrgentAtOnce,
			})
			refs = append(refs, ref{p, i})
		}
	}
	if len(reqs) == 0 {
		return
	}
	results, err := s.groups.AddBatch(ctx, reqs, now)
	if err != nil {
		s.logWarn("notification: group unavailable; sending on its own", "error", logger.SanitizeError(err))
	}
	for k, r := range refs {
		if k >= len(results) || results[k].GroupID.IsZero() || results[k].SendAlone {
			continue
		}
		if r.pass.grouped == nil {
			r.pass.grouped = map[int]outboxdom.GroupAddResult{}
		}
		r.pass.grouped[r.index] = results[k]
	}
}

// FlushDueGroups sends the groups that are due, up to limit, each as one
// outbox entry. It returns how many groups it closed.
func (s *Service) FlushDueGroups(ctx context.Context, limit int) (int, error) {
	return s.FlushDueGroupsAt(ctx, time.Now(), limit)
}

// FlushDueGroupsAt is FlushDueGroups as of now.
func (s *Service) FlushDueGroupsAt(ctx context.Context, now time.Time, limit int) (int, error) {
	if s.groups == nil {
		return 0, nil
	}
	return s.groups.ClaimDue(ctx, now, limit, s.enqueueGroup)
}

// announced returns the items a group's message announces: not already sent
// on their own, and, for a priority raise, still raised (a raise undone
// within the window, or a finding deleted since, is left out: the flap
// collapses into its final state).
func announced(items []outboxdom.GroupItem) []outboxdom.GroupItem {
	out := make([]outboxdom.GroupItem, 0, len(items))
	for _, it := range items {
		if it.SentAlone {
			continue
		}
		if it.EventType == string(integration.EventTypeFindingPriorityEscalated) && it.AggregateType == aggregateFinding {
			raisedTo, _ := it.Metadata["new_class"].(string)
			if it.CurrentPriorityClass == "" || (raisedTo != "" && priorityRank(it.CurrentPriorityClass) > priorityRank(raisedTo)) {
				continue
			}
		}
		out = append(out, it)
	}
	return out
}

func priorityRank(c string) int {
	switch c {
	case "P0":
		return 0
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	default:
		return 99
	}
}

// sortForMessage orders items most important first: severity, then urgent,
// then the latest event.
func sortForMessage(items []outboxdom.GroupItem) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if ra, rb := notifymsg.SeverityRank(a.Severity), notifymsg.SeverityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Urgent != b.Urgent {
			return a.Urgent
		}
		return a.EventAt.After(b.EventAt)
	})
}

// GroupLink is the console list of exactly the findings of a group.
func GroupLink(groupID shared.ID) string {
	return "/findings?" + outboxdom.MetaGroupID + "=" + groupID.String()
}

// enqueueGroup turns one claimed group into its message, inside the claim's
// transaction: nothing left, no message; one item, that event on its own
// (the full card); more, one grouped entry for the group's channel.
func (s *Service) enqueueGroup(ctx context.Context, tx *sql.Tx, g outboxdom.Group, items []outboxdom.GroupItem) (*shared.ID, int, error) {
	items = announced(items)
	if len(items) == 0 {
		return nil, 0, nil
	}
	sortForMessage(items)
	name, provider := s.channelLabel(ctx, g.TenantID, g.IntegrationID)
	delivery := outboxdom.NewChannelDelivery(g.IntegrationID.String(), name, provider)

	var entry *outboxdom.Outbox
	if len(items) == 1 {
		it := items[0]
		meta := make(map[string]any, len(it.Metadata)+1)
		maps.Copy(meta, it.Metadata)
		meta[outboxdom.MetaGroupID] = g.ID.String()
		entry = outboxdom.NewOutbox(outboxdom.OutboxParams{
			TenantID: g.TenantID, EventType: it.EventType, AggregateType: it.AggregateType, AggregateID: it.AggregateID,
			Title: it.Title, Body: it.Body, Severity: outboxdom.Severity(it.Severity), URL: it.URL, Metadata: meta,
		})
	} else {
		counts := map[string]int{}
		for _, it := range items {
			counts[notifymsg.NormalizeSeverityName(it.Severity)]++
		}
		// The archive's title, in English (the channel's message is built in
		// the organization's language when it is sent).
		head := notifymsg.BuildGroup(notifymsg.GroupInput{EventType: g.Key, Level: notifymsg.LevelMinimal, Count: len(items), Severities: counts})
		gid, err := uuid.Parse(g.ID.String())
		if err != nil {
			return nil, 0, fmt.Errorf("group id: %w", err)
		}
		entry = outboxdom.NewOutbox(outboxdom.OutboxParams{
			TenantID: g.TenantID, EventType: g.Key, AggregateType: outboxdom.AggregateNotificationGroup, AggregateID: &gid,
			Title: head.Headline, Severity: outboxdom.Severity(head.Severity), URL: GroupLink(g.ID),
			Metadata: map[string]any{
				outboxdom.MetaGroupID: g.ID.String(),
				"item_count":          len(items),
				"integration_id":      g.IntegrationID.String(),
				"burst":               g.Burst,
			},
		})
	}
	entry.SetDeliveries([]outboxdom.ChannelDelivery{delivery})
	if err := s.outboxRepo.CreateInTx(ctx, tx, entry); err != nil {
		return nil, 0, fmt.Errorf("enqueue group message: %w", err)
	}
	id := entry.ID()
	return &id, len(items), nil
}

// channelLabel names the channel for its delivery record (empty when it is
// gone: the delivery then fails as "not connected" and is retried).
func (s *Service) channelLabel(ctx context.Context, tenantID, integrationID shared.ID) (name, provider string) {
	intgs, err := s.getNotificationIntegrationsForTenant(ctx, tenantID)
	if err != nil {
		return "", ""
	}
	for _, intg := range intgs {
		if intg.ID() == integrationID {
			return intg.Name(), intg.Provider().String()
		}
	}
	return "", ""
}

// buildGroupMessage builds the one message of a group for its channel: the
// count, the items by asset (most important first, at most
// notifymsg.MaxGroupLines), "+N more" and one link to exactly those
// findings. Each listed item is checked against the private-program routing
// and scrubbed like a single message; an item the channel may no longer
// receive is not listed.
func (s *Service) buildGroupMessage(ctx context.Context, intg *integration.IntegrationWithNotification, entry *outboxdom.Outbox, delivery bountyprogram.Delivery) (notificationclient.Message, bool) {
	if s.groups == nil || entry.AggregateID() == nil {
		return notificationclient.Message{}, false
	}
	groupID, err := shared.IDFromString(entry.AggregateID().String())
	if err != nil {
		return notificationclient.Message{}, false
	}
	all, err := s.groups.Items(ctx, entry.TenantID(), groupID)
	if err != nil || len(all) == 0 {
		if err != nil {
			s.logWarn("notification: group items unreadable", "outbox_id", entry.ID().String(), "error", logger.SanitizeError(err))
		}
		return notificationclient.Message{}, false
	}
	items := announced(all)
	if len(items) == 0 {
		// Undone since the claim: still say what the group was.
		for _, it := range all {
			if !it.SentAlone {
				items = append(items, it)
			}
		}
	}
	sortForMessage(items)

	ext := intg.Notification
	level := notifymsg.LevelMinimal
	if ext != nil {
		level = ext.DetailLevel()
	}
	org, lang := s.organization(ctx, entry.TenantID())
	id := intg.ID()

	counts := map[string]int{}
	for _, it := range items {
		counts[notifymsg.NormalizeSeverityName(it.Severity)]++
	}
	count := len(items)
	var entries []notifymsg.GroupEntry
	for i, it := range items {
		if len(entries) >= notifymsg.MaxGroupLines || i >= groupItemsScanCap {
			break
		}
		d := delivery
		if s.delivery != nil {
			d, err = s.delivery.Resolve(ctx, entry.TenantID(), DeliverySubject(it.AggregateType, it.AggregateID, nil))
			if err != nil {
				// Unknown routing: never list it.
				count--
				continue
			}
		}
		if !d.Allows(id) {
			count--
			continue
		}
		// Every text of a listed item is scrubbed with that item's own
		// routing (the names of private programs this channel is not
		// attached to), like a single message.
		scrub := func(v string) string { return d.Scrub(id, v) }
		e := notifymsg.GroupEntry{Severity: it.Severity, Title: scrub(it.Title)}
		if r, ok := it.Metadata["reason"].(string); ok {
			e.Reason = scrub(r)
		}
		if level.Includes(notifymsg.LevelStandard) && s.facts != nil && it.AggregateID != nil {
			if fid, err := shared.IDFromString(it.AggregateID.String()); err == nil {
				if f, err := s.facts.Finding(ctx, entry.TenantID(), fid); err == nil && f != nil {
					f.Title, f.AssetName, f.AssetType = scrub(f.Title), scrub(f.AssetName), scrub(f.AssetType)
					f.Description = ""
					e.Facts = f
				}
			}
		}
		entries = append(entries, e)
	}
	count = max(count, len(entries))

	card := notifymsg.BuildGroup(notifymsg.GroupInput{
		EventType: entry.EventType(), Level: level, Locale: lang, Organization: org,
		URL: deliveryLink(s.linkBase, entry), Count: count, Severities: counts, Entries: entries,
	})
	if ext != nil && ext.MessageTemplate() != "" {
		var ok bool
		if card, ok = notifymsg.ApplyTemplateCount(card, ext.MessageTemplate(), count); !ok {
			s.logWarn("notification template no longer valid; default layout used",
				"integration_id", intg.Integration.ID().String())
		}
	}
	card = card.Map(func(v string) string { return delivery.Scrub(id, v) })
	return notificationclient.Message{
		Title:          card.Headline,
		Body:           card.Text(),
		Severity:       card.Severity,
		URL:            card.Action.URL,
		IdempotencyKey: idempotencyKey(entry),
		EventType:      entry.EventType(),
		EventVersion:   integration.EventPayloadVersion(integration.EventType(entry.EventType())),
		OccurredAt:     entry.CreatedAt(),
		Card:           &card,
	}, true
}
