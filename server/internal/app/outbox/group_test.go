package outbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/server/pkg/domain/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/notifymsg"
)

// memGroups is an in-memory GroupRepository with the same rules as the
// Postgres one (window, early flush, burst, urgent budget, dedupe by item).
type memGroups struct {
	mu     sync.Mutex
	groups []*outboxdom.Group
	items  map[shared.ID]map[string]*outboxdom.GroupItem
	// current priority class by finding id (the findings join).
	priority map[string]string
	// findings in KEV (the store's join).
	kev    map[string]bool
	addErr error
}

func newMemGroups() *memGroups {
	return &memGroups{items: map[shared.ID]map[string]*outboxdom.GroupItem{}, priority: map[string]string{}, kev: map[string]bool{}}
}

func (m *memGroups) AddBatch(_ context.Context, reqs []outboxdom.GroupAddRequest, now time.Time) ([]outboxdom.GroupAddResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]outboxdom.GroupAddResult, len(reqs))
	if m.addErr != nil {
		return out, m.addErr
	}
	for i, r := range reqs {
		item := r.Item
		if item.AggregateID != nil && m.kev[item.AggregateID.String()] {
			item.Urgent = true
		}
		out[i] = m.add(r.TenantID, r.IntegrationID, r.Key, r.Window, item, r.UrgentAtOnce, now)
	}
	return out, nil
}

func (m *memGroups) add(tenantID, integrationID shared.ID, key string, window time.Duration,
	item outboxdom.GroupItem, urgentAtOnce bool, now time.Time,
) outboxdom.GroupAddResult {
	var g *outboxdom.Group
	burst := false
	for _, x := range m.groups {
		if x.TenantID != tenantID || x.IntegrationID != integrationID || x.Key != key {
			continue
		}
		if x.ClosedAt == nil {
			g = x
		} else if x.SentCount > 0 && x.ClosedAt.After(now.Add(-window)) {
			burst = true
		}
	}
	if g == nil {
		g = &outboxdom.Group{ID: shared.NewID(), TenantID: tenantID, IntegrationID: integrationID, Key: key,
			Burst: burst, OpenedAt: now, LastItemAt: now, FlushAt: now.Add(window)}
		m.groups = append(m.groups, g)
		m.items[g.ID] = map[string]*outboxdom.GroupItem{}
	} else {
		g.LastItemAt = now
		if g.Burst {
			g.FlushAt = minTime(g.OpenedAt.Add(outboxdom.GroupMaxHold), now.Add(window))
		}
	}
	alone := item.Urgent && urgentAtOnce && g.UrgentSent < outboxdom.GroupUrgentPerWindow
	item.SentAlone = alone
	if prev, ok := m.items[g.ID][item.ItemKey]; ok {
		item.UpdateCount = prev.UpdateCount + 1
	} else {
		item.UpdateCount = 1
		g.ItemCount++
	}
	if alone {
		g.UrgentSent++
	}
	it := item
	m.items[g.ID][item.ItemKey] = &it
	return outboxdom.GroupAddResult{GroupID: g.ID, SendAlone: alone}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (m *memGroups) ClaimDue(ctx context.Context, now time.Time, limit int, fn outboxdom.GroupClaimFunc) (int, error) {
	n := 0
	for _, g := range m.groups {
		if n >= limit {
			break
		}
		if g.ClosedAt != nil || (g.FlushAt.After(now) && (g.Burst || g.ItemCount < outboxdom.GroupEarlyFlushItems)) {
			continue
		}
		items, _ := m.Items(ctx, g.TenantID, g.ID)
		oid, sent, err := fn(ctx, nil, *g, items)
		if err != nil {
			return n, err
		}
		t := now
		g.ClosedAt, g.SentCount, g.OutboxID = &t, sent, oid
		n++
	}
	return n, nil
}

func (m *memGroups) Get(_ context.Context, tenantID, groupID shared.ID) (*outboxdom.Group, error) {
	for _, g := range m.groups {
		if g.ID == groupID && g.TenantID == tenantID {
			return g, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *memGroups) Items(_ context.Context, tenantID, groupID shared.ID) ([]outboxdom.GroupItem, error) {
	var g *outboxdom.Group
	for _, x := range m.groups {
		if x.ID == groupID && x.TenantID == tenantID {
			g = x
		}
	}
	if g == nil {
		return nil, nil
	}
	out := make([]outboxdom.GroupItem, 0, len(m.items[g.ID]))
	for _, it := range m.items[g.ID] {
		c := *it
		c.CurrentPriorityClass = m.priority[c.ItemKey]
		if c.CurrentPriorityClass == "" {
			c.CurrentPriorityClass = "P1"
		}
		out = append(out, c)
	}
	return out, nil
}

func (m *memGroups) DeleteClosedBefore(context.Context, time.Time) (int64, error) { return 0, nil }

// groupOutboxRepo keeps the entries a claim enqueues.
type groupOutboxRepo struct {
	fakeOutboxRepo
	created []*outboxdom.Outbox
}

func (r *groupOutboxRepo) CreateInTx(_ context.Context, _ *sql.Tx, e *outboxdom.Outbox) error {
	r.created = append(r.created, e)
	return nil
}

// groupFacts answers every finding with a CVE on an asset named after it.
type groupFacts struct {
	asset map[string]string
	kev   map[string]bool
	reads int
}

func (f *groupFacts) Organization(context.Context, shared.ID) (string, string, error) {
	return "Example Corp", "en", nil
}

func (f *groupFacts) Finding(_ context.Context, _ shared.ID, id shared.ID) (*notifymsg.Facts, error) {
	f.reads++
	asset := f.asset[id.String()]
	if asset == "" {
		asset = "http://203.0.113.10"
	}
	return &notifymsg.Facts{Title: "PHP 8.1.2 " + id.String()[:4], CVE: "CVE-2024-4577", KEV: f.kev[id.String()],
		AssetName: asset, AssetType: "service"}, nil
}

func (f *groupFacts) Exposure(context.Context, shared.ID, shared.ID) (*notifymsg.Facts, error) {
	return nil, nil
}

func (f *groupFacts) AssetSources(context.Context, shared.ID, []string) ([]notifymsg.AssetRef, error) {
	return nil, nil
}

// stdChannel is a channel at the standard detail level (names, what, why)
// with the default filters and grouping.
func stdChannel(tenant shared.ID, name string) *integration.IntegrationWithNotification {
	ch := channel(tenant, name)
	ch.Notification = integration.NewNotificationExtension(ch.ID())
	return ch
}

type groupHarness struct {
	*harness
	groups *memGroups
	repo   *groupOutboxRepo
	facts  *groupFacts
}

func newGroupHarness(chs ...*integration.IntegrationWithNotification) *groupHarness {
	h := newHarness(chs...)
	g := &groupHarness{harness: h, groups: newMemGroups(), repo: &groupOutboxRepo{}, facts: &groupFacts{asset: map[string]string{}, kev: map[string]bool{}}}
	h.svc.outboxRepo = g.repo
	h.svc.SetGroupRepository(g.groups)
	h.svc.SetFactsSource(g.facts)
	return g
}

func raised(tenant shared.ID, severity string) *outboxdom.Outbox {
	id := uuid.New()
	return outboxdom.NewOutbox(outboxdom.OutboxParams{
		TenantID: tenant, EventType: string(integration.EventTypeFindingPriorityEscalated), AggregateType: "finding",
		AggregateID: &id, Title: "Priority escalated P2 -> P1", Body: "EPSS above the threshold",
		Severity: outboxdom.Severity(severity), URL: "/findings/" + id.String(),
		Metadata: map[string]any{"previous_class": "P2", "new_class": "P1", "reason": "EPSS above the threshold"},
	})
}

func (g *groupHarness) process(t *testing.T, entries ...*outboxdom.Outbox) {
	t.Helper()
	for _, e := range entries {
		if err := g.svc.processOutboxEntry(context.Background(), e, nil); err != nil {
			t.Fatalf("process: %v", err)
		}
	}
}

func (g *groupHarness) flushAt(t *testing.T, now time.Time) int {
	t.Helper()
	n, err := g.groups.ClaimDue(context.Background(), now, 100, g.svc.enqueueGroup)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	return n
}

// The owner's report: six "priority raised" events in the same minute were
// six messages. Grouped, the channel gets none at once and one message when
// the window ends, with the count, every item, one link, and every event
// still archived with its own record.
func TestGroup_BurstBecomesOneMessage(t *testing.T) {
	tenant := shared.NewID()
	ch := stdChannel(tenant, "tg")
	g := newGroupHarness(ch)
	var entries []*outboxdom.Outbox
	for range 6 {
		entries = append(entries, raised(tenant, "high"))
	}
	g.process(t, entries...)
	if len(g.sent) != 0 {
		t.Fatalf("sent %d messages before the window ended", len(g.sent))
	}
	for _, e := range entries {
		d := e.Deliveries()
		if len(d) != 1 || d[0].Status != outboxdom.DeliveryGrouped || d[0].GroupID == "" {
			t.Fatalf("delivery not grouped: %+v", d)
		}
	}
	if len(g.events.events) != 6 {
		t.Fatalf("archived %d events, want every one of the 6", len(g.events.events))
	}
	for _, ev := range g.events.events {
		if r := ev.SendResults(); len(r) != 1 || r[0].Status != "grouped" || r[0].GroupID == "" {
			t.Fatalf("archive does not say grouped: %+v", r)
		}
	}

	if n := g.flushAt(t, time.Now()); n != 0 {
		t.Fatalf("group sent before its window: %d", n)
	}
	if n := g.flushAt(t, time.Now().Add(3*time.Minute)); n != 1 {
		t.Fatalf("groups sent = %d, want 1", n)
	}
	if len(g.repo.created) != 1 {
		t.Fatalf("enqueued %d group entries, want 1", len(g.repo.created))
	}
	ge := g.repo.created[0]
	if ge.AggregateType() != outboxdom.AggregateNotificationGroup || ge.Title() != "6 findings raised to High" {
		t.Fatalf("group entry %q %q", ge.AggregateType(), ge.Title())
	}
	if d := ge.Deliveries(); len(d) != 1 || d[0].IntegrationID != ch.ID().String() {
		t.Fatalf("group entry goes to %+v, want only its channel", d)
	}
	g.process(t, ge)
	if len(g.sent) != 1 {
		t.Fatalf("sent %d messages for the group, want 1", len(g.sent))
	}
	msg := g.sent[0].msg
	if msg.Card == nil || msg.Card.Headline != "6 findings raised to High" {
		t.Fatalf("headline %+v", msg.Card)
	}
	if !strings.Contains(msg.URL, "/findings?notification_group_id="+ge.AggregateID().String()) {
		t.Fatalf("link %q is not the group's findings list", msg.URL)
	}
	if !strings.Contains(msg.Body, "http://203.0.113.10 (service)") || strings.Count(msg.Body, "- CVE-2024-4577") != 6 {
		t.Fatalf("body does not list the six items by asset:\n%s", msg.Body)
	}
}

// A group that ends up with one item sends that event's full card.
func TestGroup_SingleItemGetsTheFullCard(t *testing.T) {
	tenant := shared.NewID()
	g := newGroupHarness(stdChannel(tenant, "tg"))
	e := raised(tenant, "high")
	g.process(t, e)
	g.flushAt(t, time.Now().Add(3*time.Minute))
	if len(g.repo.created) != 1 {
		t.Fatalf("enqueued %d", len(g.repo.created))
	}
	single := g.repo.created[0]
	if single.AggregateType() != "finding" || single.AggregateID().String() != e.AggregateID().String() {
		t.Fatalf("single item sent as %q", single.AggregateType())
	}
	g.process(t, single)
	if len(g.sent) != 1 || g.sent[0].msg.Card.Headline != "Finding priority raised" || g.sent[0].msg.Card.Subject.Name == "" {
		t.Fatalf("single message %+v", g.sent)
	}
	// The copy is not grouped again.
	if d := single.Deliveries(); d[0].Status != outboxdom.DeliverySucceeded {
		t.Fatalf("single copy delivery %+v", d)
	}
}

// Urgent items (critical, or known exploited) go out at once when the
// channel says so, a few per window; the rest still group.
func TestGroup_UrgentBypass(t *testing.T) {
	tenant := shared.NewID()
	g := newGroupHarness(stdChannel(tenant, "tg"))
	var crit []*outboxdom.Outbox
	for range outboxdom.GroupUrgentPerWindow + 2 {
		crit = append(crit, raised(tenant, "critical"))
	}
	g.process(t, crit...)
	if len(g.sent) != outboxdom.GroupUrgentPerWindow {
		t.Fatalf("sent %d urgent items at once, want %d", len(g.sent), outboxdom.GroupUrgentPerWindow)
	}
	kev := raised(tenant, "high")
	g.groups.kev[kev.AggregateID().String()] = true
	g.process(t, kev)
	if len(g.sent) != outboxdom.GroupUrgentPerWindow {
		t.Fatal("a known-exploited item went alone after the urgent budget was spent")
	}
	g.flushAt(t, time.Now().Add(3*time.Minute))
	if len(g.repo.created) != 1 || g.repo.created[0].Metadata()["item_count"] != 3 {
		t.Fatalf("the group should carry the 3 urgent items over budget: %+v", g.repo.created)
	}

	// Off: urgent items wait like the rest.
	tenant2 := shared.NewID()
	ch := channel(tenant2, "slack")
	ext := integration.NewNotificationExtension(ch.ID())
	ext.SetGrouping(integration.Grouping{Enabled: true, WindowMinutes: 2, UrgentAtOnce: false})
	ch.Notification = ext
	g2 := newGroupHarness(ch)
	g2.process(t, raised(tenant2, "critical"))
	if len(g2.sent) != 0 {
		t.Fatal("urgent item sent at once with the setting off")
	}

	// A known-exploited finding, not critical, goes alone when on.
	tenant3 := shared.NewID()
	g3 := newGroupHarness(stdChannel(tenant3, "tg"))
	e := raised(tenant3, "high")
	g3.groups.kev[e.AggregateID().String()] = true
	g3.process(t, e)
	if len(g3.sent) != 1 {
		t.Fatal("known-exploited item was not sent at once")
	}
}

// Grouping off sends every event on its own, as before.
func TestGroup_OffSendsEachEvent(t *testing.T) {
	tenant := shared.NewID()
	ch := channel(tenant, "tg")
	ext := integration.NewNotificationExtension(ch.ID())
	ext.SetEnabledSeverities([]integration.Severity{integration.SeverityHigh, integration.SeverityCritical})
	ext.SetGrouping(integration.Grouping{Enabled: false, WindowMinutes: 2})
	ch.Notification = ext
	g := newGroupHarness(ch)
	g.process(t, raised(tenant, "high"), raised(tenant, "high"))
	if len(g.sent) != 2 {
		t.Fatalf("sent %d, want 2", len(g.sent))
	}
}

// Events that are not about one finding, and redeliveries, are never
// grouped; a group write that fails sends the event on its own (never lost).
func TestGroup_NotGroupedCases(t *testing.T) {
	tenant := shared.NewID()
	g := newGroupHarness(stdChannel(tenant, "tg"))
	approval := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: "approval_requested", Title: "x", Severity: "medium"})
	redelivery := raised(tenant, "high")
	redelivery.Metadata()[MetaRedeliveryOf] = uuid.NewString()
	g.process(t, approval, redelivery)
	if len(g.sent) != 2 {
		t.Fatalf("sent %d, want both alone", len(g.sent))
	}
	g.groups.addErr = errors.New("db down")
	g.process(t, raised(tenant, "high"))
	if len(g.sent) != 3 {
		t.Fatal("event lost when the group could not be written")
	}
}

// A raise undone within the window (lowered again) is not announced; a
// repeated raise of the same finding is one item in its final state.
func TestGroup_FlapCollapsesToFinalState(t *testing.T) {
	tenant := shared.NewID()
	g := newGroupHarness(stdChannel(tenant, "tg"))
	a, b, c := raised(tenant, "high"), raised(tenant, "high"), raised(tenant, "high")
	again := raised(tenant, "critical")
	aid := *a.AggregateID()
	again = outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: again.EventType(), AggregateType: "finding",
		AggregateID: &aid, Title: "Priority escalated P1 -> P0", Severity: "critical",
		Metadata: map[string]any{"previous_class": "P1", "new_class": "P0"}})
	// The setting is off for urgent so the second raise joins the group.
	ch := g.notif.list[0]
	ext := integration.NewNotificationExtension(ch.ID())
	ext.SetEnabledSeverities([]integration.Severity{integration.SeverityHigh, integration.SeverityCritical})
	ext.SetGrouping(integration.Grouping{Enabled: true, WindowMinutes: 2, UrgentAtOnce: false})
	ch.Notification = ext
	g.process(t, a, b, c, again)
	g.groups.priority[a.AggregateID().String()] = "P0"
	g.groups.priority[b.AggregateID().String()] = "P2" // lowered again
	g.groups.priority[c.AggregateID().String()] = "P1"
	g.flushAt(t, time.Now().Add(3*time.Minute))
	if len(g.repo.created) != 1 {
		t.Fatalf("enqueued %d", len(g.repo.created))
	}
	ge := g.repo.created[0]
	if ge.Metadata()["item_count"] != 2 {
		t.Fatalf("item_count %v, want 2 (a in its final state, c; b undone)", ge.Metadata()["item_count"])
	}
	if ge.Title() != "2 findings raised in priority" {
		t.Fatalf("title %q", ge.Title())
	}
}

// A group of thousands lists ten lines and "+N more", and fits Telegram.
func TestGroup_LargeGroupIsOneSummary(t *testing.T) {
	tenant := shared.NewID()
	g := newGroupHarness(stdChannel(tenant, "tg"))
	for i := range 3000 {
		e := raised(tenant, "high")
		g.facts.asset[e.AggregateID().String()] = fmt.Sprintf("host-%d.example.com", i%7)
		g.process(t, e)
	}
	if n := g.flushAt(t, time.Now().Add(time.Second)); n != 1 {
		t.Fatalf("flushed %d groups, want 1 (full group goes early)", n)
	}
	g.process(t, g.repo.created[0])
	if len(g.sent) != 1 {
		t.Fatalf("sent %d", len(g.sent))
	}
	body := g.sent[0].msg.Body
	if strings.Count(body, "\n- ") != notifymsg.MaxGroupLines || !strings.Contains(body, "+2990 more") {
		t.Fatalf("body:\n%s", body)
	}
	if g.facts.reads > notifymsg.MaxGroupLines {
		t.Fatalf("facts read %d times: the message must read only its listed items", g.facts.reads)
	}
}

// An item the channel may no longer receive (its asset moved into a private
// program) is not listed.
type denyResolver struct{ deny map[string]bool }

func (r denyResolver) Resolve(_ context.Context, _ shared.ID, s bountyprogram.DeliverySubject) (bountyprogram.Delivery, error) {
	for _, f := range s.FindingIDs {
		if r.deny[f.String()] {
			return bountyprogram.Delivery{Restricted: [][]shared.ID{{shared.NewID()}}}, nil
		}
	}
	return bountyprogram.Delivery{}, nil
}

func (r denyResolver) RestrictedAssets(context.Context, shared.ID, []shared.ID) (map[shared.ID]bool, error) {
	return nil, nil
}

func TestGroup_PrivateProgramItemNotListed(t *testing.T) {
	tenant := shared.NewID()
	g := newGroupHarness(stdChannel(tenant, "tg"))
	a, b := raised(tenant, "high"), raised(tenant, "high")
	g.facts.asset[b.AggregateID().String()] = "secret-program-host.example.com"
	g.process(t, a, b)
	g.flushAt(t, time.Now().Add(3*time.Minute))
	g.svc.SetDeliveryResolver(denyResolver{deny: map[string]bool{b.AggregateID().String(): true}})
	g.process(t, g.repo.created[0])
	if len(g.sent) != 1 {
		t.Fatalf("sent %d", len(g.sent))
	}
	if body := g.sent[0].msg.Body; strings.Contains(body, "secret-program-host") || strings.Count(body, "\n- ") != 1 {
		t.Fatalf("restricted item listed:\n%s", body)
	}
}

// Groups never mix tenants or channels.
func TestGroup_TenantAndChannelIsolation(t *testing.T) {
	t1, t2 := shared.NewID(), shared.NewID()
	g := newGroupHarness(stdChannel(t1, "a"), stdChannel(t1, "b"))
	g.process(t, raised(t1, "high"), raised(t1, "high"))
	// Another tenant's harness shares the group store.
	g2 := newGroupHarness(stdChannel(t2, "c"))
	g2.svc.SetGroupRepository(g.groups)
	g2.svc.outboxRepo = g.repo
	g2.process(t, raised(t2, "high"))
	g.flushAt(t, time.Now().Add(3*time.Minute))
	// tenant 1: two channels, one group each with 2 items; tenant 2: one group with 1 item.
	if len(g.repo.created) != 3 {
		t.Fatalf("enqueued %d group messages, want 3", len(g.repo.created))
	}
	for _, e := range g.repo.created {
		ch := e.Deliveries()[0].IntegrationID
		switch e.TenantID() {
		case t1:
			if e.Metadata()["item_count"] != 2 || (ch != g.notif.list[0].Integration.ID().String() && ch != g.notif.list[1].Integration.ID().String()) {
				t.Fatalf("tenant 1 group %+v", e.Metadata())
			}
		case t2:
			if e.AggregateType() != "finding" || ch != g2.notif.list[0].Integration.ID().String() {
				t.Fatalf("tenant 2 group crossed: %q to %s", e.AggregateType(), ch)
			}
		default:
			t.Fatal("unknown tenant")
		}
	}
}
