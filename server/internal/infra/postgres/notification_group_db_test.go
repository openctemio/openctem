package postgres

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	appoutbox "github.com/openctemio/openctem/server/internal/app/outbox"
	notificationclient "github.com/openctemio/openctem/server/internal/infra/notifier"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	"github.com/openctemio/openctem/server/pkg/domain/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// Grouped alerts (docs/architecture/notification-system.md "Grouped
// alerts") against the real schema: window, early send at the item limit,
// burst, urgent budget, dedupe, tenant isolation, the findings link, and a
// 5,000-event burst through the outbox worker.

type groupFixture struct {
	ctx    context.Context
	db     *sql.DB
	repo   *NotificationGroupRepository
	tenant shared.ID
	asset  shared.ID
	intg   shared.ID
}

func newGroupFixture(t *testing.T, db *sql.DB) *groupFixture {
	t.Helper()
	ctx := context.Background()
	f := &groupFixture{ctx: ctx, db: db, repo: NewNotificationGroupRepository(&DB{DB: db})}
	f.tenant = seedTestTenant(ctx, t, db)
	f.asset = seedTestAsset(ctx, t, db, f.tenant)
	f.intg = f.integration(t, f.tenant)
	return f
}

func (f *groupFixture) integration(t *testing.T, tenant shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	mustExec(t, f.db, `INSERT INTO integrations (id, tenant_id, name, category, provider, status, auth_type, credentials_encrypted)
		VALUES ($1, $2, $3, 'notification', 'webhook', 'connected', 'token', 'https://hook.example.com/x')`,
		id.String(), tenant.String(), "hook-"+id.String()[:8])
	mustExec(t, f.db, `INSERT INTO integration_notification_extensions (integration_id, enabled_event_types)
		VALUES ($1, '["finding_priority_escalated", "new_finding"]')`, id.String())
	return id
}

func (f *groupFixture) finding(t *testing.T, tenant, asset shared.ID, class string) shared.ID {
	t.Helper()
	id := shared.NewID()
	mustExec(t, f.db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, priority_class)
		VALUES ($1, $2, $3, 'sca', 'test', 'm', 'high', $4, 'new', $5)`,
		id.String(), tenant.String(), asset.String(), shared.NewID().String(), class)
	return id
}

func groupItem(findingID shared.ID, severity string) outbox.GroupItem {
	u := uuid.MustParse(findingID.String())
	return outbox.GroupItem{ItemKey: findingID.String(), OutboxID: shared.NewID(), EventType: "finding_priority_escalated",
		AggregateType: "finding", AggregateID: &u, Title: "Priority escalated P2 -> P1", Severity: severity,
		Metadata: map[string]any{"new_class": "P1"}, EventAt: time.Now()}
}

// add records one item through AddBatch.
func (f *groupFixture) add(t *testing.T, key string, it outbox.GroupItem, urgentAtOnce bool, at time.Time) outbox.GroupAddResult {
	t.Helper()
	res, err := f.repo.AddBatch(f.ctx, []outbox.GroupAddRequest{{TenantID: f.tenant, IntegrationID: f.intg, Key: key,
		Window: 2 * time.Minute, Item: it, UrgentAtOnce: urgentAtOnce}}, at)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	return res[0]
}

// claim closes the due groups and returns what each one carried.
func (f *groupFixture) claim(t *testing.T, now time.Time) map[shared.ID][]outbox.GroupItem {
	t.Helper()
	got := map[shared.ID][]outbox.GroupItem{}
	_, err := f.repo.ClaimDue(f.ctx, now, 1000, func(_ context.Context, _ *sql.Tx, g outbox.Group, items []outbox.GroupItem) (*shared.ID, int, error) {
		if g.TenantID == f.tenant {
			got[g.ID] = items
		}
		return nil, len(items), nil
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	return got
}

func TestNotificationGroups_WindowAndDedupe_DB(t *testing.T) {
	f := newGroupFixture(t, openSensorDB(t))
	now := time.Now()
	a := f.finding(t, f.tenant, f.asset, "P1")
	b := f.finding(t, f.tenant, f.asset, "P1")
	var gid shared.ID
	for i, id := range []shared.ID{a, b, a} {
		res := f.add(t, "finding_priority_escalated", groupItem(id, "high"), true, now.Add(time.Duration(i)*time.Second))
		if i > 0 && res.GroupID != gid {
			t.Fatal("same channel and kind opened a second group")
		}
		gid = res.GroupID
	}
	if got := f.claim(t, now.Add(time.Minute)); len(got) != 0 {
		t.Fatal("group sent before its window ended")
	}
	got := f.claim(t, now.Add(2*time.Minute+time.Second))
	items := got[gid]
	if len(items) != 2 {
		t.Fatalf("group carried %d items, want 2 (a repeated finding is one item)", len(items))
	}
	for _, it := range items {
		if it.ItemKey == a.String() && it.UpdateCount != 2 {
			t.Fatalf("update_count %d, want 2", it.UpdateCount)
		}
		if it.CurrentPriorityClass != "P1" || it.AssetID != f.asset.String() {
			t.Fatalf("finding join %+v", it)
		}
	}
	g, err := f.repo.Get(f.ctx, f.tenant, gid)
	if err != nil || g.ClosedAt == nil || g.SentCount != 2 || g.ItemCount != 2 {
		t.Fatalf("closed group %+v err %v", g, err)
	}
	// The next item opens a new group: a closed one never takes items.
	if res := f.add(t, "finding_priority_escalated", groupItem(b, "high"), true, now.Add(3*time.Minute)); res.GroupID == gid {
		t.Fatal("a closed group took an item")
	}
}

func TestNotificationGroups_EarlySendAndBurst_DB(t *testing.T) {
	f := newGroupFixture(t, openSensorDB(t))
	now := time.Now()
	add := func(at time.Time) shared.ID {
		return f.add(t, "new_finding", groupItem(f.finding(t, f.tenant, f.asset, "P2"), "high"), true, at).GroupID
	}
	var first shared.ID
	for range outbox.GroupEarlyFlushItems {
		first = add(now)
	}
	got := f.claim(t, now.Add(time.Second))
	if len(got[first]) != outbox.GroupEarlyFlushItems {
		t.Fatalf("a full group was not sent early: %d", len(got))
	}
	// The burst goes on: the next group collects until quiet, whatever its size.
	var second shared.ID
	for i := range 3 * outbox.GroupEarlyFlushItems {
		second = add(now.Add(time.Duration(i) * time.Second))
	}
	g, _ := f.repo.Get(f.ctx, f.tenant, second)
	if !g.Burst {
		t.Fatal("group after an early send is not a burst group")
	}
	last := now.Add(time.Duration(3*outbox.GroupEarlyFlushItems-1) * time.Second)
	if got := f.claim(t, last.Add(time.Minute)); len(got) != 0 {
		t.Fatal("burst group sent while the burst was still going")
	}
	got = f.claim(t, last.Add(2*time.Minute+time.Second))
	if len(got[second]) != 3*outbox.GroupEarlyFlushItems {
		t.Fatalf("burst group carried %d items", len(got[second]))
	}
	// A burst that never goes quiet is still sent after GroupMaxHold.
	closedAt := last.Add(2*time.Minute + time.Second)
	third := add(closedAt.Add(10 * time.Second))
	for i := 1; i <= 20; i++ {
		third = add(closedAt.Add(10*time.Second + time.Duration(i)*time.Minute))
	}
	g, _ = f.repo.Get(f.ctx, f.tenant, third)
	if !g.Burst || !g.FlushAt.Equal(g.OpenedAt.Add(outbox.GroupMaxHold)) {
		t.Fatalf("burst group flush_at %v, opened %v: want opened + %v", g.FlushAt, g.OpenedAt, outbox.GroupMaxHold)
	}
}

func TestNotificationGroups_UrgentBudget_DB(t *testing.T) {
	f := newGroupFixture(t, openSensorDB(t))
	now := time.Now()
	alone := 0
	var gid shared.ID
	for range outbox.GroupUrgentPerWindow + 3 {
		it := groupItem(f.finding(t, f.tenant, f.asset, "P0"), "critical")
		it.Urgent = true
		res := f.add(t, "finding_priority_escalated", it, true, now)
		gid = res.GroupID
		if res.SendAlone {
			alone++
		}
	}
	if alone != outbox.GroupUrgentPerWindow {
		t.Fatalf("%d urgent items went alone, want %d", alone, outbox.GroupUrgentPerWindow)
	}
	items, err := f.repo.Items(f.ctx, f.tenant, gid)
	if err != nil {
		t.Fatal(err)
	}
	sentAlone := 0
	for _, it := range items {
		if it.SentAlone {
			sentAlone++
		}
	}
	if len(items) != outbox.GroupUrgentPerWindow+3 || sentAlone != outbox.GroupUrgentPerWindow {
		t.Fatalf("items %d, sent alone %d: every item is recorded in the group", len(items), sentAlone)
	}
}

// Another tenant reads none of a group, and the findings link of a group
// lists exactly its findings, for its tenant only.
func TestNotificationGroups_TenantIsolationAndLink_DB(t *testing.T) {
	db := openSensorDB(t)
	f := newGroupFixture(t, db)
	other := newGroupFixture(t, db)
	now := time.Now()
	listed := []shared.ID{f.finding(t, f.tenant, f.asset, "P1"), f.finding(t, f.tenant, f.asset, "P1")}
	f.finding(t, f.tenant, f.asset, "P1") // not in the group
	var gid shared.ID
	for _, id := range listed {
		gid = f.add(t, "finding_priority_escalated", groupItem(id, "high"), false, now).GroupID
	}
	if items, _ := f.repo.Items(f.ctx, other.tenant, gid); len(items) != 0 {
		t.Fatal("another tenant read the group's items")
	}
	if _, err := f.repo.Get(f.ctx, other.tenant, gid); err == nil {
		t.Fatal("another tenant read the group")
	}
	// An item cannot name another tenant's finding into the join either.
	foreign := other.finding(t, other.tenant, other.asset, "P0")
	f.add(t, "finding_priority_escalated", groupItem(foreign, "high"), false, now)
	items, _ := f.repo.Items(f.ctx, f.tenant, gid)
	for _, it := range items {
		if it.ItemKey == foreign.String() && it.CurrentPriorityClass != "" {
			t.Fatal("the findings join crossed tenants")
		}
	}

	count := func(tenant shared.ID) int {
		v, _ := url.ParseQuery(outbox.MetaGroupID + "=" + gid.String())
		spec, err := filterspec.ParseValues(v, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		where, err := filterspec.Compile(spec, vulnerability.FindingFields, filterspec.SystemActor(tenant, "test"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		var n int
		if err := db.QueryRowContext(f.ctx, `SELECT count(*) FROM findings WHERE `+where.SQL, where.Args...).Scan(&n); err != nil {
			t.Fatalf("query: %v", err)
		}
		return n
	}
	if n := count(f.tenant); n != 2 {
		t.Fatalf("link lists %d findings, want exactly the 2 of the group", n)
	}
	if n := count(other.tenant); n != 0 {
		t.Fatalf("another tenant's link lists %d findings", n)
	}
}

func TestNotificationExtension_GroupingRoundTrip_DB(t *testing.T) {
	db := openSensorDB(t)
	f := newGroupFixture(t, db)
	repo := NewIntegrationNotificationExtensionRepository(&DB{DB: db}, NewIntegrationRepository(&DB{DB: db}))
	list, err := repo.ListIntegrationsWithNotification(f.ctx, f.tenant)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v (%d)", err, len(list))
	}
	if g := list[0].Notification.Grouping(); g != integration.DefaultGrouping() {
		t.Fatalf("existing channel grouping %+v, want the default (on)", g)
	}
	ext := list[0].Notification
	ext.SetGrouping(integration.Grouping{Enabled: false, WindowMinutes: 15, UrgentAtOnce: false})
	if err := repo.Update(f.ctx, ext); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := repo.GetByIntegrationID(f.ctx, f.intg)
	if err != nil || got.Grouping() != (integration.Grouping{Enabled: false, WindowMinutes: 15}) {
		t.Fatalf("read back %+v err %v", got.Grouping(), err)
	}
	if _, err := db.ExecContext(f.ctx, `UPDATE integration_notification_extensions SET group_window_minutes = 0 WHERE integration_id = $1`, f.intg.String()); err == nil {
		t.Fatal("a window of 0 minutes was stored")
	}
}

// countingClient counts sends without reaching any provider.
type countingClient struct {
	mu   *sync.Mutex
	msgs *[]notificationclient.Message
}

func (c countingClient) Send(_ context.Context, m notificationclient.Message) (*notificationclient.SendResult, error) {
	c.mu.Lock()
	*c.msgs = append(*c.msgs, m)
	c.mu.Unlock()
	return &notificationclient.SendResult{Success: true}, nil
}
func (c countingClient) TestConnection(context.Context) (*notificationclient.SendResult, error) {
	return nil, nil
}
func (c countingClient) Provider() string { return "webhook" }

// A re-score burst of 5,000 priority raises reaches the channel as at most
// two messages (the first full group, then one summary once the burst is
// quiet), every event is archived with its own record, and the worker
// absorbs the burst in seconds.
func TestNotificationGroups_Burst5000_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "notify_group_burst", "../../../migrations")
	f := newGroupFixture(t, db)
	const n = 5000
	ctx := f.ctx
	mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, priority_class)
		SELECT uuid_generate_v7(), $1, $2, 'sca', 'test', 'm', 'high', 'fp-' || g, 'new', 'P1' FROM generate_series(1, $3) g`,
		f.tenant.String(), f.asset.String(), n)
	mustExec(t, db, `INSERT INTO notification_outbox (tenant_id, event_type, aggregate_type, aggregate_id, title, severity, url, metadata)
		SELECT tenant_id, 'finding_priority_escalated', 'finding', id, 'Priority escalated P2 -> P1', 'high',
		       '/findings/' || id, '{"previous_class":"P2","new_class":"P1","reason":"EPSS above the threshold"}'::jsonb
		FROM findings WHERE tenant_id = $1`, f.tenant.String())

	pdb := &DB{DB: db}
	svc := appoutbox.NewService(NewOutboxRepository(pdb), NewOutboxEventRepository(pdb),
		NewIntegrationNotificationExtensionRepository(pdb, NewIntegrationRepository(pdb)),
		func(s string) (string, error) { return s, nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.SetGroupRepository(f.repo)
	svc.SetFactsSource(NewNotificationFactsRepository(pdb))
	var (
		mu   sync.Mutex
		msgs []notificationclient.Message
	)
	svc.SetClientFactory(func(notificationclient.Config) (notificationclient.Client, error) {
		return countingClient{mu: &mu, msgs: &msgs}, nil
	})

	start := time.Now()
	rounds := 0
	for {
		processed, failed, err := svc.ProcessOutboxBatch(ctx, "burst-test", 50)
		if err != nil {
			t.Fatalf("batch: %v", err)
		}
		if failed > 0 {
			t.Fatalf("%d entries failed", failed)
		}
		// The worker sends due groups between batches (worst case for the
		// item limit: every round).
		if _, err := svc.FlushDueGroups(ctx, 100); err != nil {
			t.Fatalf("flush: %v", err)
		}
		rounds++
		if processed == 0 {
			break
		}
	}
	absorbed := time.Since(start)
	// The burst goes quiet: its summary is due one window later.
	flushStart := time.Now()
	if _, err := svc.FlushDueGroupsAt(ctx, time.Now().Add(3*time.Minute), 100); err != nil {
		t.Fatalf("flush: %v", err)
	}
	t.Logf("closing the burst group took %v", time.Since(flushStart))
	sendStart := time.Now()
	for {
		processed, _, err := svc.ProcessOutboxBatch(ctx, "burst-test", 50)
		if err != nil {
			t.Fatal(err)
		}
		if processed == 0 {
			break
		}
	}
	total := time.Since(start)
	t.Logf("sending the burst summary took %v", time.Since(sendStart))

	if len(msgs) == 0 || len(msgs) > 2 {
		t.Fatalf("a burst of %d sent %d messages, want at most 2", n, len(msgs))
	}
	var archived, grouped int
	if err := db.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE send_results @> '[{"status":"grouped"}]')
		FROM notification_events WHERE tenant_id = $1 AND aggregate_type = 'finding'`, f.tenant.String()).Scan(&archived, &grouped); err != nil {
		t.Fatal(err)
	}
	if archived != n || grouped != n {
		t.Fatalf("archived %d events (%d grouped), want every one of %d", archived, grouped, n)
	}
	var announced int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(sum(sent_count), 0) FROM notification_groups WHERE tenant_id = $1`, f.tenant.String()).Scan(&announced); err != nil {
		t.Fatal(err)
	}
	if announced != n {
		t.Fatalf("groups announced %d of %d", announced, n)
	}
	for _, m := range msgs {
		if m.Card == nil || len([]rune(m.Body)) > 4096 {
			t.Fatalf("message without card or too long: %d", len(m.Body))
		}
		t.Logf("message: %s (%d characters)", m.Card.Headline, len([]rune(m.Body)))
	}
	t.Logf("burst of %d: absorbed in %v over %d batches of 50, %d messages, done in %v", n, absorbed, rounds, len(msgs), total)
}

// One batch: a finding raised twice is one item (two events folded), a
// finding in KEV is urgent whatever its severity, and every request gets
// its group.
func TestNotificationGroups_BatchFoldAndKEV_DB(t *testing.T) {
	f := newGroupFixture(t, openSensorDB(t))
	now := time.Now()
	a := f.finding(t, f.tenant, f.asset, "P1")
	kev := f.finding(t, f.tenant, f.asset, "P1")
	mustExec(t, f.db, `UPDATE findings SET is_in_kev = true WHERE tenant_id = $1 AND id = $2`, f.tenant.String(), kev.String())
	req := func(id shared.ID) outbox.GroupAddRequest {
		return outbox.GroupAddRequest{TenantID: f.tenant, IntegrationID: f.intg, Key: "finding_priority_escalated",
			Window: 2 * time.Minute, Item: groupItem(id, "high"), UrgentAtOnce: true}
	}
	res, err := f.repo.AddBatch(f.ctx, []outbox.GroupAddRequest{req(a), req(kev), req(a)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].GroupID.IsZero() || res[0].GroupID != res[1].GroupID || res[1].GroupID != res[2].GroupID {
		t.Fatalf("results %+v", res)
	}
	if res[0].SendAlone || res[2].SendAlone || !res[1].SendAlone {
		t.Fatalf("only the KEV finding goes alone: %+v", res)
	}
	items, _ := f.repo.Items(f.ctx, f.tenant, res[0].GroupID)
	if len(items) != 2 {
		t.Fatalf("items %d, want 2", len(items))
	}
	for _, it := range items {
		if it.ItemKey == a.String() && it.UpdateCount != 2 {
			t.Fatalf("folded events %d, want 2", it.UpdateCount)
		}
	}
	g, _ := f.repo.Get(f.ctx, f.tenant, res[0].GroupID)
	if g.ItemCount != 2 || g.UrgentSent != 1 {
		t.Fatalf("group counts %+v", g)
	}
}
