package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gws "github.com/gorilla/websocket"
	_ "github.com/lib/pq"

	integrationsvc "github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	"github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// In-app notifications are pushed over the WebSocket hub. These tests run the
// real hub, the real /ws handler and the real notification repository against
// Postgres, connect several users of one tenant, and check that a
// notification reaches exactly the users its inbox query would show it to:
//
//   - user-targeted: only that user, and nobody can subscribe to another
//     user's channel;
//   - group-targeted: only the group's members;
//   - audience "all": every member, filtered by each one's preferences;
//   - preferences (in-app off, muted type, minimum severity) apply the same
//     way to the inbox list, the unread count and the push.
//
// Run with: go test -v ./tests/integration -run 'TestNotificationWS|TestNotificationPreferences'

type wsHarness struct {
	t        *testing.T
	db       *sql.DB
	tenantID shared.ID
	repo     *postgres.NotificationRepository
	svc      *integrationsvc.NotificationService
	server   *httptest.Server
}

func newWSHarness(t *testing.T) *wsHarness {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	tenantID := createTestTenant(t, db, "WS Notification Isolation")
	t.Cleanup(func() { cleanupTestData(db, tenantID) })

	log := logger.NewNop()
	hub := websocket.NewHub(log)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go hub.Run(ctx)

	// Stand-in for the ticket middleware: the identity a connection
	// authenticates as comes from the server, never from the channel name.
	h := websocket.NewHandler(hub, log, nil, "development")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := context.WithValue(r.Context(), middleware.UserIDKey, r.URL.Query().Get("as"))
		c = context.WithValue(c, middleware.TenantIDKey, tenantID.String())
		h.ServeWS(w, r.WithContext(c))
	}))
	t.Cleanup(srv.Close)

	repo := postgres.NewNotificationRepository(&postgres.DB{DB: db})
	return &wsHarness{
		t: t, db: db, tenantID: tenantID, repo: repo,
		svc:    integrationsvc.NewNotificationService(repo, hub, log),
		server: srv,
	}
}

func (h *wsHarness) member(name string) shared.ID {
	h.t.Helper()
	email := fmt.Sprintf("ws-%s-%d@example.com", name, time.Now().UnixNano())
	uid := createTestUser(h.t, h.db, email, name)
	h.t.Cleanup(func() {
		for _, q := range []string{
			"DELETE FROM group_members WHERE user_id = $1",
			"DELETE FROM notification_preferences WHERE user_id = $1",
			"DELETE FROM tenant_members WHERE user_id = $1",
			"DELETE FROM users WHERE id = $1",
		} {
			_, _ = h.db.Exec(q, uid.String())
		}
	})
	createTestMembership(h.t, h.db, h.tenantID, uid, "member")
	return uid
}

func (h *wsHarness) group(members ...shared.ID) shared.ID {
	h.t.Helper()
	gid := shared.NewID()
	if _, err := h.db.Exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, $3, $3)`,
		gid.String(), h.tenantID.String(), "ws-group-"+gid.String()[:8]); err != nil {
		h.t.Fatalf("create group: %v", err)
	}
	for _, m := range members {
		if _, err := h.db.Exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`,
			gid.String(), m.String()); err != nil {
			h.t.Fatalf("add group member: %v", err)
		}
	}
	return gid
}

// wsConn is one connected user with every server message buffered.
type wsConn struct {
	t    *testing.T
	conn *gws.Conn
	msgs chan websocket.Message
}

func (h *wsHarness) connect(userID shared.ID) *wsConn {
	h.t.Helper()
	url := "ws" + strings.TrimPrefix(h.server.URL, "http") + "/?as=" + userID.String()
	conn, resp, err := gws.DefaultDialer.Dial(url, nil)
	if err != nil {
		h.t.Fatalf("dial ws as %s: %v", userID, err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	c := &wsConn{t: h.t, conn: conn, msgs: make(chan websocket.Message, 64)}
	go func() {
		for {
			var m websocket.Message
			if err := conn.ReadJSON(&m); err != nil {
				close(c.msgs)
				return
			}
			c.msgs <- m
		}
	}()
	h.t.Cleanup(func() { _ = conn.Close() })
	return c
}

// subscribe asks for a channel and returns whether the server accepted it.
func (c *wsConn) subscribe(channel string) bool {
	c.t.Helper()
	if err := c.conn.WriteJSON(map[string]any{
		"type": "subscribe",
		"data": map[string]string{"channel": channel, "request_id": channel},
	}); err != nil {
		c.t.Fatalf("subscribe write: %v", err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case m, ok := <-c.msgs:
			if !ok {
				c.t.Fatal("connection closed while subscribing")
			}
			switch {
			case m.Type == websocket.MessageTypeSubscribed && m.Channel == channel:
				return true
			case m.Type == websocket.MessageTypeError && m.RequestID == channel:
				return false
			}
		case <-deadline:
			c.t.Fatalf("no reply to subscribe %s", channel)
		}
	}
}

// events collects notification events that arrive within the window.
func (c *wsConn) events(window time.Duration) []map[string]any {
	c.t.Helper()
	var out []map[string]any
	deadline := time.After(window)
	for {
		select {
		case m, ok := <-c.msgs:
			if !ok {
				return out
			}
			if m.Type != websocket.MessageTypeEvent {
				continue
			}
			var data map[string]any
			_ = json.Unmarshal(m.Data, &data)
			if data["type"] == "notification" {
				data["_channel"] = m.Channel
				out = append(out, data)
			}
		case <-deadline:
			return out
		}
	}
}

func titles(evs []map[string]any) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, fmt.Sprint(e["title"]))
	}
	return out
}

func (h *wsHarness) notify(p notification.NotificationParams) {
	h.t.Helper()
	p.TenantID = h.tenantID
	if p.NotificationType == "" {
		p.NotificationType = notification.TypeSystemAlert
	}
	if p.Severity == "" {
		p.Severity = notification.SeverityInfo
	}
	if err := h.svc.Notify(context.Background(), p); err != nil {
		h.t.Fatalf("notify %q: %v", p.Title, err)
	}
}

// watch connects the user and subscribes to every channel a client could try
// for notifications: its own user channel and the tenant channel.
func (h *wsHarness) watch(userID shared.ID) *wsConn {
	h.t.Helper()
	c := h.connect(userID)
	if !c.subscribe(notification.UserChannel(h.tenantID.String(), userID.String())) {
		h.t.Fatalf("user %s refused its own channel", userID)
	}
	if !c.subscribe("tenant:" + h.tenantID.String()) {
		h.t.Fatalf("user %s refused its tenant channel", userID)
	}
	return c
}

const pushWindow = 800 * time.Millisecond

func TestNotificationWS_UserTargetedReachesOnlyThatUser(t *testing.T) {
	h := newWSHarness(t)
	alice, bob := h.member("alice"), h.member("bob")

	a := h.watch(alice)
	b := h.watch(bob)

	// Bob cannot pick Alice's channel, nor the retired per-user channel name.
	if b.subscribe(notification.UserChannel(h.tenantID.String(), alice.String())) {
		t.Fatal("bob was allowed to subscribe to alice's user channel")
	}
	if b.subscribe("notification:" + alice.String()) {
		t.Fatal("bob was allowed to subscribe to notification:{alice}")
	}

	h.notify(notification.NotificationParams{
		Audience: notification.AudienceUser, AudienceID: &alice,
		NotificationType: notification.TypeFindingAssigned, Severity: notification.SeverityHigh,
		Title: "for-alice-only", Body: "assignment details",
	})

	if leaked := b.events(pushWindow); len(leaked) != 0 {
		t.Errorf("bob received a notification addressed to alice: %v", titles(leaked))
	}
	got := a.events(pushWindow)
	if len(got) != 1 || got[0]["title"] != "for-alice-only" {
		t.Fatalf("alice: want exactly her notification, got %v", titles(got))
	}
	if want := notification.UserChannel(h.tenantID.String(), alice.String()); got[0]["_channel"] != want {
		t.Errorf("alice got it on %v, want %s", got[0]["_channel"], want)
	}
}

func TestNotificationWS_GroupTargetedReachesOnlyMembers(t *testing.T) {
	h := newWSHarness(t)
	alice, bob, carol := h.member("alice"), h.member("bob"), h.member("carol")
	gid := h.group(alice, carol)

	a, b, c := h.watch(alice), h.watch(bob), h.watch(carol)

	// Without a membership/permission resolver the group channel is refused,
	// so a non-member cannot reach group traffic that way either.
	if b.subscribe("group:" + gid.String()) {
		t.Fatal("bob was allowed to subscribe to a group channel he is not in")
	}

	h.notify(notification.NotificationParams{
		Audience: notification.AudienceGroup, AudienceID: &gid,
		Title: "for-the-group", Severity: notification.SeverityMedium,
	})

	for name, conn := range map[string]*wsConn{"alice": a, "carol": c} {
		if got := conn.events(pushWindow); len(got) != 1 || got[0]["title"] != "for-the-group" {
			t.Errorf("%s (member): want the group notification, got %v", name, titles(got))
		}
	}
	if leaked := b.events(pushWindow); len(leaked) != 0 {
		t.Fatalf("bob (not a member) received the group notification: %v", titles(leaked))
	}
}

func TestNotificationWS_AudienceAllReachesEveryMemberOnOwnChannel(t *testing.T) {
	h := newWSHarness(t)
	alice, bob := h.member("alice"), h.member("bob")
	a, b := h.watch(alice), h.watch(bob)

	h.notify(notification.NotificationParams{Audience: notification.AudienceAll, Title: "for-everyone"})

	for name, pair := range map[string]struct {
		c   *wsConn
		uid shared.ID
	}{"alice": {a, alice}, "bob": {b, bob}} {
		got := pair.c.events(pushWindow)
		if len(got) != 1 || got[0]["title"] != "for-everyone" {
			t.Fatalf("%s: want the broadcast once, got %v", name, titles(got))
		}
		if want := notification.UserChannel(h.tenantID.String(), pair.uid.String()); got[0]["_channel"] != want {
			t.Errorf("%s got it on %v, want own channel %s", name, got[0]["_channel"], want)
		}
	}
}

// visibleTo returns the titles in the user's inbox and the unread count.
func (h *wsHarness) visibleTo(userID shared.ID) ([]string, int) {
	h.t.Helper()
	ctx := context.Background()
	res, err := h.svc.ListNotifications(ctx, h.tenantID, userID, notification.ListFilter{}, pagination.New(1, 100))
	if err != nil {
		h.t.Fatalf("list: %v", err)
	}
	out := make([]string, 0, len(res.Data))
	for _, n := range res.Data {
		out = append(out, n.Title())
	}
	count, err := h.svc.GetUnreadCount(ctx, h.tenantID, userID)
	if err != nil {
		h.t.Fatalf("unread count: %v", err)
	}
	return out, count
}

func TestNotificationPreferences_AppliedToListCountAndPush(t *testing.T) {
	inAppOff := false
	high := notification.SeverityHigh

	cases := []struct {
		name  string
		prefs integrationsvc.UpdatePreferencesInput
		// sent notifications (type, severity, title) and which titles the
		// user must still see.
		send []notification.NotificationParams
		want []string
	}{
		{
			name:  "in-app disabled",
			prefs: integrationsvc.UpdatePreferencesInput{InAppEnabled: &inAppOff},
			send: []notification.NotificationParams{
				{Title: "crit", Severity: notification.SeverityCritical},
				{Title: "info", Severity: notification.SeverityInfo},
			},
			want: nil,
		},
		{
			name:  "muted type",
			prefs: integrationsvc.UpdatePreferencesInput{MutedTypes: []string{notification.TypeScanCompleted}},
			send: []notification.NotificationParams{
				{Title: "scan-done", NotificationType: notification.TypeScanCompleted},
				{Title: "scan-failed", NotificationType: notification.TypeScanFailed},
			},
			want: []string{"scan-failed"},
		},
		{
			name:  "minimum severity high",
			prefs: integrationsvc.UpdatePreferencesInput{MinSeverity: &high},
			send: []notification.NotificationParams{
				{Title: "sev-critical", Severity: notification.SeverityCritical},
				{Title: "sev-high", Severity: notification.SeverityHigh},
				{Title: "sev-medium", Severity: notification.SeverityMedium},
				{Title: "sev-info", Severity: notification.SeverityInfo},
			},
			want: []string{"sev-critical", "sev-high"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newWSHarness(t)
			alice, bob := h.member("alice"), h.member("bob")
			if _, err := h.svc.UpdatePreferences(context.Background(), h.tenantID, bob, tc.prefs); err != nil {
				t.Fatalf("save preferences: %v", err)
			}
			a, b := h.watch(alice), h.watch(bob)

			sent := make([]string, 0, len(tc.send))
			for _, p := range tc.send {
				p.Audience = notification.AudienceAll
				h.notify(p)
				sent = append(sent, p.Title)
			}

			// Bob (with the preference): list, badge and push all agree.
			list, count := h.visibleTo(bob)
			pushed := titles(b.events(pushWindow))
			if !sameSet(list, tc.want) {
				t.Errorf("bob list = %v, want %v", list, tc.want)
			}
			if count != len(tc.want) {
				t.Errorf("bob unread count = %d, want %d", count, len(tc.want))
			}
			if !sameSet(pushed, tc.want) {
				t.Errorf("bob push = %v, want %v", pushed, tc.want)
			}

			// Alice (defaults) still gets everything: the filter is per user.
			list, count = h.visibleTo(alice)
			if !sameSet(list, sent) || count != len(sent) {
				t.Errorf("alice list = %v (unread %d), want all of %v", list, count, sent)
			}
			if pushed := titles(a.events(pushWindow)); !sameSet(pushed, sent) {
				t.Errorf("alice push = %v, want %v", pushed, sent)
			}
		})
	}
}

// The SQL filter is the twin of Preferences.Allows; check every combination
// of stored preference and notification against the Go definition.
func TestNotificationPreferences_SQLMatchesDomainRule(t *testing.T) {
	h := newWSHarness(t)
	ctx := context.Background()
	severities := []string{
		notification.SeverityCritical, notification.SeverityHigh, notification.SeverityMedium,
		notification.SeverityLow, notification.SeverityInfo,
	}
	types := []string{notification.TypeFindingNew, notification.TypeScanFailed}
	for _, typ := range types {
		for _, sev := range severities {
			h.notify(notification.NotificationParams{
				Audience: notification.AudienceAll, NotificationType: typ, Severity: sev,
				Title: typ + "/" + sev,
			})
		}
	}

	off, on := false, true
	prefSets := []integrationsvc.UpdatePreferencesInput{{InAppEnabled: &on}, {InAppEnabled: &off}}
	for _, sev := range append([]string{""}, severities...) {
		s := sev
		prefSets = append(prefSets, integrationsvc.UpdatePreferencesInput{MinSeverity: &s, MutedTypes: []string{notification.TypeScanFailed}})
	}

	for i, in := range prefSets {
		uid := h.member(fmt.Sprintf("parity%d", i))
		prefs, err := h.svc.UpdatePreferences(ctx, h.tenantID, uid, in)
		if err != nil {
			t.Fatalf("save preferences %d: %v", i, err)
		}
		var want []string
		for _, typ := range types {
			for _, sev := range severities {
				if prefs.Allows(typ, sev) {
					want = append(want, typ+"/"+sev)
				}
			}
		}
		got, count := h.visibleTo(uid)
		if !sameSet(got, want) || count != len(want) {
			t.Errorf("prefs %d (in_app=%v min=%q muted=%v): list %v (unread %d), want %v",
				i, prefs.InAppEnabled(), prefs.MinSeverity(), prefs.MutedTypes(), got, count, want)
		}
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		if seen[s] == 0 {
			return false
		}
		seen[s]--
	}
	return true
}
