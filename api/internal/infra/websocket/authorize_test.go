package websocket

import (
	"context"
	"errors"
	"testing"

	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeAccess struct {
	perms   map[string]bool // permission -> granted
	groups  map[string]bool // group id -> member
	hidden  map[string]bool // finding id -> outside the user's data scope
	runs    map[string]bool // run id -> the user may read it (another tenant's or out of scope: absent)
	failAll bool
}

func (f fakeAccess) CanSeeRun(_ context.Context, _, _, runID string) (bool, error) {
	if f.failAll {
		return false, errors.New("lookup failed")
	}
	return f.runs[runID], nil
}

func (f fakeAccess) CanSeeFinding(_ context.Context, _, _, findingID string) (bool, error) {
	if f.failAll {
		return false, errors.New("lookup failed")
	}
	return !f.hidden[findingID], nil
}

func (f fakeAccess) HasPermission(_ context.Context, _, _, perm string) (bool, error) {
	if f.failAll {
		return false, errors.New("lookup failed")
	}
	return f.perms[perm], nil
}

func (f fakeAccess) IsGroupMember(_ context.Context, _, groupID, _ string) (bool, error) {
	if f.failAll {
		return false, errors.New("lookup failed")
	}
	return f.groups[groupID], nil
}

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
	alice   = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	bob     = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

func TestDefaultAuthorize_Channels(t *testing.T) {
	member := fakeAccess{
		perms:  map[string]bool{permission.FindingsRead.String(): true},
		groups: map[string]bool{"g-mine": true},
		hidden: map[string]bool{"f-other-group": true},
	}
	noPerms := fakeAccess{}
	runReader := fakeAccess{
		perms: map[string]bool{permission.ScansRead.String(): true},
		runs:  map[string]bool{"r-mine": true},
	}

	cases := []struct {
		name    string
		access  ChannelAccessChecker
		channel string
		want    bool
	}{
		// A user's own notification channel, and nobody else's.
		{"own user channel", noPerms, notificationdom.UserChannel(tenantA, alice), true},
		{"another user's channel", noPerms, notificationdom.UserChannel(tenantA, bob), false},
		{"own user id in another tenant", noPerms, notificationdom.UserChannel(tenantB, alice), false},
		{"user channel with suffix", noPerms, notificationdom.UserChannel(tenantA, alice) + ":x", false},
		{"bare user prefix", noPerms, "user:" + tenantA, false},
		// Retired channel names are refused.
		{"notification channel retired", noPerms, "notification:" + alice, false},
		{"notification tenant channel retired", noPerms, "notification:" + tenantA, false},
		// Tenant channel: own tenant only.
		{"own tenant channel", noPerms, "tenant:" + tenantA, true},
		{"other tenant channel", noPerms, "tenant:" + tenantB, false},
		// Permission-scoped channels.
		{"finding with findings:read", member, "finding:f1", true},
		{"finding without findings:read", noPerms, "finding:f1", false},
		{"triage with findings:read", member, "triage:f1", true},
		{"triage without findings:read", noPerms, "triage:f1", false},
		// Layer 2 data scope: a finding outside the user's groups is refused.
		{"finding outside data scope", member, "finding:f-other-group", false},
		{"triage outside data scope", member, "triage:f-other-group", false},
		{"scan without scans:read", member, "scan:s1", false},
		{"group member", member, "group:g-mine", true},
		{"group non-member without groups:read", member, "group:g-other", false},
		{"group non-member with groups:read", fakeAccess{perms: map[string]bool{permission.GroupsRead.String(): true}}, "group:g-other", true},
		// A run's change notices: scans:read and a run the user may read.
		{"own run with scans:read", runReader, "run:r-mine", true},
		{"run of another tenant or out of scope", runReader, "run:r-other", false},
		{"own run without scans:read", fakeAccess{runs: map[string]bool{"r-mine": true}}, "run:r-mine", false},
		{"no checker: run refused", nil, "run:r-mine", false},
		{"run lookup error refused", fakeAccess{perms: runReader.perms, failAll: true}, "run:r-mine", false},
		// Fail closed.
		{"no checker: finding refused", nil, "finding:f1", false},
		{"no checker: group refused", nil, "group:g-mine", false},
		{"lookup error refused", fakeAccess{failAll: true}, "finding:f1", false},
		{"unknown type", member, "admin:" + tenantA, false},
		{"empty id", member, "finding:", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHub(logger.NewNop())
			if tc.access != nil {
				h.SetChannelAccessChecker(tc.access)
			}
			c := &Client{UserID: alice, TenantID: tenantA}
			if got := h.authorizeSubscription(c, tc.channel); got != tc.want {
				t.Errorf("authorize(%q) = %v, want %v", tc.channel, got, tc.want)
			}
		})
	}
}

func TestDefaultAuthorize_UnauthenticatedClientRefused(t *testing.T) {
	h := NewHub(logger.NewNop())
	for _, c := range []*Client{{TenantID: tenantA}, {UserID: alice}} {
		if h.authorizeSubscription(c, "tenant:"+tenantA) {
			t.Errorf("client %+v without full identity was authorized", c)
		}
	}
}

// Even if a client were subscribed to someone else's user channel (a bug in
// authorization, or a future code path that subscribes server-side), the
// broadcast must still only reach the channel's owner.
func TestBroadcast_UserChannelDeliveredOnlyToOwner(t *testing.T) {
	h := NewHub(logger.NewNop())
	owner := &Client{UserID: alice, TenantID: tenantA, send: make(chan []byte, 1), subscriptions: map[string]bool{}, logger: logger.NewNop()}
	other := &Client{UserID: bob, TenantID: tenantA, send: make(chan []byte, 1), subscriptions: map[string]bool{}, logger: logger.NewNop()}

	ch := notificationdom.UserChannel(tenantA, alice)
	h.subscribeToChannel(owner, ch)
	h.subscribeToChannel(other, ch) // forced, bypassing authorization

	h.broadcastToChannel(&BroadcastMessage{Channel: ch, Message: NewMessage(MessageTypeEvent).WithChannel(ch), TenantID: tenantA})

	if len(owner.send) != 1 {
		t.Errorf("owner should receive its notification, got %d messages", len(owner.send))
	}
	if len(other.send) != 0 {
		t.Errorf("another user received a message on %s", ch)
	}
}
