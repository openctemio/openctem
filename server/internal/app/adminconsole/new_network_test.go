package adminconsole

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

type networkNotifier struct {
	fakeNotifier
	network []NewNetworkAlert
}

func (n *networkNotifier) NotifyNewNetworkSignIn(_ context.Context, a NewNetworkAlert) error {
	n.network = append(n.network, a)
	return nil
}

// A console sign-in from another address than last time is audited and told
// to every administrator; the same address, a first sign-in and a break-glass
// sign-in (alerted on its own) are not.
func TestNewNetworkSignInAlert(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lastIP string
		want   bool
	}{
		{"new network", "198.51.100.1", true},
		{"same network", client.IP, false},
		{"first sign-in", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			now := time.Now()
			a := admin.Reconstitute(h.admin.ID(), h.admin.Email(), h.admin.Name(), admin.AdminRoleSuperAdmin, true,
				h.admin.UserID(), &now, tc.lastIP, 0, nil, nil, "", now, nil, now)
			h.admins.byID[a.ID().String()] = a
			h.admin = a
			n := &networkNotifier{}
			h.svc.SetBreakGlassNotifier(n)

			h.enroll(t)

			if got := h.audit.has(ActionNewNetworkSignIn); got != tc.want {
				t.Fatalf("audited new-network sign-in = %v, want %v (%v)", got, tc.want, h.audit.actions)
			}
			if tc.want {
				if len(n.network) != 1 || n.network[0].IP != client.IP || n.network[0].PreviousIP != tc.lastIP ||
					len(n.network[0].Recipients) != 1 || n.network[0].Recipients[0] != a.Email() {
					t.Fatalf("alert: %+v", n.network)
				}
			} else if len(n.network) != 0 {
				t.Fatalf("unexpected alert: %+v", n.network)
			}
		})
	}
}
