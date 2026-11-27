package bountyprogram

import (
	"context"
	"testing"

	bp "github.com/openctemio/openctem/server/pkg/domain/bountyprogram"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
)

// A widening sync and a suspension carry their language-neutral messages.
func TestSync_NoticeMessages(t *testing.T) {
	ctx := context.Background()
	svc, _, fetch, p, user := syncService(t)
	n := &notes{}
	svc.SetNotifier(n)
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"}); err != nil {
		t.Fatal(err)
	}
	fetch.text = "*.acme.example\nacme.example\n-admin.acme.example\nshop.acme.example\napi.other.example\n"
	if _, err := svc.Sync(ctx, p.TenantID, user, p.ID); err != nil {
		t.Fatal(err)
	}
	if len(n.msgs) != 1 || n.msgs[0] == nil || n.msgs[0].Code != "program.scope_changed" ||
		n.msgs[0].Params["program"] != p.Name || n.msgs[0].Params["count"] != 1 {
		t.Fatalf("widening message = %+v", n.msgs)
	}

	fetch.open = false
	if res, err := svc.Sync(ctx, p.TenantID, user, p.ID); err != nil || !res.Suspended {
		t.Fatalf("closed: %+v %v", res, err)
	}
	m := n.msgs[len(n.msgs)-1]
	r, _ := m.Params["reason"].(*notificationdom.Message)
	if m.Code != "program.suspended" || m.Params["program"] != p.Name || r == nil || r.Code != "program.suspend_reason.no_submissions" {
		t.Fatalf("suspension message = %+v", m)
	}
}
