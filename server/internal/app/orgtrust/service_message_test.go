package orgtrust

import (
	"context"
	"sync"
	"testing"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type msgTrusts struct {
	mu sync.Mutex
	m  map[shared.ID]*orgtrust.Trust
}

func (r *msgTrusts) Create(_ context.Context, t *orgtrust.Trust) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[t.ID] = t
	return nil
}
func (r *msgTrusts) Update(context.Context, *orgtrust.Trust) error { return nil }
func (r *msgTrusts) GetForTenant(_ context.Context, _, id shared.ID) (*orgtrust.Trust, error) {
	return r.m[id], nil
}
func (r *msgTrusts) GetPair(context.Context, shared.ID, shared.ID) (*orgtrust.Trust, error) {
	return nil, orgtrust.ErrNotFound
}
func (r *msgTrusts) ListForTenant(context.Context, shared.ID) ([]*orgtrust.Trust, error) {
	return nil, nil
}
func (r *msgTrusts) Delete(_ context.Context, _, id shared.ID) error {
	delete(r.m, id)
	return nil
}

type homeOwner struct{ home shared.ID }

func (h homeOwner) OwnerOfDomain(context.Context, string) (shared.ID, bool, error) {
	return h.home, true, nil
}

type noteMembers struct {
	names map[shared.ID]string
	to    []shared.ID
	msgs  []*notificationdom.Message
}

func (n *noteMembers) SuspendExternalMembersFromHome(context.Context, shared.ID, shared.ID, string) (int, error) {
	return 0, nil
}
func (n *noteMembers) NotifyAdminsMsg(_ context.Context, id shared.ID, msg *notificationdom.Message, _, _, _ string) {
	n.to = append(n.to, id)
	n.msgs = append(n.msgs, msg)
}
func (n *noteMembers) TenantName(_ context.Context, id shared.ID) string { return n.names[id] }

func TestTrustNotices_MessageCodes(t *testing.T) {
	ctx := context.Background()
	host, home, actor := shared.NewID(), shared.NewID(), shared.NewID()
	members := &noteMembers{names: map[shared.ID]string{host: "Host Co", home: "Home Co"}}
	svc := NewService(&msgTrusts{m: map[shared.ID]*orgtrust.Trust{}}, homeOwner{home}, members, nil, logger.NewNop())

	v, err := svc.Request(ctx, host, actor, "home.example", orgtrust.DefaultSettings(), auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if m := members.msgs[0]; members.to[0] != home || m == nil || m.Code != "trust.requested" || m.Params["org"] != "Host Co" {
		t.Fatalf("requested: to %v msg %+v", members.to, m)
	}
	if _, err := svc.Accept(ctx, home, v.Trust.ID, actor, false, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if m := members.msgs[1]; members.to[1] != host || m == nil || m.Code != "trust.accepted" || m.Params["org"] != "Home Co" {
		t.Fatalf("accepted: to %v msg %+v", members.to, m)
	}
	if err := svc.Revoke(ctx, host, v.Trust.ID, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if m := members.msgs[2]; members.to[2] != home || m == nil || m.Code != "trust.ended" || m.Params["org"] != "Host Co" {
		t.Fatalf("ended: to %v msg %+v", members.to, m)
	}
}
