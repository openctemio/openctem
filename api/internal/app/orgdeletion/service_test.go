package orgdeletion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeStore struct {
	owners map[shared.ID]bool
	status map[shared.ID]tenantdom.OrganizationStatus
	due    map[shared.ID]time.Time
}

func newStore() *fakeStore {
	return &fakeStore{owners: map[shared.ID]bool{}, status: map[shared.ID]tenantdom.OrganizationStatus{}, due: map[shared.ID]time.Time{}}
}

func (f *fakeStore) IsActiveOwner(_ context.Context, _, u shared.ID) (bool, error) {
	return f.owners[u], nil
}
func (f *fakeStore) OrganizationName(_ context.Context, id shared.ID) (string, error) {
	if _, ok := f.status[id]; !ok {
		return "", shared.ErrNotFound
	}
	return "Acme", nil
}
func (f *fakeStore) Schedule(_ context.Context, id, _ shared.ID, _, due time.Time) (bool, error) {
	if f.status[id] != tenantdom.OrganizationActive {
		return false, nil
	}
	f.status[id], f.due[id] = tenantdom.OrganizationPendingDeletion, due
	return true, nil
}
func (f *fakeStore) Cancel(_ context.Context, id shared.ID) (bool, error) {
	if f.status[id] != tenantdom.OrganizationPendingDeletion {
		return false, nil
	}
	f.status[id] = tenantdom.OrganizationActive
	delete(f.due, id)
	return true, nil
}
func (f *fakeStore) ListDue(_ context.Context, now time.Time, _ int) ([]shared.ID, error) {
	var out []shared.ID
	for id, d := range f.due {
		if !d.After(now) {
			out = append(out, id)
		}
	}
	return out, nil
}

type fakePurger struct {
	deleted []string
	fail    map[string]bool
}

func (p *fakePurger) DeleteTenant(_ context.Context, _ auditapp.AuditContext, id string) error {
	if p.fail[id] {
		return errors.New("storage down")
	}
	p.deleted = append(p.deleted, id)
	return nil
}

type fakeCache struct {
	last      map[shared.ID]tenantdom.OrganizationStatus
	forgotten []shared.ID
}

func (c *fakeCache) Remember(_ context.Context, id shared.ID, s tenantdom.OrganizationStatus) {
	c.last[id] = s
}
func (c *fakeCache) Forget(_ context.Context, id shared.ID) { c.forgotten = append(c.forgotten, id) }

type sockets struct{ closed []string }

func (s *sockets) RevokeOrganization(_ context.Context, id string) { s.closed = append(s.closed, id) }

type adminRows struct{ rows []*admin.AuditLog }

func (a *adminRows) Create(_ context.Context, l *admin.AuditLog) error {
	a.rows = append(a.rows, l)
	return nil
}

type tenantEvents struct{ events []auditapp.AuditEvent }

func (a *tenantEvents) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

func superAdmin() *admin.AdminUser {
	now := time.Now()
	return admin.Reconstitute(shared.NewID(), "root@example.com", "Root", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
}

type harness struct {
	svc     *Service
	store   *fakeStore
	purger  *fakePurger
	cache   *fakeCache
	sockets *sockets
	admin   *adminRows
	events  *tenantEvents
	now     time.Time
}

func newHarness() *harness {
	h := &harness{store: newStore(), purger: &fakePurger{fail: map[string]bool{}},
		cache: &fakeCache{last: map[shared.ID]tenantdom.OrganizationStatus{}}, sockets: &sockets{},
		admin: &adminRows{}, events: &tenantEvents{}, now: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)}
	h.svc = NewService(h.store, h.purger, h.cache, h.admin, h.events, nil)
	h.svc.SetSocketCloser(h.sockets)
	h.svc.SetClock(func() time.Time { return h.now })
	return h
}

func TestScheduleAndCancel(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	org, owner, member := shared.NewID(), shared.NewID(), shared.NewID()
	h.store.status[org] = tenantdom.OrganizationActive
	h.store.owners[owner] = true

	if _, err := h.svc.Schedule(ctx, auditapp.AuditContext{}, org, member); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("non-owner: %v", err)
	}
	due, err := h.svc.Schedule(ctx, auditapp.AuditContext{}, org, owner)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if !due.Equal(h.now.Add(tenantdom.DeletionGrace)) {
		t.Fatalf("due = %v, want now + 14 days", due)
	}
	if h.cache.last[org] != tenantdom.OrganizationPendingDeletion || len(h.sockets.closed) != 1 {
		t.Fatalf("closing: cache=%v sockets=%v", h.cache.last[org], h.sockets.closed)
	}
	if len(h.events.events) != 1 || h.events.events[0].Action != auditdom.ActionTenantDeletionScheduled {
		t.Fatalf("events = %+v", h.events.events)
	}
	if _, err := h.svc.Schedule(ctx, auditapp.AuditContext{}, org, owner); !errors.Is(err, ErrNotActive) {
		t.Fatalf("second schedule: %v", err)
	}
	// Nothing is deleted before the grace period ends.
	if n, err := h.svc.PurgeDue(ctx); n != 0 || err != nil || len(h.purger.deleted) != 0 {
		t.Fatalf("early purge: %d %v %v", n, err, h.purger.deleted)
	}

	if err := h.svc.Cancel(ctx, auditapp.AuditContext{}, org, member); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("non-owner cancel: %v", err)
	}
	if err := h.svc.Cancel(ctx, auditapp.AuditContext{}, org, owner); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if h.store.status[org] != tenantdom.OrganizationActive || h.cache.last[org] != tenantdom.OrganizationActive {
		t.Fatalf("after cancel: store=%v cache=%v", h.store.status[org], h.cache.last[org])
	}
	if err := h.svc.Cancel(ctx, auditapp.AuditContext{}, org, owner); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second cancel: %v", err)
	}
	sys, _ := shared.IDFromString(tenantdom.SystemTenantID)
	if _, err := h.svc.Schedule(ctx, auditapp.AuditContext{}, sys, owner); !errors.Is(err, ErrSystemOrganization) {
		t.Fatalf("system organization: %v", err)
	}
}

func TestPurgeDue(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	a, b, owner := shared.NewID(), shared.NewID(), shared.NewID()
	h.store.owners[owner] = true
	for _, id := range []shared.ID{a, b} {
		h.store.status[id] = tenantdom.OrganizationActive
		if _, err := h.svc.Schedule(ctx, auditapp.AuditContext{}, id, owner); err != nil {
			t.Fatal(err)
		}
	}
	h.purger.fail[a.String()] = true
	h.now = h.now.Add(tenantdom.DeletionGrace + time.Minute)
	n, err := h.svc.PurgeDue(ctx)
	if n != 1 || err == nil || len(h.purger.deleted) != 1 || h.purger.deleted[0] != b.String() {
		t.Fatalf("purge: n=%d err=%v deleted=%v (one failure must not stop the other)", n, err, h.purger.deleted)
	}
}

func TestPurgeNow(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	org := shared.NewID()
	h.store.status[org] = tenantdom.OrganizationSuspended
	actor := superAdmin()

	for _, r := range []string{"", "short", strings.Repeat("x", MaxReasonRunes+1)} {
		if err := h.svc.PurgeNow(ctx, actor, org, r, Client{}); !errors.Is(err, ErrReasonRequired) {
			t.Fatalf("reason %q: %v", r, err)
		}
	}
	sys, _ := shared.IDFromString(tenantdom.SystemTenantID)
	if err := h.svc.PurgeNow(ctx, actor, sys, "legal request 2026-17", Client{}); !errors.Is(err, ErrSystemOrganization) {
		t.Fatalf("system organization: %v", err)
	}
	if err := h.svc.PurgeNow(ctx, nil, org, "legal request 2026-17", Client{}); err == nil {
		t.Fatal("no administrator admitted")
	}
	if len(h.purger.deleted) != 0 {
		t.Fatal("a refused purge deleted")
	}

	// A failed purge is audited as failed and the cached status forgotten.
	h.purger.fail[org.String()] = true
	if err := h.svc.PurgeNow(ctx, actor, org, "legal request 2026-17", Client{IP: "203.0.113.4"}); err == nil {
		t.Fatal("failure not reported")
	}
	if len(h.cache.forgotten) != 1 || len(h.admin.rows) != 1 || h.admin.rows[0].ResponseStatus != 500 {
		t.Fatalf("failed purge: forgotten=%v rows=%+v", h.cache.forgotten, h.admin.rows)
	}
	h.purger.fail[org.String()] = false
	if err := h.svc.PurgeNow(ctx, actor, org, "legal request 2026-17", Client{}); err != nil {
		t.Fatalf("purge: %v", err)
	}
	last := h.admin.rows[len(h.admin.rows)-1]
	if len(h.purger.deleted) != 1 || last.Action != ActionOrganizationPurged || last.Severity != admin.SeverityCritical {
		t.Fatalf("purge: deleted=%v audit=%+v", h.purger.deleted, last)
	}
}
