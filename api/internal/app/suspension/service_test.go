package suspension

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeStore struct {
	mu      sync.Mutex
	status  map[string]tenantdom.OrganizationStatus
	reads   int
	readErr error
	by      *shared.ID
	reason  string
}

func newFakeStore() *fakeStore {
	return &fakeStore{status: map[string]tenantdom.OrganizationStatus{}}
}

func (f *fakeStore) OrganizationStatus(_ context.Context, id shared.ID) (tenantdom.OrganizationStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.readErr != nil {
		return "", f.readErr
	}
	s, ok := f.status[id.String()]
	if !ok {
		return "", shared.ErrNotFound
	}
	return s, nil
}

func (f *fakeStore) Suspension(_ context.Context, id shared.ID) (*tenantdom.Suspension, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.status[id.String()]
	if !ok {
		return nil, "", shared.ErrNotFound
	}
	return &tenantdom.Suspension{Status: s, By: f.by, Reason: f.reason}, "Acme", nil
}

func (f *fakeStore) Suspend(_ context.Context, id shared.ID, by *shared.ID, reason string, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status[id.String()] != tenantdom.OrganizationActive {
		return false, nil
	}
	f.status[id.String()], f.by, f.reason = tenantdom.OrganizationSuspended, by, reason
	return true, nil
}

func (f *fakeStore) Unsuspend(_ context.Context, id shared.ID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status[id.String()] != tenantdom.OrganizationSuspended {
		return false, nil
	}
	f.status[id.String()], f.by, f.reason = tenantdom.OrganizationActive, nil, ""
	return true, nil
}

type mapCache struct {
	mu   sync.Mutex
	m    map[string]CachedStatus
	fail bool
}

func (c *mapCache) Get(_ context.Context, key string) (*CachedStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	if !ok {
		return nil, errors.New("miss")
	}
	return &v, nil
}

func (c *mapCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
	return nil
}

func (c *mapCache) Set(_ context.Context, key string, v CachedStatus) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("down")
	}
	c.m[key] = v
	return nil
}

type adminAuditSpy struct{ rows []*admin.AuditLog }

func (a *adminAuditSpy) Create(_ context.Context, l *admin.AuditLog) error {
	a.rows = append(a.rows, l)
	return nil
}

type tenantAuditSpy struct{ events []auditapp.AuditEvent }

func (a *tenantAuditSpy) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

type socketSpy struct{ closed []string }

func (s *socketSpy) RevokeOrganization(_ context.Context, id string) { s.closed = append(s.closed, id) }

func testAdmin() *admin.AdminUser {
	now := time.Now()
	return admin.Reconstitute(shared.NewID(), "ops@example.com", "Ops", admin.AdminRoleOpsAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
}

func TestGate(t *testing.T) {
	ctx := context.Background()
	id := shared.NewID()

	t.Run("active passes, suspended and unknown are refused", func(t *testing.T) {
		st := newFakeStore()
		st.status[id.String()] = tenantdom.OrganizationActive
		g := NewGate(st, nil, nil)
		if err := g.CheckAccess(ctx, id); err != nil {
			t.Fatalf("active: %v", err)
		}
		st.status[id.String()] = tenantdom.OrganizationSuspended
		if err := g.CheckAccess(ctx, id); !errors.Is(err, tenantdom.ErrOrganizationSuspended) {
			t.Fatalf("suspended: %v", err)
		}
		// Any status other than active is refused (positive check).
		st.status[id.String()] = "pending_something"
		if err := g.CheckAccess(ctx, id); !errors.Is(err, tenantdom.ErrOrganizationSuspended) {
			t.Fatalf("unknown status: %v", err)
		}
		if err := g.CheckAccess(ctx, shared.NewID()); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("missing organization: %v", err)
		}
		if err := g.CheckAccess(ctx, shared.ID{}); err == nil {
			t.Fatal("zero id admitted")
		}
	})

	t.Run("fails closed when the status cannot be read", func(t *testing.T) {
		st := newFakeStore()
		st.readErr = errors.New("db down")
		if err := NewGate(st, nil, nil).CheckAccess(ctx, id); err == nil {
			t.Fatal("unreadable status admitted")
		}
		var nilGate *Gate
		if err := nilGate.CheckAccess(ctx, id); err == nil {
			t.Fatal("unconfigured gate admitted")
		}
	})

	t.Run("cache answers repeat checks; Remember overwrites at once", func(t *testing.T) {
		st := newFakeStore()
		st.status[id.String()] = tenantdom.OrganizationActive
		c := &mapCache{m: map[string]CachedStatus{}}
		g := NewGate(st, c, nil)
		for range 3 {
			if err := g.CheckAccess(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		if st.reads != 1 {
			t.Fatalf("store reads = %d, want 1 (cached)", st.reads)
		}
		g.Remember(ctx, id, tenantdom.OrganizationSuspended)
		if err := g.CheckAccess(ctx, id); !errors.Is(err, tenantdom.ErrOrganizationSuspended) {
			t.Fatalf("after Remember: %v", err)
		}
	})
}

func TestServiceSuspendAndLift(t *testing.T) {
	ctx := context.Background()
	id := shared.NewID()
	setup := func() (*Service, *fakeStore, *mapCache, *adminAuditSpy, *tenantAuditSpy, *socketSpy) {
		st := newFakeStore()
		st.status[id.String()] = tenantdom.OrganizationActive
		c := &mapCache{m: map[string]CachedStatus{}}
		aa, ta, ws := &adminAuditSpy{}, &tenantAuditSpy{}, &socketSpy{}
		s := NewService(st, NewGate(st, c, nil), aa, ta, nil)
		s.SetSocketCloser(ws)
		return s, st, c, aa, ta, ws
	}

	t.Run("suspend: status, cache, sockets, critical audits without the reason for members", func(t *testing.T) {
		s, st, c, aa, ta, ws := setup()
		// Warm the cache with active: the change must overwrite it.
		if err := s.gate.CheckAccess(ctx, id); err != nil {
			t.Fatal(err)
		}
		actor := testAdmin()
		if err := s.Suspend(ctx, actor, id, "  phishing pages reported  ", Client{IP: "203.0.113.9"}); err != nil {
			t.Fatalf("Suspend: %v", err)
		}
		if st.status[id.String()] != tenantdom.OrganizationSuspended || st.reason != "phishing pages reported" || st.by == nil || *st.by != actor.ID() {
			t.Fatalf("store = %v reason=%q by=%v", st.status[id.String()], st.reason, st.by)
		}
		if c.m[id.String()].Status != string(tenantdom.OrganizationSuspended) {
			t.Fatalf("cache not overwritten: %v", c.m)
		}
		if err := s.gate.CheckAccess(ctx, id); !errors.Is(err, tenantdom.ErrOrganizationSuspended) {
			t.Fatalf("gate after suspend: %v", err)
		}
		if len(ws.closed) != 1 || ws.closed[0] != id.String() {
			t.Fatalf("sockets closed = %v", ws.closed)
		}
		if len(aa.rows) != 1 || aa.rows[0].Action != ActionOrganizationSuspended || aa.rows[0].Severity != admin.SeverityCritical {
			t.Fatalf("admin audit = %+v", aa.rows)
		}
		if len(ta.events) != 1 || strings.Contains(ta.events[0].Message, "phishing") {
			t.Fatalf("tenant audit must exist and carry no reason: %+v", ta.events)
		}
	})

	t.Run("lift restores access; double actions conflict", func(t *testing.T) {
		s, _, _, aa, _, ws := setup()
		actor := testAdmin()
		if err := s.Unsuspend(ctx, actor, id, "not suspended", Client{}); !errors.Is(err, ErrNotSuspended) {
			t.Fatalf("unsuspend active: %v", err)
		}
		if err := s.Suspend(ctx, actor, id, "abuse report 42", Client{}); err != nil {
			t.Fatal(err)
		}
		if err := s.Suspend(ctx, actor, id, "abuse report 42", Client{}); !errors.Is(err, ErrAlreadySuspended) {
			t.Fatalf("second suspend: %v", err)
		}
		if err := s.Unsuspend(ctx, actor, id, "resolved with the customer", Client{}); err != nil {
			t.Fatal(err)
		}
		if err := s.gate.CheckAccess(ctx, id); err != nil {
			t.Fatalf("gate after lift: %v", err)
		}
		if len(ws.closed) != 1 {
			t.Fatalf("lifting must not close sockets: %v", ws.closed)
		}
		if last := aa.rows[len(aa.rows)-1]; last.Action != ActionOrganizationUnsuspended || last.Severity != admin.SeverityCritical {
			t.Fatalf("lift audit = %+v", last)
		}
	})

	t.Run("refusals: no reason, too long, system organization, unknown, no actor", func(t *testing.T) {
		s, st, _, aa, _, _ := setup()
		actor := testAdmin()
		for _, r := range []string{"", "   ", "too short", strings.Repeat("x", MaxReasonRunes+1)} {
			if err := s.Suspend(ctx, actor, id, r, Client{}); !errors.Is(err, ErrReasonRequired) {
				t.Fatalf("reason %q: %v", r, err)
			}
		}
		sys, _ := shared.IDFromString(tenantdom.SystemTenantID)
		st.status[sys.String()] = tenantdom.OrganizationActive
		if err := s.Suspend(ctx, actor, sys, "abuse report 42", Client{}); !errors.Is(err, ErrSystemOrganization) {
			t.Fatalf("system organization: %v", err)
		}
		if err := s.Suspend(ctx, actor, shared.NewID(), "abuse report 42", Client{}); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("unknown organization: %v", err)
		}
		if err := s.Suspend(ctx, nil, id, "abuse report 42", Client{}); err == nil {
			t.Fatal("no actor admitted")
		}
		if len(aa.rows) != 0 || st.status[id.String()] != tenantdom.OrganizationActive {
			t.Fatalf("a refused action changed state: rows=%d status=%v", len(aa.rows), st.status[id.String()])
		}
	})
}
