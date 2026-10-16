package instancezone

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	zonedom "github.com/openctemio/openctem/api/pkg/domain/instancezone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// memRepo is a zone repository in memory.
type memRepo struct {
	zones   map[shared.ID]*zonedom.Zone
	failSet bool
}

func newRepo() *memRepo { return &memRepo{zones: map[shared.ID]*zonedom.Zone{}} }

func (m *memRepo) Create(_ context.Context, z *zonedom.Zone, _ *shared.ID) error {
	c := *z
	m.zones[z.ID] = &c
	return nil
}
func (m *memRepo) Update(_ context.Context, z *zonedom.Zone) error {
	if _, ok := m.zones[z.ID]; !ok {
		return zonedom.ErrNotFound
	}
	c := *z
	m.zones[z.ID] = &c
	return nil
}
func (m *memRepo) Delete(_ context.Context, id shared.ID) error {
	if _, ok := m.zones[id]; !ok {
		return zonedom.ErrNotFound
	}
	delete(m.zones, id)
	return nil
}
func (m *memRepo) Get(_ context.Context, id shared.ID) (*zonedom.Zone, error) {
	z, ok := m.zones[id]
	if !ok {
		return nil, zonedom.ErrNotFound
	}
	c := *z
	c.SensorIDs, c.TenantIDs = slices.Clone(z.SensorIDs), slices.Clone(z.TenantIDs)
	return &c, nil
}
func (m *memRepo) List(context.Context) ([]*zonedom.Zone, error) { return nil, nil }
func (m *memRepo) SetSensors(_ context.Context, id shared.ID, ids []shared.ID, _ *shared.ID) error {
	if m.failSet {
		return errors.New("db down")
	}
	m.zones[id].SensorIDs = slices.Clone(ids)
	return nil
}
func (m *memRepo) SetTenants(_ context.Context, id shared.ID, ids []shared.ID, _ *shared.ID) error {
	if m.failSet {
		return errors.New("db down")
	}
	m.zones[id].TenantIDs = slices.Clone(ids)
	return nil
}

// ListForTenant deliberately returns every zone: the service must still
// keep only the organization's own (defense in depth).
func (m *memRepo) ListForTenant(context.Context, shared.ID) ([]*zonedom.Zone, error) {
	out := make([]*zonedom.Zone, 0, len(m.zones))
	for _, z := range m.zones {
		c := *z
		out = append(out, &c)
	}
	return out, nil
}

type memLedger struct {
	changes []jobsign.ZoneChange
	fail    bool
}

func (l *memLedger) ApplyZone(_ context.Context, ch jobsign.ZoneChange) (jobsign.ZoneChangeResult, error) {
	if l.fail {
		return jobsign.ZoneChangeResult{}, errors.New("signer unreachable")
	}
	l.changes = append(l.changes, ch)
	return jobsign.ZoneChangeResult{}, nil
}

type policy bool

func (p policy) SharedSensorsInternalZonesAllowed(context.Context) bool { return bool(p) }

func change(t *testing.T) Change {
	t.Helper()
	a, err := admin.NewAdminUser("root@example.com", "Root", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return Change{Actor: a, Reason: "central scanners"}
}

// Organization A cannot use organization B's zone, even when both zones
// cover the same private range: the zone tells them apart.
func TestZoneFor_CrossOrganizationAndOverlap(t *testing.T) {
	ctx := context.Background()
	repo, ledger := newRepo(), &memLedger{}
	s := NewService(repo, ledger, policy(true), nil, nil)
	c := change(t)
	orgA, orgB, sensor := shared.NewID(), shared.NewID(), shared.NewID()

	za, err := s.Create(ctx, "A office", "", []string{"10.20.0.0/16"}, c)
	if err != nil {
		t.Fatal(err)
	}
	zb, err := s.Create(ctx, "B office", "", []string{"10.20.0.0/16"}, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, z := range []*zonedom.Zone{za, zb} {
		if _, err := s.SetSensors(ctx, z.ID, []shared.ID{sensor}, c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetTenants(ctx, za.ID, []shared.ID{orgA}, c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetTenants(ctx, zb.ID, []shared.ID{orgB}, c); err != nil {
		t.Fatal(err)
	}

	got, err := s.ZoneFor(ctx, orgA, []string{"10.20.1.5"})
	if err != nil || got == nil || got.ID != za.ID {
		t.Fatalf("A's target routed to %v (%v), want A's zone", got, err)
	}
	got, _ = s.ZoneFor(ctx, orgB, []string{"10.20.1.5"})
	if got == nil || got.ID != zb.ID {
		t.Fatalf("B's target routed to %v, want B's zone", got)
	}
	// An organization with no zone gets none.
	if got, _ := s.ZoneFor(ctx, shared.NewID(), []string{"10.20.1.5"}); got != nil {
		t.Fatalf("an unassigned organization got zone %v", got.ID)
	}
	// Outside the zone, or a name: none.
	if got, _ := s.ZoneFor(ctx, orgA, []string{"10.21.0.1"}); got != nil {
		t.Fatal("target outside the zone routed")
	}
	if got, _ := s.ZoneFor(ctx, orgA, []string{"db.internal"}); got != nil {
		t.Fatal("an internal name routed into a zone")
	}
	// Setting off (hosted default): none.
	off := NewService(repo, ledger, policy(false), nil, nil)
	if got, _ := off.ZoneFor(ctx, orgA, []string{"10.20.1.5"}); got != nil {
		t.Fatal("zone used while internal zones are off")
	}
	// No policy wired: none (fail closed).
	if got, _ := NewService(repo, ledger, nil, nil, nil).ZoneFor(ctx, orgA, []string{"10.20.1.5"}); got != nil {
		t.Fatal("zone used without a policy")
	}
	// A zone without sensors serves nobody.
	if _, err := s.SetSensors(ctx, za.ID, nil, c); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ZoneFor(ctx, orgA, []string{"10.20.1.5"}); got != nil {
		t.Fatal("a zone without sensors routed")
	}
}

// The signer records every change before the database; an unreachable
// signer refuses the change and nothing is stored.
func TestChangesGoToTheSignerFirst(t *testing.T) {
	ctx := context.Background()
	repo, ledger := newRepo(), &memLedger{}
	s := NewService(repo, ledger, policy(true), nil, nil)
	c := change(t)
	z, err := s.Create(ctx, "HQ", "", []string{"192.168.0.0/16"}, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.changes) != 1 || ledger.changes[0].Put == nil || ledger.changes[0].Requester != "root@example.com" {
		t.Fatalf("signer changes = %+v", ledger.changes)
	}
	org := shared.NewID()
	ledger.fail = true
	if _, err := s.SetTenants(ctx, z.ID, []shared.ID{org}, c); !errors.Is(err, ErrSignerRefused) {
		t.Fatalf("err = %v, want ErrSignerRefused", err)
	}
	if stored, _ := repo.Get(ctx, z.ID); len(stored.TenantIDs) != 0 {
		t.Fatal("assignment stored although the signer refused it")
	}
	if _, err := s.Create(ctx, "Lab", "", []string{"10.0.0.0/8"}, c); !errors.Is(err, ErrSignerRefused) {
		t.Fatalf("create with signer down: %v", err)
	}
	if len(repo.zones) != 1 {
		t.Fatal("zone created although the signer refused it")
	}
	// A failed save puts the signer back to what the database holds.
	ledger.fail, repo.failSet = false, true
	before := len(ledger.changes)
	if _, err := s.SetTenants(ctx, z.ID, []shared.ID{org}, c); err == nil {
		t.Fatal("save failure not reported")
	}
	if len(ledger.changes) != before+2 || len(ledger.changes[before+1].Put.Tenants) != 0 {
		t.Fatalf("signer not restored: %+v", ledger.changes[before:])
	}
	// Changes need an actor and a reason.
	if _, err := s.Create(ctx, "X", "", []string{"10.0.0.0/8"}, Change{Reason: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := s.Create(ctx, "X", "", []string{"10.0.0.0/8"}, Change{Actor: c.Actor}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	// Delete goes to the signer as a delete.
	repo.failSet = false
	if err := s.Delete(ctx, z.ID, c); err != nil {
		t.Fatal(err)
	}
	if last := ledger.changes[len(ledger.changes)-1]; last.DeleteID != z.ID.String() {
		t.Fatalf("last signer change = %+v", last)
	}
	if _, err := s.StatementZone(ctx, z.ID); err == nil {
		t.Fatal("a deleted zone still gives a statement zone")
	}
}
