package tool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type countingSources struct {
	tooldom.TenantToolConfigRepository
	calls    atomic.Int32
	failNext atomic.Bool
	zones    map[shared.ID][]*scanzone.Zone // by tenant
}

func (c *countingSources) ListToolsWithConfig(_ context.Context, _ shared.ID, _ tooldom.ToolFilter, _ pagination.Pagination) (pagination.Result[*tooldom.ToolWithConfig], error) {
	c.calls.Add(1)
	if c.failNext.CompareAndSwap(true, false) {
		return pagination.Result[*tooldom.ToolWithConfig]{}, errors.New("db down")
	}
	return pagination.Result[*tooldom.ToolWithConfig]{}, nil
}
func (c *countingSources) ListAllSensors(context.Context, string) ([]*sensor.Sensor, error) {
	c.calls.Add(1)
	return nil, nil
}

type zoneSource struct{ c *countingSources }

func (z zoneSource) List(_ context.Context, tenantID shared.ID) ([]*scanzone.Zone, error) {
	z.c.calls.Add(1)
	return z.c.zones[tenantID], nil
}
func (c *countingSources) ListByTenant(context.Context, shared.ID) (map[shared.ID]*sensor.Grant, error) {
	c.calls.Add(1)
	return nil, nil
}
func (c *countingSources) CurrentManifestsByTenant(context.Context, shared.ID) (map[shared.ID]*sensor.ManifestVersion, error) {
	c.calls.Add(1)
	return nil, nil
}

// reads per uncached ToolAvailability: catalog, sensors, zones, grants, manifests.
const readsPerView = 5

func newMemoService(src *countingSources) *Service {
	s := &Service{configRepo: src, logger: logger.NewNop()}
	s.SetAvailabilitySources(src, zoneSource{src}, src)
	s.SetManifestSource(src)
	return s
}

func TestToolAvailabilityMemo(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	za, zb := shared.NewID(), shared.NewID()
	newSrc := func() *countingSources {
		return &countingSources{zones: map[shared.ID][]*scanzone.Zone{
			a: {{ID: za, TenantID: a, Name: "A"}},
			b: {{ID: zb, TenantID: b, Name: "B"}},
		}}
	}

	t.Run("same tenant computed once", func(t *testing.T) {
		src := newSrc()
		s := newMemoService(src)
		ctx := WithAvailabilityMemo(context.Background())
		for i := 0; i < 3; i++ {
			if _, err := s.ToolAvailability(ctx, a.String(), ""); err != nil {
				t.Fatal(err)
			}
		}
		if got := src.calls.Load(); got != readsPerView {
			t.Fatalf("repo reads = %d, want %d", got, readsPerView)
		}
	})

	t.Run("nested memo reuses the outer one", func(t *testing.T) {
		src := newSrc()
		s := newMemoService(src)
		ctx := WithAvailabilityMemo(context.Background())
		if WithAvailabilityMemo(ctx) != ctx {
			t.Fatal("nested WithAvailabilityMemo must return ctx unchanged")
		}
		_, _ = s.ToolAvailability(ctx, a.String(), "")
		_, _ = s.ToolAvailability(WithAvailabilityMemo(ctx), a.String(), "")
		if got := src.calls.Load(); got != readsPerView {
			t.Fatalf("repo reads = %d, want %d", got, readsPerView)
		}
	})

	t.Run("other tenant never gets this tenant's result", func(t *testing.T) {
		src := newSrc()
		s := newMemoService(src)
		ctx := WithAvailabilityMemo(context.Background())
		ra, err := s.ToolAvailability(ctx, a.String(), "")
		if err != nil {
			t.Fatal(err)
		}
		rb, err := s.ToolAvailability(ctx, b.String(), "")
		if err != nil {
			t.Fatal(err)
		}
		if ra == rb {
			t.Fatal("tenant B received tenant A's memoised result")
		}
		if got := src.calls.Load(); got != 2*readsPerView {
			t.Fatalf("repo reads = %d, want %d", got, 2*readsPerView)
		}
		// Tenant B asking for tenant A's zone must still be not found, memo or not.
		if _, err := s.ToolAvailability(ctx, b.String(), za.String()); !errors.Is(err, ErrZoneNotFound) {
			t.Fatalf("foreign zone: err = %v, want ErrZoneNotFound", err)
		}
	})

	t.Run("zones are separate entries", func(t *testing.T) {
		src := newSrc()
		s := newMemoService(src)
		ctx := WithAvailabilityMemo(context.Background())
		r1, _ := s.ToolAvailability(ctx, a.String(), "")
		r2, err := s.ToolAvailability(ctx, a.String(), za.String())
		if err != nil {
			t.Fatal(err)
		}
		if r1 == r2 || r2.ZoneID == nil || *r2.ZoneID != za {
			t.Fatal("zone view must not reuse the all-zones view")
		}
		if got := src.calls.Load(); got != 2*readsPerView {
			t.Fatalf("repo reads = %d, want %d", got, 2*readsPerView)
		}
	})

	t.Run("no memo computes every time", func(t *testing.T) {
		src := newSrc()
		s := newMemoService(src)
		for i := 0; i < 3; i++ {
			_, _ = s.ToolAvailability(context.Background(), a.String(), "")
		}
		if got := src.calls.Load(); got != 3*readsPerView {
			t.Fatalf("repo reads = %d, want %d", got, 3*readsPerView)
		}
	})

	t.Run("errors are not cached", func(t *testing.T) {
		src := newSrc()
		s := newMemoService(src)
		ctx := WithAvailabilityMemo(context.Background())
		src.failNext.Store(true)
		if _, err := s.ToolAvailability(ctx, a.String(), ""); err == nil {
			t.Fatal("first call should fail")
		}
		if _, err := s.ToolAvailability(ctx, a.String(), ""); err != nil {
			t.Fatalf("second call should succeed: %v", err)
		}
	})
}
