package assetdiscovery

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app/outbox"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeOutbox struct {
	mu    sync.Mutex
	items []outbox.EnqueueParams
}

func (f *fakeOutbox) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items = append(f.items, p)
	return nil
}

type fakeInApp struct {
	mu    sync.Mutex
	items []notification.NotificationParams
}

func (f *fakeInApp) Notify(_ context.Context, p notification.NotificationParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items = append(f.items, p)
	return nil
}

// manualClock replaces time.AfterFunc: windows only close when the test says.
type manualClock struct {
	pending []*manualTimer
}

type manualTimer struct {
	f       func()
	stopped bool
}

func (t *manualTimer) Stop() bool { t.stopped = true; return true }

func (c *manualClock) afterFunc(_ time.Duration, f func()) timer {
	t := &manualTimer{f: f}
	c.pending = append(c.pending, t)
	return t
}

// fire closes every open window once.
func (c *manualClock) fire() {
	due := c.pending
	c.pending = nil
	for _, t := range due {
		if !t.stopped {
			t.f()
		}
	}
}

func newTestNotifier() (*Notifier, *fakeOutbox, *fakeInApp, *manualClock) {
	o, in, clk := &fakeOutbox{}, &fakeInApp{}, &manualClock{}
	n := NewNotifier(o, in, time.Minute, logger.NewNop())
	n.afterFunc = clk.afterFunc
	return n, o, in, clk
}

func publicAsset(t *testing.T, tenant shared.ID, name string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenant, name, asset.AssetTypeDomain, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.SetExposure(asset.ExposurePublic)
	return a
}

func internalAsset(t *testing.T, tenant shared.ID, name string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenant, name, asset.AssetTypeHost, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNotifier_FirstDiscoveryNotifiesImmediately(t *testing.T) {
	n, o, in, _ := newTestNotifier()
	tenant := shared.NewID()
	a := publicAsset(t, tenant, "api.example.com")

	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{a})

	if len(o.items) != 1 || len(in.items) != 1 {
		t.Fatalf("outbox=%d inapp=%d, want 1/1", len(o.items), len(in.items))
	}
	ob := o.items[0]
	if ob.TenantID != tenant || ob.EventType != string(integration.EventTypeNewAsset) {
		t.Fatalf("outbox params %+v", ob)
	}
	if ob.AggregateID == nil || ob.AggregateID.String() != a.ID().String() {
		t.Fatal("single-asset notification should reference the asset")
	}
	ia := in.items[0]
	if ia.TenantID != tenant || ia.NotificationType != notification.TypeAssetDiscovered || ia.Audience != notification.AudienceAll {
		t.Fatalf("in-app params %+v", ia)
	}
	if !strings.Contains(ia.Title, "api.example.com") {
		t.Fatalf("title %q does not name the asset", ia.Title)
	}
}

func TestNotifier_InternalAssetsNeverNotify(t *testing.T) {
	n, o, in, clk := newTestNotifier()
	tenant := shared.NewID()
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{internalAsset(t, tenant, "10.0.0.7")})
	clk.fire()
	if len(o.items)+len(in.items) != 0 {
		t.Fatalf("internal asset produced %d notifications", len(o.items)+len(in.items))
	}
}

// A large recon run arrives as many batches: one immediate notice, then ONE
// summary per window, never one per asset.
func TestNotifier_LargeRunIsCoalescedPerWindow(t *testing.T) {
	n, o, in, clk := newTestNotifier()
	tenant := shared.NewID()

	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "first.example.com")})
	for batch := 0; batch < 50; batch++ {
		assets := make([]*asset.Asset, 0, 40)
		for i := 0; i < 40; i++ {
			assets = append(assets, publicAsset(t, tenant, fmt.Sprintf("b%d-%d.example.com", batch, i)))
		}
		n.AssetsDiscovered(context.Background(), tenant, assets)
	}
	if len(o.items) != 1 || len(in.items) != 1 {
		t.Fatalf("during the window: outbox=%d inapp=%d, want only the leading notice", len(o.items), len(in.items))
	}

	clk.fire() // window closes: one summary for the 2000 buffered assets
	if len(o.items) != 2 || len(in.items) != 2 {
		t.Fatalf("after window: outbox=%d inapp=%d, want 2/2", len(o.items), len(in.items))
	}
	summary := o.items[1]
	if summary.Metadata["asset_count"] != 2000 {
		t.Fatalf("summary asset_count = %v, want 2000", summary.Metadata["asset_count"])
	}
	if listed := summary.Metadata["assets"].([]map[string]any); len(listed) != maxListed {
		t.Fatalf("summary lists %d assets, want cap %d", len(listed), maxListed)
	}
	if summary.AggregateID != nil {
		t.Fatal("multi-asset summary must not point at a single asset")
	}
	if !strings.HasPrefix(in.items[1].Title, "2000 new internet-facing assets") {
		t.Fatalf("summary title %q", in.items[1].Title)
	}

	// Quiet window: no notification, tenant returns to idle...
	clk.fire()
	if len(o.items) != 2 {
		t.Fatalf("empty window sent a notification")
	}
	// ...so the next discovery notifies immediately again.
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "later.example.com")})
	if len(o.items) != 3 {
		t.Fatalf("idle tenant not notified immediately (outbox=%d)", len(o.items))
	}
}

func TestNotifier_DedupWithinWindow(t *testing.T) {
	n, o, _, clk := newTestNotifier()
	tenant := shared.NewID()
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "lead.example.com")})

	dup := publicAsset(t, tenant, "dup.example.com")
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{dup, dup})
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{dup})
	clk.fire()

	if len(o.items) != 2 {
		t.Fatalf("outbox=%d, want 2", len(o.items))
	}
	if got := o.items[1].Metadata["asset_count"]; got != 1 {
		t.Fatalf("duplicate asset counted %v times, want 1", got)
	}
}

func TestNotifier_TenantIsolation(t *testing.T) {
	n, o, in, clk := newTestNotifier()
	t1, t2 := shared.NewID(), shared.NewID()

	n.AssetsDiscovered(context.Background(), t1, []*asset.Asset{publicAsset(t, t1, "one.example.com")})
	// Tenant 2 is idle: its own throttle, notified immediately, not merged into t1's.
	n.AssetsDiscovered(context.Background(), t2, []*asset.Asset{publicAsset(t, t2, "two.example.com")})
	// A tenant-1 asset delivered under tenant 2's callback is dropped.
	n.AssetsDiscovered(context.Background(), t2, []*asset.Asset{publicAsset(t, t1, "leak.example.com")})
	clk.fire()

	if len(o.items) != 2 || len(in.items) != 2 {
		t.Fatalf("outbox=%d inapp=%d, want 2/2", len(o.items), len(in.items))
	}
	for _, it := range o.items {
		body := it.Title + it.Body
		if it.TenantID == t2 && strings.Contains(body, "one.example.com") {
			t.Fatal("tenant 1 asset leaked into tenant 2 notification")
		}
		if strings.Contains(body, "leak.example.com") {
			t.Fatal("cross-tenant asset was notified")
		}
	}
	if o.items[0].TenantID != t1 || o.items[1].TenantID != t2 {
		t.Fatalf("tenants = %s,%s", o.items[0].TenantID, o.items[1].TenantID)
	}
}

func TestNotifier_StopFlushesPending(t *testing.T) {
	n, o, _, _ := newTestNotifier()
	tenant := shared.NewID()
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "lead.example.com")})
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "buffered.example.com")})

	n.Stop()
	if len(o.items) != 2 || !strings.Contains(o.items[1].Title, "buffered.example.com") {
		t.Fatalf("Stop did not flush the buffered summary (outbox=%d)", len(o.items))
	}
	// After Stop nothing more is sent.
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "late.example.com")})
	if len(o.items) != 2 {
		t.Fatal("notified after Stop")
	}
}

func TestNotifier_ExistingAssetBecameExposed(t *testing.T) {
	n, o, in, clk := newTestNotifier()
	tenant := shared.NewID()
	host := internalAsset(t, tenant, "10.9.9.9")
	host.SetInternetAccessible(true)

	n.AssetsExposed(context.Background(), tenant, []*asset.Asset{host})
	if len(in.items) != 1 || !strings.HasPrefix(in.items[0].Title, "Asset now internet-facing: 10.9.9.9") {
		t.Fatalf("in-app = %+v", in.items)
	}

	// Mixed window: one new + one newly exposed -> one combined summary.
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "new.example.com")})
	other := internalAsset(t, tenant, "10.9.9.10")
	other.SetExposure(asset.ExposurePublic)
	n.AssetsExposed(context.Background(), tenant, []*asset.Asset{other})
	clk.fire()
	if len(o.items) != 2 {
		t.Fatalf("outbox = %d, want 2", len(o.items))
	}
	sum := o.items[1]
	if sum.Title != "2 assets newly exposed to the internet" || sum.Metadata["newly_exposed_count"] != 1 || sum.Metadata["new_asset_count"] != 1 {
		t.Fatalf("mixed summary = %q %v", sum.Title, sum.Metadata)
	}
	if sum.URL != ChangesURL {
		t.Fatalf("mixed summary URL = %q", sum.URL)
	}
	if o.items[0].URL != ChangesURL+"?view=newly_exposed" {
		t.Fatalf("exposed-only URL = %q", o.items[0].URL)
	}
}

func TestNotifier_NilSinksAreSafe(t *testing.T) {
	n := NewNotifier(nil, nil, 0, nil)
	n.afterFunc = (&manualClock{}).afterFunc
	tenant := shared.NewID()
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "x.example.com")})
	n.Stop()
}
