package easm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/easmchange"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeChangeStore struct {
	counts   map[easmchange.Kind]int
	total    int
	items    []easmchange.Change
	claimed  map[string]bool
	released int
	scopes   []*shared.DataScope
	windows  [][2]time.Time
}

func (f *fakeChangeStore) ListChanges(_ context.Context, _ shared.ID, scope *shared.DataScope, q easmchange.Query) (*easmchange.Page, error) {
	f.scopes = append(f.scopes, scope)
	return &easmchange.Page{From: q.From, To: q.To, Counts: f.counts, Total: f.total, Items: f.items}, nil
}

func (f *fakeChangeStore) CountChanges(_ context.Context, _ shared.ID, scope *shared.DataScope, from, to time.Time) (map[easmchange.Kind]int, int, error) {
	f.scopes = append(f.scopes, scope)
	f.windows = append(f.windows, [2]time.Time{from, to})
	return f.counts, f.total, nil
}

func (f *fakeChangeStore) ClaimDigest(_ context.Context, tenantID shared.ID, slot, _ time.Time, _ map[easmchange.Kind]int, _ int) (bool, error) {
	key := tenantID.String() + slot.String()
	if f.claimed[key] {
		return false, nil
	}
	f.claimed[key] = true
	return true, nil
}

func (f *fakeChangeStore) ReleaseDigest(_ context.Context, tenantID shared.ID, slot time.Time) error {
	f.released++
	delete(f.claimed, tenantID.String()+slot.String())
	return nil
}

type fakeDigestSettings struct {
	es  tenant.EASMSettings
	err error
}

func (f fakeDigestSettings) GetEASMSettings(context.Context, string) (*tenant.EASMSettings, error) {
	return &f.es, f.err
}

type fakeEnqueuer struct {
	sent []outbox.EnqueueParams
	err  error
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, p)
	return nil
}

type fakeInApp struct {
	got []notificationdom.NotificationParams
}

func (f *fakeInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	f.got = append(f.got, p)
	return nil
}

type fakeAdmins struct{ ids []shared.ID }

func (f fakeAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return f.ids, nil
}

func TestDigestJob(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	admin := shared.NewID()
	monday := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	name := "new.example.com"

	newJob := func(store *fakeChangeStore, es tenant.EASMSettings, ob *fakeEnqueuer, inApp *fakeInApp) *DigestJob {
		j := NewDigestJob(store, fakeDigestSettings{es: es}, ob, inApp, fakeAdmins{ids: []shared.ID{admin}}, nil)
		j.SetClock(func() time.Time { return monday })
		return j
	}
	busy := func() *fakeChangeStore {
		return &fakeChangeStore{
			counts:  map[easmchange.Kind]int{easmchange.KindHostAdded: 2, easmchange.KindDNSDangling: 1},
			total:   3,
			items:   []easmchange.Change{{Kind: easmchange.KindDNSDangling, AssetName: name}},
			claimed: map[string]bool{},
		}
	}

	t.Run("sends once per slot to channels and administrators", func(t *testing.T) {
		store, ob, inApp := busy(), &fakeEnqueuer{}, &fakeInApp{}
		j := newJob(store, tenant.EASMSettings{}, ob, inApp)
		sent, err := j.RunTenant(ctx, tenantID)
		if err != nil || !sent {
			t.Fatalf("first run: %v %v", sent, err)
		}
		if sent, _ = j.RunTenant(ctx, tenantID); sent {
			t.Fatal("second run of the same slot sent again")
		}
		if len(ob.sent) != 1 || ob.sent[0].EventType != "attack_surface_digest" || ob.sent[0].TenantID != tenantID {
			t.Fatalf("outbox: %+v", ob.sent)
		}
		msg := ob.sent[0]
		if !strings.Contains(msg.Title, "3 changes") || !strings.Contains(msg.Body, "2 new hosts") ||
			!strings.Contains(msg.Body, "1 dangling DNS record") || !strings.Contains(msg.Body, name) {
			t.Fatalf("message: %q / %q", msg.Title, msg.Body)
		}
		if !strings.HasPrefix(msg.URL, ChangesURL+"?from=") {
			t.Fatalf("url: %s", msg.URL)
		}
		if len(inApp.got) != 1 || *inApp.got[0].AudienceID != admin || inApp.got[0].Audience != notificationdom.AudienceUser {
			t.Fatalf("in-app: %+v", inApp.got)
		}
		// The window is the week before Monday 08:00 UTC.
		w := store.windows[0]
		if w[1] != time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC) || w[1].Sub(w[0]) != 7*24*time.Hour {
			t.Fatalf("window: %v", w)
		}
	})

	t.Run("off sends nothing", func(t *testing.T) {
		store, ob := busy(), &fakeEnqueuer{}
		sent, err := newJob(store, tenant.EASMSettings{WeeklyDigestDisabled: true}, ob, &fakeInApp{}).RunTenant(ctx, tenantID)
		if err != nil || sent || len(ob.sent) != 0 || len(store.claimed) != 0 {
			t.Fatalf("disabled digest ran: %v %v", sent, err)
		}
	})

	t.Run("a quiet week is recorded and silent", func(t *testing.T) {
		store := &fakeChangeStore{counts: map[easmchange.Kind]int{}, claimed: map[string]bool{}}
		ob := &fakeEnqueuer{}
		sent, err := newJob(store, tenant.EASMSettings{}, ob, &fakeInApp{}).RunTenant(ctx, tenantID)
		if err != nil || sent || len(ob.sent) != 0 || len(store.claimed) != 1 {
			t.Fatalf("quiet week: %v %v %d", sent, err, len(store.claimed))
		}
	})

	t.Run("an outbox failure releases the slot for a retry", func(t *testing.T) {
		store, ob := busy(), &fakeEnqueuer{err: errors.New("db down")}
		if _, err := newJob(store, tenant.EASMSettings{}, ob, &fakeInApp{}).RunTenant(ctx, tenantID); err == nil {
			t.Fatal("outbox error swallowed")
		}
		if store.released != 1 || len(store.claimed) != 0 {
			t.Fatalf("slot not released: %d", store.released)
		}
	})

	t.Run("unreadable settings fail closed", func(t *testing.T) {
		store := busy()
		j := NewDigestJob(store, fakeDigestSettings{err: errors.New("boom")}, &fakeEnqueuer{}, nil, nil, nil)
		if sent, err := j.RunTenant(ctx, tenantID); err == nil || sent {
			t.Fatal("digest sent without settings")
		}
	})

	t.Run("the chosen weekday moves the slot", func(t *testing.T) {
		store := busy()
		j := newJob(store, tenant.EASMSettings{DigestWeekday: 5}, &fakeEnqueuer{}, &fakeInApp{})
		if _, err := j.RunTenant(ctx, tenantID); err != nil {
			t.Fatal(err)
		}
		if got := store.windows[0][1]; got != time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC) {
			t.Fatalf("friday slot = %v", got)
		}
	})
}

func TestChangeServiceRejectsBadWindow(t *testing.T) {
	svc := NewChangeService(&fakeChangeStore{claimed: map[string]bool{}}, nil)
	now := time.Now()
	_, err := svc.List(context.Background(), shared.NewID(), easmchange.Query{From: now.Add(-40 * 24 * time.Hour), To: now})
	if !errors.Is(err, easmchange.ErrInvalidQuery) {
		t.Fatalf("40-day window accepted: %v", err)
	}
}
