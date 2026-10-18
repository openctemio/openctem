package versioncheck

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type memSettings struct {
	mu   sync.Mutex
	rows map[string]platformsetting.State
	fail error
}

func (m *memSettings) Get(_ context.Context, k string) (platformsetting.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return platformsetting.State{}, m.fail
	}
	s, ok := m.rows[k]
	if !ok {
		return platformsetting.State{}, platformsetting.ErrNotFound
	}
	return s, nil
}

func (m *memSettings) CreateIfAbsent(_ context.Context, k string, s platformsetting.State) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string]platformsetting.State{}
	}
	if _, ok := m.rows[k]; ok {
		return false, nil
	}
	m.rows[k] = s
	return true, nil
}

func (m *memSettings) Update(_ context.Context, k string, v json.RawMessage, expected int, by shared.ID, at time.Time) (platformsetting.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.rows[k]
	if cur.Version != expected {
		return platformsetting.State{}, platformsetting.ErrVersionConflict
	}
	next := platformsetting.State{Value: v, Version: expected + 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: at}
	m.rows[k] = next
	return next, nil
}

func switchService(t *testing.T, envEnabled bool) (*Service, *server, *clock, *memSettings) {
	t.Helper()
	k, srv, c := newKeys(t), newServer(t), &clock{now: t0}
	srv.body = k.feed(t, 1, t0, "v0.9.8")
	svc := New(&memRepo{}, Config{Enabled: envEnabled, URL: srv.srv.URL, Keys: []string{k.pinned()}, Running: "v0.9.7",
		Client: http.DefaultClient, Now: c.Now, Jitter: func(time.Duration) time.Duration { return 0 }}, logger.NewNop())
	settings := &memSettings{}
	svc.SetSettings(settings)
	return svc, srv, c, settings
}

func runDays(t *testing.T, svc *Service, c *clock, days int) {
	t.Helper()
	for i := 0; i < days; i++ {
		c.now = c.now.Add(48 * time.Hour)
		if err := svc.RunDue(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

// The console turns the online check off without a restart: no request leaves
// the instance afterwards, and the view says it is off.
func TestConsoleSwitchTurnsTheCheckOff(t *testing.T) {
	svc, srv, c, _ := switchService(t, true)
	if err := svc.UpdateEnabled(context.Background(), false, shared.NewID()); err != nil {
		t.Fatal(err)
	}
	runDays(t, svc, c, 3)
	if len(srv.headers) != 0 {
		t.Fatalf("sent %d requests after the console turned the check off", len(srv.headers))
	}
	v, _ := svc.View(context.Background())
	if v.Enabled || v.LockedByEnvironment || v.NextCheckAt != nil {
		t.Fatalf("view = %+v", v)
	}

	// And back on.
	if err := svc.UpdateEnabled(context.Background(), true, shared.NewID()); err != nil {
		t.Fatal(err)
	}
	runDays(t, svc, c, 2)
	if len(srv.headers) == 0 {
		t.Fatal("no check after the console turned it back on")
	}
}

// VERSION_CHECK_ENABLED=false is a ceiling: a console session cannot turn the
// outbound request on.
func TestEnvironmentOffIsACeiling(t *testing.T) {
	svc, srv, c, settings := switchService(t, false)
	if err := svc.UpdateEnabled(context.Background(), true, shared.NewID()); !errors.Is(err, ErrLockedByEnvironment) {
		t.Fatalf("turning on under VERSION_CHECK_ENABLED=false: %v, want ErrLockedByEnvironment", err)
	}
	if len(settings.rows) != 0 {
		t.Fatal("nothing may be stored when the switch is refused")
	}
	// Even a stored "on" (from before the operator turned the environment
	// off) sends nothing.
	settings.rows = map[string]platformsetting.State{SettingKey: {Value: []byte(`{"enabled":true}`), Version: 1}}
	runDays(t, svc, c, 3)
	if len(srv.headers) != 0 {
		t.Fatalf("sent %d requests under VERSION_CHECK_ENABLED=false", len(srv.headers))
	}
	v, _ := svc.View(context.Background())
	if v.Enabled || !v.LockedByEnvironment {
		t.Fatalf("view = %+v", v)
	}
	// Turning it off is always allowed.
	if err := svc.UpdateEnabled(context.Background(), false, shared.NewID()); err != nil {
		t.Fatalf("turning off: %v", err)
	}
}

// A store that cannot be read sends nothing (no request on an unknown answer).
func TestUnreadableSwitchSendsNothing(t *testing.T) {
	svc, srv, c, settings := switchService(t, true)
	settings.fail = errors.New("db down")
	runDays(t, svc, c, 3)
	if len(srv.headers) != 0 {
		t.Fatalf("sent %d requests with an unreadable switch", len(srv.headers))
	}
}
