package extensionhost

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ext "github.com/openctemio/openctem/api/pkg/extension"
	"github.com/openctemio/openctem/api/pkg/extension/example"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func build(t *testing.T, exts ...ext.Extension) *Set {
	t.Helper()
	for i := range exts {
		exts[i].APIVersion = ext.APIVersion
		if exts[i].Name == "" {
			exts[i].Name = "custom"
		}
	}
	s, err := New(exts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type stubProvider struct{}

func (stubProvider) Grant(_ context.Context, _ shared.ID, k limits.GrantKey) (limits.Grant, error) {
	return limits.Grant{Key: k, Status: limits.GrantActive}, nil
}
func (stubProvider) Notices(context.Context) ([]limits.Notice, error) { return nil, nil }

// The Community build gets the core defaults for every seam.
func TestCommunityDefaults(t *testing.T) {
	ctx := context.Background()
	for _, s := range []*Set{nil, build(t)} {
		h := Host{Log: logger.NewNop()}
		if !s.Empty() || len(s.Info()) != 0 || s.Declares("ANY") {
			t.Fatal("Community build has an extension")
		}
		if p := s.Grants(ctx, h); p != nil {
			t.Fatalf("grant provider: %T", p)
		}
		if cs, err := s.Controllers(ctx, h); err != nil || cs != nil {
			t.Fatalf("controllers: %v %v", cs, err)
		}
		if rs, err := s.Routes(ctx, h); err != nil || rs != nil {
			t.Fatalf("routes: %v %v", rs, err)
		}
	}
}

func TestNewRefusesAnInvalidBuild(t *testing.T) {
	bad := ext.Extension{APIVersion: ext.APIVersion + 1, Name: "custom"}
	if _, err := New([]ext.Extension{bad}); err == nil {
		t.Fatal("accepted another API version")
	}
	a := ext.Extension{APIVersion: ext.APIVersion, Name: "same"}
	if _, err := New([]ext.Extension{a, a}); err == nil {
		t.Fatal("accepted a name twice")
	}
}

func TestInfoListsExtensionsInOrder(t *testing.T) {
	s := build(t, ext.Extension{Name: "one", Version: "v1"}, ext.Extension{Name: "two"})
	got := s.Info()
	if len(got) != 2 || got[0].Name != "one" || got[0].Version != "v1" || got[1].Name != "two" {
		t.Fatalf("%+v", got)
	}
}

func TestGrants(t *testing.T) {
	s := build(t,
		ext.Extension{Name: "plain"},
		ext.Extension{Name: "granting", Grants: func(context.Context, ext.Deps) (ext.GrantProvider, error) { return stubProvider{}, nil }},
	)
	p := s.Grants(context.Background(), Host{Log: logger.NewNop()})
	if _, ok := p.(stubProvider); !ok {
		t.Fatalf("provider %T", p)
	}
}

// A failing provider leaves every grant off and never stops the server.
func TestGrantsFailureKeepsCommunity(t *testing.T) {
	s := build(t, ext.Extension{Grants: func(context.Context, ext.Deps) (ext.GrantProvider, error) {
		return nil, errors.New("licence store unreadable")
	}})
	if p := s.Grants(context.Background(), Host{Log: logger.NewNop()}); p != nil {
		t.Fatalf("provider %T", p)
	}
}

type ctrl struct{ exclusive bool }

func (ctrl) Name() string                           { return "c" }
func (ctrl) Interval() time.Duration                { return time.Minute }
func (ctrl) Reconcile(context.Context) (int, error) { return 0, nil }
func (c ctrl) Exclusive() bool                      { return c.exclusive }

func TestControllers(t *testing.T) {
	s := build(t,
		ext.Extension{Name: "one", Controllers: func(context.Context, ext.Deps) ([]ext.Controller, error) {
			return []ext.Controller{ctrl{exclusive: true}}, nil
		}},
		ext.Extension{Name: "two", Controllers: func(context.Context, ext.Deps) ([]ext.Controller, error) {
			return []ext.Controller{ctrl{}}, nil
		}},
	)
	cs, err := s.Controllers(context.Background(), Host{})
	if err != nil || len(cs) != 2 {
		t.Fatalf("%v %v", cs, err)
	}
	if x, ok := cs[0].(interface{ Exclusive() bool }); !ok || !x.Exclusive() {
		t.Fatal("an exclusive controller lost its lease")
	}

	failing := build(t, ext.Extension{Controllers: func(context.Context, ext.Deps) ([]ext.Controller, error) {
		return nil, errors.New("bad sink")
	}})
	if _, err := failing.Controllers(context.Background(), Host{}); err == nil || !strings.Contains(err.Error(), "custom") {
		t.Fatalf("a failing controller must stop the start, naming the extension: %v", err)
	}
	nilCtrl := build(t, ext.Extension{Controllers: func(context.Context, ext.Deps) ([]ext.Controller, error) {
		return []ext.Controller{nil}, nil
	}})
	if _, err := nilCtrl.Controllers(context.Background(), Host{}); err == nil {
		t.Fatal("a nil controller was accepted")
	}
}

// An extension reads only the keys it declared; a core setting (secrets
// above all) is refused at start, and an extension reads no other
// extension's keys.
func TestSettingsAndConfigKeys(t *testing.T) {
	env := map[string]string{"CUSTOM_KEY": "v", "OTHER_KEY": "o", "APP_ENCRYPTION_KEY": "secret"}
	a := ext.Extension{APIVersion: ext.APIVersion, Name: "a", ConfigKeys: []string{"CUSTOM_KEY"}}
	b := ext.Extension{APIVersion: ext.APIVersion, Name: "b", ConfigKeys: []string{"OTHER_KEY"}}
	s := build(t, a, b)
	if !s.Declares("CUSTOM_KEY") || !s.Declares("OTHER_KEY") || s.Declares("APP_ENCRYPTION_KEY") {
		t.Fatal("Declares")
	}
	d := DepsFor(a, Host{Getenv: func(k string) string { return env[k] }})
	if d.Settings.Get("CUSTOM_KEY") != "v" {
		t.Fatal("declared key unreadable")
	}
	if d.Settings.Get("OTHER_KEY") != "" || d.Settings.Get("APP_ENCRYPTION_KEY") != "" {
		t.Fatal("an undeclared key was readable")
	}

	for _, k := range []string{"APP_ENCRYPTION_KEY", "DATABASE_URL", "AUTH_JWT_SECRET"} {
		_, err := New([]ext.Extension{{APIVersion: ext.APIVersion, Name: "custom", ConfigKeys: []string{k}}})
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s: declaring a core setting was accepted: %v", k, err)
		}
	}
}

func routesOf(t *testing.T, fns ...func(context.Context, ext.Router, ext.Deps) error) ([]Route, error) {
	t.Helper()
	exts := make([]ext.Extension, 0, len(fns))
	for i, fn := range fns {
		exts = append(exts, ext.Extension{Name: "ext" + string(rune('a'+i)), Routes: fn})
	}
	return build(t, exts...).Routes(context.Background(), Host{})
}

func TestRoutesValidation(t *testing.T) {
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	good := ext.Route{Method: http.MethodGet, Path: "/custom-things/{id}", Permission: "settings:read", Grant: "custom_things", Handler: h}
	rs, err := routesOf(t, func(_ context.Context, r ext.Router, _ ext.Deps) error { return r.Handle(good) })
	if err != nil || len(rs) != 1 || rs[0].Permission != "settings:read" || rs[0].Grant != "custom_things" {
		t.Fatalf("%+v %v", rs, err)
	}

	bad := map[string]func(*ext.Route){
		"no permission":      func(r *ext.Route) { r.Permission = "" },
		"unknown permission": func(r *ext.Route) { r.Permission = "custom:everything" },
		"no grant":           func(r *ext.Route) { r.Grant = "" },
		"bad grant":          func(r *ext.Route) { r.Grant = "Bad Key" },
		"no handler":         func(r *ext.Route) { r.Handler = nil },
		"method":             func(r *ext.Route) { r.Method = "TRACE" },
		"no leading slash":   func(r *ext.Route) { r.Path = "custom" },
		"dot segment":        func(r *ext.Route) { r.Path = "/custom/../admin" },
		"wildcard":           func(r *ext.Route) { r.Path = "/custom/*" },
		"admin plane":        func(r *ext.Route) { r.Path = "/admin/custom" },
		"auth":               func(r *ext.Route) { r.Path = "/auth/login" },
		"scim":               func(r *ext.Route) { r.Path = "/scim/v2/Users" },
		"sensor":             func(r *ext.Route) { r.Path = "/sensor" },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			rt := good
			mutate(&rt)
			if _, err := routesOf(t, func(_ context.Context, r ext.Router, _ ext.Deps) error { return r.Handle(rt) }); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	twice := func(_ context.Context, r ext.Router, _ ext.Deps) error {
		_ = r.Handle(good)
		return r.Handle(good)
	}
	if _, err := routesOf(t, twice); err == nil {
		t.Fatal("a route registered twice was accepted")
	}
	once := func(_ context.Context, r ext.Router, _ ext.Deps) error { return r.Handle(good) }
	if _, err := routesOf(t, once, once); err == nil {
		t.Fatal("two extensions serving the same route were accepted")
	}
}

// The example extension, written against the public API only, wires into
// every seam of the core, next to another extension.
func TestExampleWires(t *testing.T) {
	s := build(t, example.Extension(), ext.Extension{Name: "other"})
	h := Host{Getenv: func(k string) string {
		if k == example.ConfigGrantAll {
			return "true"
		}
		return ""
	}}
	p := s.Grants(context.Background(), h)
	if p == nil {
		t.Fatal("no provider")
	}
	if g, _ := p.Grant(context.Background(), shared.NewID(), example.Grant); !g.Status.Granting() {
		t.Fatal("example grant off")
	}
	if cs, err := s.Controllers(context.Background(), h); err != nil || len(cs) != 1 {
		t.Fatalf("%v %v", cs, err)
	}
	rs, err := s.Routes(context.Background(), h)
	if err != nil || len(rs) != 2 {
		t.Fatalf("%v %v", rs, err)
	}
}
