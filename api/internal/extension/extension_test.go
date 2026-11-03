package extension

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
	"github.com/openctemio/openctem/api/pkg/version"
)

func reset(t *testing.T) {
	t.Helper()
	ext.ResetForTesting()
	t.Cleanup(ext.ResetForTesting)
}

func register(t *testing.T, e ext.Extension) {
	t.Helper()
	reset(t)
	e.APIVersion = ext.APIVersion
	if e.Name == "" {
		e.Name = "custom"
	}
	ext.Register(e)
}

type stubProvider struct{}

func (stubProvider) Grant(_ context.Context, _ shared.ID, k limits.GrantKey) (limits.Grant, error) {
	return limits.Grant{Key: k, Status: limits.GrantActive}, nil
}
func (stubProvider) Notices(context.Context) ([]limits.Notice, error) { return nil, nil }

// The Community build gets the core defaults for every seam.
func TestCommunityDefaults(t *testing.T) {
	reset(t)
	ctx := context.Background()
	if Name() != Community {
		t.Fatalf("Name() = %q", Name())
	}
	d := Deps(Host{Log: logger.NewNop()})
	if d.Store != nil || d.Settings != nil {
		t.Fatal("Community build built extension deps")
	}
	if p := Grants(ctx, d); p != nil {
		t.Fatalf("grant provider: %T", p)
	}
	if cs, err := Controllers(ctx, d); err != nil || cs != nil {
		t.Fatalf("controllers: %v %v", cs, err)
	}
	if rs, err := Routes(ctx, d); err != nil || rs != nil {
		t.Fatalf("routes: %v %v", rs, err)
	}
	if err := Check(); err != nil || Claims("ADMIN_AUDIT_SINK") {
		t.Fatalf("check %v, claims %v", err, Claims("ADMIN_AUDIT_SINK"))
	}
}

func TestVersionMirrorsTheAPIVersion(t *testing.T) {
	if version.Get().ExtensionAPI != ext.APIVersion {
		t.Fatalf("pkg/version reports extension API %d, pkg/extension serves %d", version.Get().ExtensionAPI, ext.APIVersion)
	}
}

func TestGrants(t *testing.T) {
	var got ext.Deps
	register(t, ext.Extension{Grants: func(_ context.Context, d ext.Deps) (ext.GrantProvider, error) {
		got = d
		return stubProvider{}, nil
	}})
	log := logger.NewNop()
	d := Deps(Host{Log: log})
	if p := Grants(context.Background(), d); p == nil {
		t.Fatal("no provider")
	}
	if got.Log != log || got.Entitlements == nil || got.Settings == nil {
		t.Fatalf("deps not handed over: %+v", got)
	}
	// Without a grant service, every grant is off.
	if err := got.Entitlements.RequireGrant(context.Background(), shared.NewID(), "x"); err == nil {
		t.Fatal("default entitlements granted")
	}
}

// A provider that fails to start leaves every grant off and never stops
// the server.
func TestGrantsFailureKeepsCommunity(t *testing.T) {
	register(t, ext.Extension{Grants: func(context.Context, ext.Deps) (ext.GrantProvider, error) {
		return stubProvider{}, errors.New("schema missing")
	}})
	if p := Grants(context.Background(), ext.Deps{Log: logger.NewNop()}); p != nil {
		t.Fatalf("provider returned despite its error: %T", p)
	}
	if p := Grants(context.Background(), ext.Deps{}); p != nil {
		t.Fatal("nil logger must not panic and must return no provider")
	}
}

type ctrl struct{ exclusive bool }

func (ctrl) Name() string                           { return "c" }
func (ctrl) Interval() time.Duration                { return time.Minute }
func (ctrl) Reconcile(context.Context) (int, error) { return 0, nil }
func (c ctrl) Exclusive() bool                      { return c.exclusive }

func TestControllers(t *testing.T) {
	register(t, ext.Extension{Controllers: func(context.Context, ext.Deps) ([]ext.Controller, error) {
		return []ext.Controller{ctrl{exclusive: true}}, nil
	}})
	cs, err := Controllers(context.Background(), ext.Deps{})
	if err != nil || len(cs) != 1 {
		t.Fatalf("%v %v", cs, err)
	}
	// The core lease logic still sees the controller as exclusive.
	if x, ok := cs[0].(interface{ Exclusive() bool }); !ok || !x.Exclusive() {
		t.Fatal("exclusive lost in the adapter")
	}

	register(t, ext.Extension{Controllers: func(context.Context, ext.Deps) ([]ext.Controller, error) {
		return nil, errors.New("bad sink")
	}})
	if _, err := Controllers(context.Background(), ext.Deps{}); err == nil {
		t.Fatal("a controller error must stop the start")
	}
	register(t, ext.Extension{Controllers: func(context.Context, ext.Deps) ([]ext.Controller, error) {
		return []ext.Controller{nil}, nil
	}})
	if _, err := Controllers(context.Background(), ext.Deps{}); err == nil {
		t.Fatal("a nil controller must stop the start")
	}
}

// An extension reads only the keys it declared; core settings (secrets
// above all) are refused at start, except the ones it may take over.
func TestSettingsAndConfigKeys(t *testing.T) {
	env := map[string]string{"CUSTOM_KEY": "v", "APP_ENCRYPTION_KEY": "secret", "ADMIN_AUDIT_SINK": "file:///x"}
	register(t, ext.Extension{ConfigKeys: []string{"CUSTOM_KEY", "ADMIN_AUDIT_SINK"}})
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	d := Deps(Host{Getenv: func(k string) string { return env[k] }})
	if d.Settings.Get("CUSTOM_KEY") != "v" || d.Settings.Get("ADMIN_AUDIT_SINK") != "file:///x" {
		t.Fatal("declared keys unreadable")
	}
	if d.Settings.Get("APP_ENCRYPTION_KEY") != "" {
		t.Fatal("an undeclared core secret was readable")
	}
	if !Claims("ADMIN_AUDIT_SINK") || Claims("CUSTOM_KEY") || Claims("APP_ENCRYPTION_KEY") {
		t.Fatal("claims")
	}

	for _, k := range []string{"APP_ENCRYPTION_KEY", "DATABASE_URL", "AUTH_JWT_SECRET"} {
		register(t, ext.Extension{ConfigKeys: []string{k}})
		if err := Check(); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s: declaring a core setting was accepted: %v", k, err)
		}
	}
}

func TestRoutesValidation(t *testing.T) {
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	good := ext.Route{Method: http.MethodGet, Path: "/custom-things/{id}", Permission: "settings:read", Grant: "custom_things", Handler: h}
	register(t, ext.Extension{Routes: func(_ context.Context, r ext.Router, _ ext.Deps) error { return r.Handle(good) }})
	rs, err := Routes(context.Background(), ext.Deps{})
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
			register(t, ext.Extension{Routes: func(_ context.Context, r ext.Router, _ ext.Deps) error { return r.Handle(rt) }})
			if _, err := Routes(context.Background(), ext.Deps{}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	register(t, ext.Extension{Routes: func(_ context.Context, r ext.Router, _ ext.Deps) error {
		_ = r.Handle(good)
		return r.Handle(good)
	}})
	if _, err := Routes(context.Background(), ext.Deps{}); err == nil {
		t.Fatal("a route registered twice was accepted")
	}
}

// The example extension, written against the public API only, wires into
// every seam of the core.
func TestExampleWires(t *testing.T) {
	reset(t)
	ext.Register(example.Extension())
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	d := Deps(Host{Getenv: func(k string) string {
		if k == example.ConfigGrantAll {
			return "true"
		}
		return ""
	}})
	p := Grants(context.Background(), d)
	if p == nil {
		t.Fatal("no provider")
	}
	if g, _ := p.Grant(context.Background(), shared.NewID(), example.Grant); !g.Status.Granting() {
		t.Fatal("example grant off")
	}
	if cs, err := Controllers(context.Background(), d); err != nil || len(cs) != 1 {
		t.Fatalf("%v %v", cs, err)
	}
	rs, err := Routes(context.Background(), d)
	if err != nil || len(rs) != 2 {
		t.Fatalf("%v %v", rs, err)
	}
}
