package include

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

var testRegistry = NewRegistry(
	Spec{Name: "settings", Permissions: []permission.Permission{permission.TenantToolsRead}},
	Spec{Name: "stats", Permissions: []permission.Permission{permission.TenantToolsRead, permission.ScansRead}, Cost: 2, Expensive: true},
	Spec{Name: "availability", Permissions: []permission.Permission{permission.TenantToolsRead}, Cost: 2, Expensive: true},
)

func req(query string, perms ...permission.Permission) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/tools?"+query, nil)
	p := make([]string, 0, len(perms))
	for _, x := range perms {
		p = append(p, x.String())
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.FetchedPermissionsKey, p))
}

func TestParse_RefusesWhatTheWhitelistDoesNotOffer(t *testing.T) {
	for _, q := range []string{
		"include=secrets",                               // unknown
		"include=settings.config",                       // nested
		"include=settings(config)",                      // nested, other syntax
		"include=settings,stats,availability,settings",  // more than 3 values
		"include=" + strings.Repeat("a", maxParamLen+1), // too long
		"include=settings,unknown",                      // one unknown among known
	} {
		_, err := testRegistry.Parse(req(q, permission.TenantToolsRead))
		if err == nil || err.Status != http.StatusBadRequest || err.Code != "INVALID_INCLUDE" {
			t.Errorf("%s: %+v, want 400 INVALID_INCLUDE", q, err)
		}
	}
}

func TestParse_OmitsWithoutPermissionAndListsIt(t *testing.T) {
	set, err := testRegistry.Parse(req("include=settings,stats", permission.TenantToolsRead))
	if err != nil {
		t.Fatal(err)
	}
	// stats needs scans:read as well: left out, listed, not an error.
	if !set.Has("settings") || set.Has("stats") || len(set.Omitted) != 1 || set.Omitted[0] != "stats" {
		t.Fatalf("set %+v", set)
	}
	none, err := testRegistry.Parse(req("include=settings,%20settings"))
	if err != nil || none.Has("settings") || len(none.Omitted) != 1 {
		t.Fatalf("no permission, duplicate collapsed: %+v %v", none, err)
	}
	if empty, _ := testRegistry.Parse(req("")); empty.Has("settings") || len(empty.Meta().OmittedIncludes) != 0 {
		t.Fatalf("no include: %+v", empty)
	}
}

func TestSet_CostAndPageCap(t *testing.T) {
	all := []permission.Permission{permission.TenantToolsRead, permission.ScansRead}
	light, _ := testRegistry.Parse(req("include=settings", all...))
	heavy, _ := testRegistry.Parse(req("include=settings,stats,availability", all...))
	if light.PerPageCap(100) != 100 || light.Cost() != 0 {
		t.Errorf("settings: cap %d cost %d", light.PerPageCap(100), light.Cost())
	}
	if heavy.PerPageCap(100) != ExpensivePerPage || heavy.Cost() != 4 {
		t.Errorf("heavy: cap %d cost %d", heavy.PerPageCap(100), heavy.Cost())
	}
	// An omitted expensive include neither costs nor caps.
	omitted, _ := testRegistry.Parse(req("include=stats", permission.TenantToolsRead))
	if omitted.PerPageCap(100) != 100 || omitted.Cost() != 0 {
		t.Errorf("omitted: cap %d cost %d", omitted.PerPageCap(100), omitted.Cost())
	}
}

func TestPrepare_NoStoreAndWeightedRateLimit(t *testing.T) {
	cfg := middleware.ReadEndpointRateLimitConfigFrom(config.RateLimitConfig{ReadRequestsPerMin: 4})
	rl := middleware.NewReadEndpointRateLimiter(cfg, logger.NewNop())
	defer rl.Stop()
	all := []permission.Permission{permission.TenantToolsRead, permission.ScansRead}

	run := func(query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			set, aerr := testRegistry.Parse(r)
			if aerr != nil {
				aerr.WriteJSON(w)
				return
			}
			if !Prepare(w, r, set) {
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		r := req(query, all...)
		r.RemoteAddr = "10.9.9.9:1"
		h.ServeHTTP(rec, r)
		return rec
	}

	plain := run("")
	if plain.Code != http.StatusOK || plain.Header().Get("Cache-Control") != "" {
		t.Fatalf("plain read: %d cache %q", plain.Code, plain.Header().Get("Cache-Control"))
	}
	// Budget 4: the plain read took 1; stats+availability takes 1+4 = 5.
	heavy := run("include=stats,availability")
	if heavy.Code != http.StatusTooManyRequests {
		t.Fatalf("expensive include over budget: %d, want 429", heavy.Code)
	}
	time.Sleep(10 * time.Millisecond)
	light := run("include=settings")
	if light.Code != http.StatusOK || light.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("include response: %d cache %q", light.Code, light.Header().Get("Cache-Control"))
	}
}

func TestNewRegistry_RefusesDeniedAndMalformedNames(t *testing.T) {
	for _, name := range []string{"secrets", "api_key", "credentials", "audit_log", "owner_email", "Settings", "a.b", ""} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%q registered, want a panic", name)
				}
			}()
			NewRegistry(Spec{Name: name, Permissions: []permission.Permission{permission.ToolsRead}})
		}()
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("an include without a permission registered")
			}
		}()
		NewRegistry(Spec{Name: "settings"})
	}()
	// Words that merely contain a denied word are fine.
	NewRegistry(Spec{Name: "catalog", Permissions: []permission.Permission{permission.ToolsRead}},
		Spec{Name: "keyboard_layout", Permissions: []permission.Permission{permission.ToolsRead}})
}
