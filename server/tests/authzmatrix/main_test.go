//go:build authzmatrix

// Package authzmatrix is the authorization regression suite: it seeds two
// organizations with one principal per role kind through the public API,
// then sends every tenant route as every principal, with its own and with
// the other organization's ids, and compares the answer with what the route
// gates (read from the source by internal/authzdoc) say it must be.
//
// It runs against a live scratch stack; ci/run.sh starts one, runs the suite
// and removes the stack. Env: MATRIX_API (base URL), MATRIX_DATABASE_URL (the
// stack's database, for the bootstrap steps that have no API),
// MATRIX_API_ROOT (the api/ directory), MATRIX_REPORT (optional JSON report
// path).
package authzmatrix

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	worldOnce sync.Once
	theWorld  *world
	worldErr  string
)

func runID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func apiRoot() string {
	if r := os.Getenv("MATRIX_API_ROOT"); r != "" {
		return r
	}
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// getWorld seeds the stack once per test binary.
func getWorld(t *testing.T) *world {
	t.Helper()
	base, dsn := os.Getenv("MATRIX_API"), os.Getenv("MATRIX_DATABASE_URL")
	if base == "" || dsn == "" {
		t.Skip("MATRIX_API and MATRIX_DATABASE_URL not set (run api/tests/authzmatrix/ci/run.sh)")
	}
	worldOnce.Do(func() {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			worldErr = err.Error()
			return
		}
		w := &world{c: newClient(base), db: db}
		ok := t.Run("seed", func(t *testing.T) { w.seed(t) })
		if !ok {
			worldErr = "seeding failed"
			return
		}
		theWorld = w
	})
	if theWorld == nil {
		t.Fatalf("no world: %s", worldErr)
	}
	return theWorld
}

// seed builds the two organizations and their principals.
func (w *world) seed(t *testing.T) {
	id := runID()
	acme := w.bootstrapTenant(t, "Acme", "acme-"+id)
	globex := w.bootstrapTenant(t, "Globex", "globex-"+id)
	for _, ten := range []*tenant{acme, globex} {
		w.seedResources(t, ten)
		w.seedPrincipals(t, ten, ten == acme)
		w.seedMachines(t, ten)
	}
	w.seedPlatformAdmin(t)
	w.add(&principal{Name: "anonymous", Kind: kindUnauth, cred: noCredential, perms: map[string]bool{}})
	for _, p := range w.order {
		t.Logf("principal %-32s kind=%s perms=%d bypass=%v scoped=%v", p.Name, p.Kind, len(p.perms), p.adminBypass, p.scoped)
	}
}

// seedPlatformAdmin signs the platform administrator (an account in no
// organization) in on the tenant sign-in, which must give it no tenant.
func (w *world) seedPlatformAdmin(t *testing.T) {
	t.Helper()
	if w.adminTmp == "" {
		t.Log("platform admin: no temporary password captured; skipped")
		return
	}
	b := w.c.newBrowser()
	r, err := b.do("POST", "/api/v1/auth/login", map[string]string{"email": "platform-admin@example.com", "password": w.adminTmp})
	if err != nil {
		t.Fatalf("platform admin login: %v", err)
	}
	t.Logf("platform admin tenant sign-in: %d %s", r.Status, r.Code)
	tok := jsonID(r, "access_token")
	if tok == "" {
		return
	}
	w.add(&principal{Name: "platform-admin", Kind: kindNoTenant, cred: bearer(tok), perms: map[string]bool{}})
}

// TestAuthz runs the passes in an order that keeps the seeded world usable:
// reads, then the scenario tests (which change roles and memberships of
// their own throw-away accounts), then writes with fresh ids, then writes
// with the other organization's ids.
func TestAuthz(t *testing.T) {
	w := getWorld(t)
	routes := loadRoutes(t)
	w.harvest(t, routes)
	allow := loadAllowlist(t)
	newRun := func() *matrixRun { return &matrixRun{w: w, allow: allow, stepped: map[*principal]time.Time{}} }

	// Positive controls for the body checks: the owner's asset list holds
	// the out-of-scope asset, so a scoped principal's list that held it
	// would be caught; the other organization's markers are in its own list.
	t.Run("controls", func(t *testing.T) {
		acme, globex := w.tenant("Acme"), w.tenant("Globex")
		m := newRun()
		owner := assetsAs(t, w, acme.owner)
		if !strings.Contains(owner, acme.get("asset.oos")) {
			t.Fatalf("control: the owner's asset list lacks the out-of-scope asset")
		}
		if leak := m.leakIn(w.byName["Acme/scoped-member"], route{Class: "scoped"}, "/api/v1/assets", []byte(owner)); leak == "" {
			t.Fatalf("control: the out-of-scope detector missed the owner's list")
		}
		if leak := m.leakIn(globex.owner, route{}, "/api/v1/assets", []byte(owner)); leak == "" {
			t.Fatalf("control: the other-organization detector missed Acme's list")
		}
	})
	t.Run("reads", func(t *testing.T) {
		m := newRun()
		m.run(t, routes, append([]*principal(nil), w.order...), false)
		markUnreachable(m.results)
		writeReport(t, "reads", m.results)
		failOnMismatches(t, m.results)
	})
	t.Run("scenarios", func(t *testing.T) { w.scenarios(t) })
	t.Run("writes", func(t *testing.T) {
		m := newRun()
		m.run(t, routes, append([]*principal(nil), w.order...), true)
		markUnreachable(m.results)
		writeReport(t, "writes", m.results)
		failOnMismatches(t, m.results)
	})
}

func assetsAs(t *testing.T, w *world, p *principal) string {
	t.Helper()
	r := must(t, "list assets")(w.as(t, p, "GET", "/api/v1/assets?per_page=100", nil))
	return string(r.Body)
}
