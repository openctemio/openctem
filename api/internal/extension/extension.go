// Package extension is the one point where a build that adds an extension
// plugs into the core (docs/development/editions.md). The Community build
// registers nothing: the core then runs with its defaults (no grant
// provider, so every grant is off and there are no notices).
//
// An extension registers itself from an init function in a package that only
// the build switch (cmd/server/edition_ee.go, behind a build tag) imports.
// Everything the core hands it is listed in Deps; it gets no other access.
package extension

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Community is the edition name of a build with no extension.
const Community = "community"

// Deps is what the core hands an extension at start.
type Deps struct {
	// DB is the API's database pool. An extension reads and writes only its
	// own schema and installation-wide state through it; every query on
	// organization data stays tenant-scoped like core code.
	DB  *postgres.DB
	Log *logger.Logger
}

// Edition is what an extension registers.
type Edition struct {
	// Name is reported in logs (lower case letters, digits and dashes).
	Name string
	// Grants builds the grant provider once at start (nil: none). A provider
	// that also implements Runner is run in the background until shutdown.
	Grants func(ctx context.Context, d Deps) (limits.GrantProvider, error)
}

// Runner is implemented by a provider that keeps itself fresh in the
// background.
type Runner interface {
	Run(ctx context.Context)
}

var (
	mu         sync.Mutex
	registered *Edition
	namePat    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// Register records the build's extension. It panics on a second
// registration, an invalid name, or the Community name: a build has exactly
// one extension or none, and a mistake must stop the build's first start.
func Register(e Edition) {
	mu.Lock()
	defer mu.Unlock()
	if registered != nil {
		panic(fmt.Sprintf("extension: %q registered after %q", e.Name, registered.Name))
	}
	if !namePat.MatchString(e.Name) || e.Name == Community {
		panic(fmt.Sprintf("extension: invalid edition name %q", e.Name))
	}
	registered = &e
}

// Name is the edition of this build: the registered extension's name, or
// Community.
func Name() string {
	mu.Lock()
	defer mu.Unlock()
	if registered == nil {
		return Community
	}
	return registered.Name
}

// Grants returns the registered extension's grant provider, or nil when
// there is none. When the extension fails to build it, the error is logged
// and the core runs with no provider: an extension can never stop the
// server or switch off a Community feature, only leave its own grants off.
func Grants(ctx context.Context, d Deps) limits.GrantProvider {
	mu.Lock()
	e := registered
	mu.Unlock()
	if e == nil || e.Grants == nil {
		return nil
	}
	p, err := e.Grants(ctx, d)
	if err != nil {
		if d.Log != nil {
			d.Log.Error("extension grant provider failed to start; every grant stays off", "edition", e.Name, "error", err)
		}
		return nil
	}
	return p
}
