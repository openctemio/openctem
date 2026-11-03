package extension

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
)

// APIVersion is the version of this extension API. See the package
// documentation for what bumps it.
const APIVersion = 1

// Community is the edition name of a build with no extension.
const Community = "community"

// GrantProvider answers for grants (things that are off unless granted).
type GrantProvider = limits.GrantProvider

// Extension is what an extension registers. Every field but APIVersion and
// Name is optional; a nil field means the core default.
type Extension struct {
	// APIVersion is the API version the extension was written for, as a
	// literal (never extension.APIVersion): Register panics when it is not
	// the core's APIVersion.
	APIVersion int
	// Name is the edition name reported by /api/v1/version and in logs:
	// lower-case letters, digits and dashes, starting with a letter, at
	// most 32 characters, never "community".
	Name string

	// Schema is the extension's own database schema (lower-case letters,
	// digits and underscores, at most 31 characters). Store transactions
	// resolve unqualified names there first. Never a core schema
	// (public, pg_*, information_schema). Required with Migrations.
	Schema string
	// Migrations are the extension's migrations, applied in Schema after
	// the core set: files VERSION_name.up.sql with a matching
	// VERSION_name.down.sql at the root, VERSION a UTC timestamp
	// (YYYYMMDDHHMMSS). They reference core tables only schema-qualified,
	// only by primary key and tenant_id, and never create a table named
	// like a core table.
	Migrations fs.FS
	// ConfigKeys are the environment keys the extension reads through
	// Deps.Settings (upper-case letters, digits and underscores). Every
	// other key reads as empty. A key the core owns may not be listed.
	ConfigKeys []string

	// Grants builds the grant provider once at start. When it fails, the
	// error is logged and every grant stays off: an extension can never
	// stop the server or switch off a Community feature. A provider that
	// also implements Runner runs in the background until shutdown.
	Grants func(ctx context.Context, d Deps) (GrantProvider, error)
	// Controllers builds the extension's background controllers at start.
	// An error stops the start: a feature the operator configured must not
	// silently vanish.
	Controllers func(ctx context.Context, d Deps) ([]Controller, error)
	// Routes registers the extension's HTTP routes at start. An error, or
	// a route the core refuses, stops the start.
	Routes func(ctx context.Context, r Router, d Deps) error
}

// Runner is implemented by a grant provider that keeps itself fresh in the
// background.
type Runner interface {
	Run(ctx context.Context)
}

var (
	mu         sync.Mutex
	registered *Extension
	namePat    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	schemaPat  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	keyPat     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

// Register records the build's extension. It panics on a second
// registration, an API version mismatch or an invalid field: a build has
// exactly one extension or none, and a mistake must stop its first start.
func Register(e Extension) {
	if err := e.validate(); err != nil {
		panic("extension: " + err.Error())
	}
	mu.Lock()
	defer mu.Unlock()
	if registered != nil {
		panic(fmt.Sprintf("extension: %q registered after %q", e.Name, registered.Name))
	}
	e.ConfigKeys = append([]string(nil), e.ConfigKeys...)
	registered = &e
}

func (e Extension) validate() error {
	if e.APIVersion != APIVersion {
		return fmt.Errorf("%q was written for extension API %d, this core serves %d", e.Name, e.APIVersion, APIVersion)
	}
	if !namePat.MatchString(e.Name) || e.Name == Community {
		return fmt.Errorf("invalid edition name %q", e.Name)
	}
	if e.Schema != "" {
		if !schemaPat.MatchString(e.Schema) || reservedSchema(e.Schema) {
			return fmt.Errorf("%q: invalid schema %q", e.Name, e.Schema)
		}
	}
	if e.Migrations != nil {
		if e.Schema == "" {
			return fmt.Errorf("%q: migrations need a schema", e.Name)
		}
		if err := ValidateMigrations(e.Migrations); err != nil {
			return fmt.Errorf("%q: %w", e.Name, err)
		}
	}
	seen := map[string]bool{}
	for _, k := range e.ConfigKeys {
		if !keyPat.MatchString(k) || seen[k] {
			return fmt.Errorf("%q: invalid or repeated config key %q", e.Name, k)
		}
		seen[k] = true
	}
	return nil
}

func reservedSchema(s string) bool {
	return s == "public" || s == "information_schema" || len(s) >= 3 && s[:3] == "pg_"
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

// Registered returns a copy of the registered extension, or false in the
// Community build. The core uses it to wire the extension at start.
func Registered() (Extension, bool) {
	mu.Lock()
	defer mu.Unlock()
	if registered == nil {
		return Extension{}, false
	}
	e := *registered
	e.ConfigKeys = append([]string(nil), registered.ConfigKeys...)
	return e, true
}

// ResetForTesting removes the registration so a test can register another
// extension. It panics outside a test binary.
func ResetForTesting() {
	if !testing.Testing() {
		panic("extension: ResetForTesting outside a test")
	}
	mu.Lock()
	registered = nil
	mu.Unlock()
}
