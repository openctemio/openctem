package extension

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
)

// APIVersion is the version of this extension API. It stays 1 until the
// core's 1.0 release; see the package documentation for how changes are
// made before then.
const APIVersion = 1

// GrantProvider answers for grants (things that are off unless granted).
type GrantProvider = limits.GrantProvider

// Extension is one extension of a build. A build passes its extensions to
// server.Main (api/pkg/server). Every field but APIVersion and Name is
// optional; a nil field means the core default.
type Extension struct {
	// APIVersion is the API version the extension was written for, as a
	// literal (never extension.APIVersion): the server refuses to start
	// when it is not the core's APIVersion.
	APIVersion int
	// Name identifies the extension in /api/v1/version and in logs:
	// lower-case letters, digits and dashes, starting with a letter, at
	// most 32 characters, unique in the build.
	Name string
	// Version is the extension's own version, reported next to its name
	// (free text, at most 64 printable characters; may be empty).
	Version string

	// Schema is the extension's own database schema (lower-case letters,
	// digits and underscores, at most 31 characters), unique in the build.
	// Store transactions resolve unqualified names there first. Never a
	// core schema (public, pg_*, information_schema) nor "extensions".
	// Required with Migrations.
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
	// other key reads as empty. A key the core owns is refused, and no two
	// extensions of a build may declare the same key.
	ConfigKeys []string

	// Grants builds the grant provider once at start. At most one
	// extension of a build may set it. When it fails, the error is logged
	// and every grant stays off: an extension can never stop the server or
	// switch off a Community feature. A provider that also implements
	// Runner runs in the background until shutdown.
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
	namePat    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	versionPat = regexp.MustCompile(`^[\x21-\x7e]{0,64}$`)
	schemaPat  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	keyPat     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

// Validate checks one extension on its own: the API version, the name,
// version, schema, migration set and config keys. The server runs it (and
// ValidateBuild) before anything starts.
func (e Extension) Validate() error {
	if e.APIVersion != APIVersion {
		return fmt.Errorf("extension %q was written for extension API %d, this core serves %d", e.Name, e.APIVersion, APIVersion)
	}
	if !namePat.MatchString(e.Name) {
		return fmt.Errorf("invalid extension name %q", e.Name)
	}
	if !versionPat.MatchString(e.Version) {
		return fmt.Errorf("extension %q: invalid version %q", e.Name, e.Version)
	}
	if e.Schema != "" {
		if !schemaPat.MatchString(e.Schema) || reservedSchema(e.Schema) {
			return fmt.Errorf("extension %q: invalid schema %q", e.Name, e.Schema)
		}
	}
	if e.Migrations != nil {
		if e.Schema == "" {
			return fmt.Errorf("extension %q: migrations need a schema", e.Name)
		}
		if err := ValidateMigrations(e.Migrations); err != nil {
			return fmt.Errorf("extension %q: %w", e.Name, err)
		}
	}
	seen := map[string]bool{}
	for _, k := range e.ConfigKeys {
		if !keyPat.MatchString(k) || seen[k] {
			return fmt.Errorf("extension %q: invalid or repeated config key %q", e.Name, k)
		}
		seen[k] = true
	}
	return nil
}

// ValidateBuild checks the extensions of one build together: each one
// valid, names, schemas and config keys unique across the build, and at
// most one grant provider. An empty build (Community) is valid.
func ValidateBuild(exts []Extension) error {
	names, schemas, keys := map[string]bool{}, map[string]string{}, map[string]string{}
	provider := ""
	var errs []error
	for _, e := range exts {
		if err := e.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if names[e.Name] {
			errs = append(errs, fmt.Errorf("extension %q: name used twice in this build", e.Name))
		}
		names[e.Name] = true
		if e.Schema != "" {
			if other, ok := schemas[e.Schema]; ok {
				errs = append(errs, fmt.Errorf("extension %q: schema %q already belongs to %q", e.Name, e.Schema, other))
			}
			schemas[e.Schema] = e.Name
		}
		for _, k := range e.ConfigKeys {
			if other, ok := keys[k]; ok {
				errs = append(errs, fmt.Errorf("extension %q: config key %s already belongs to %q", e.Name, k, other))
			}
			keys[k] = e.Name
		}
		if e.Grants != nil {
			if provider != "" {
				errs = append(errs, fmt.Errorf("extension %q: a build has at most one grant provider, %q already provides grants", e.Name, provider))
			}
			provider = e.Name
		}
	}
	return errors.Join(errs...)
}

func reservedSchema(s string) bool {
	return s == "public" || s == "information_schema" || s == "extensions" || len(s) >= 3 && s[:3] == "pg_"
}
