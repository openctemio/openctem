// Package extensionhost is the core (host) side of the public extension API
// (pkg/extension, docs/development/editions.md): it checks the extensions a
// build passed to server.Main, builds the Deps each one gets from core
// services, and wires what they add into the server. Nothing here is visible
// to an extension; an extension imports only pkg/extension and other public
// server/pkg packages.
package extensionhost

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/infra/controller"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	ext "github.com/openctemio/openctem/server/pkg/extension"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/version"
)

// Host is what the core builds an extension's Deps from.
type Host struct {
	DB             *sql.DB
	Log            *logger.Logger
	Production     bool
	ManagedService bool
	// Entitlements answers RequireGrant (nil: every grant off).
	Entitlements ext.Entitlements
	// Getenv reads the environment (nil: os.Getenv).
	Getenv func(string) string
}

// Set is the checked list of a build's extensions, in the order the build
// passed them (empty for Community).
type Set struct {
	exts []ext.Extension
}

// New checks the build's extensions (each one valid, unique names, schemas
// and config keys, at most one grant provider, no core setting declared) and
// returns them as a Set. The server refuses to start on an error.
func New(exts []ext.Extension) (*Set, error) {
	if err := ext.ValidateBuild(exts); err != nil {
		return nil, err
	}
	reg := config.Registry()
	out := make([]ext.Extension, 0, len(exts))
	for _, e := range exts {
		for _, k := range e.ConfigKeys {
			if _, core := reg.Lookup(k); core {
				return nil, fmt.Errorf("extension %q: config key %s belongs to the core", e.Name, k)
			}
		}
		e.ConfigKeys = append([]string(nil), e.ConfigKeys...)
		out = append(out, e)
	}
	return &Set{exts: out}, nil
}

// Empty reports whether the build has no extension (Community).
func (s *Set) Empty() bool { return s == nil || len(s.exts) == 0 }

// Extensions returns a copy of the build's extensions.
func (s *Set) Extensions() []ext.Extension {
	if s == nil {
		return nil
	}
	return append([]ext.Extension(nil), s.exts...)
}

// Info lists the extensions for /api/v1/version.
func (s *Set) Info() []version.Extension {
	if s == nil {
		return nil
	}
	out := make([]version.Extension, 0, len(s.exts))
	for _, e := range s.exts {
		out = append(out, version.Extension{Name: e.Name, Version: e.Version})
	}
	return out
}

// Declares reports whether an extension of the build declared config key.
func (s *Set) Declares(key string) bool {
	if s == nil {
		return false
	}
	for _, e := range s.exts {
		for _, k := range e.ConfigKeys {
			if k == key {
				return true
			}
		}
	}
	return false
}

// DepsFor builds the Deps the core would hand extension e (also used by
// pkg/extension/extensiontest, so an extension's tests run against the
// real core implementations).
func DepsFor(e ext.Extension, h Host) ext.Deps {
	getenv := h.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	ent := h.Entitlements
	if ent == nil {
		ent = noGrants{}
	}
	d := ext.Deps{
		Log:          h.Log,
		Settings:     newSettings(e.ConfigKeys, getenv),
		Entitlements: ent,
		Env:          ext.Environment{Production: h.Production, ManagedService: h.ManagedService},
	}
	if h.DB != nil {
		d.Store = &store{db: h.DB, schema: e.Schema}
		d.AdminAudit = &auditTrail{repo: postgres.NewAuditLogRepository(&postgres.DB{DB: h.DB}), db: h.DB}
	}
	return d
}

type noGrants struct{}

func (noGrants) RequireGrant(_ context.Context, _ shared.ID, key limits.GrantKey) error {
	return &limits.ErrGrantRequired{Key: key}
}

// Grants returns the build's grant provider, or nil when there is none.
// When the extension fails to build it, the error is logged and the core
// runs with no provider: an extension can never stop the server or switch
// off a Community feature, only leave its own grants off.
func (s *Set) Grants(ctx context.Context, h Host) limits.GrantProvider {
	if s == nil {
		return nil
	}
	for _, e := range s.exts {
		if e.Grants == nil {
			continue
		}
		d := DepsFor(e, h)
		p, err := e.Grants(ctx, d)
		if err != nil || p == nil {
			if err != nil && h.Log != nil {
				h.Log.Error("extension grant provider failed to start; every grant stays off", "extension", e.Name, "error", err)
			}
			return nil
		}
		return p
	}
	return nil
}

// Controllers returns every extension's controllers for the core controller
// manager (an Exclusive controller stays exclusive). An error stops the
// start.
func (s *Set) Controllers(ctx context.Context, h Host) ([]controller.Controller, error) {
	if s == nil {
		return nil, nil
	}
	var out []controller.Controller
	for _, e := range s.exts {
		if e.Controllers == nil {
			continue
		}
		cs, err := e.Controllers(ctx, DepsFor(e, h))
		if err != nil {
			return nil, fmt.Errorf("extension %q controllers: %w", e.Name, err)
		}
		for _, c := range cs {
			if c == nil {
				return nil, fmt.Errorf("extension %q returned a nil controller", e.Name)
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// Routes returns every extension's routes, validated (none in the Community
// build). A route path used by two extensions, or any route the core
// refuses, is an error that stops the start.
func (s *Set) Routes(ctx context.Context, h Host) ([]Route, error) {
	if s == nil {
		return nil, nil
	}
	r := &router{known: map[string]bool{}, seen: map[string]bool{}}
	for _, p := range permission.AllPermissions() {
		r.known[p.String()] = true
	}
	for _, e := range s.exts {
		if e.Routes == nil {
			continue
		}
		if err := e.Routes(ctx, r, DepsFor(e, h)); err != nil {
			return nil, fmt.Errorf("extension %q routes: %w", e.Name, err)
		}
	}
	return r.routes, nil
}
