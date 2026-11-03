// Package extension is the core (host) side of the public extension API
// (pkg/extension, docs/development/extension-api.md): it builds the Deps an
// extension gets from core services and wires what the extension registered
// into the server. Nothing here is visible to an extension; an extension
// imports only pkg/extension and other public api/pkg packages.
package extension

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ext "github.com/openctemio/openctem/api/pkg/extension"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Community is the edition name of a build with no extension.
const Community = ext.Community

// Name is the edition of this build.
func Name() string { return ext.Name() }

// Runner is a grant provider that keeps itself fresh in the background.
type Runner = ext.Runner

// claimable are core settings an extension may take over by listing them in
// ConfigKeys: the core feature that reads them then steps aside, so the
// feature runs once, in the extension. Any other core setting (the secrets
// above all) is refused: an extension never reads core configuration.
var claimable = map[string]bool{
	"ADMIN_AUDIT_SINK":                    true,
	"ADMIN_AUDIT_SINK_SECRET":             true,
	"ADMIN_AUDIT_SINK_SYSLOG_CA_FILE":     true,
	"ADMIN_AUDIT_SINK_SYSLOG_CLIENT_CERT": true,
	"ADMIN_AUDIT_SINK_SYSLOG_CLIENT_KEY":  true,
	"ADMIN_AUDIT_SINK_HEAD_INTERVAL":      true,
}

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

// Check validates the registered extension against the core: its config
// keys may not name a core setting unless the core lets an extension claim
// it. The server refuses to start on an error.
func Check() error {
	e, ok := ext.Registered()
	if !ok {
		return nil
	}
	reg := config.Registry()
	for _, k := range e.ConfigKeys {
		if _, core := reg.Lookup(k); core && !claimable[k] {
			return fmt.Errorf("extension %q: config key %s belongs to the core", e.Name, k)
		}
	}
	return nil
}

// Claims reports whether the registered extension took over core setting
// key (see claimable).
func Claims(key string) bool {
	e, ok := ext.Registered()
	if !ok || !claimable[key] {
		return false
	}
	for _, k := range e.ConfigKeys {
		if k == key {
			return true
		}
	}
	return false
}

// Deps builds the Deps of the registered extension (zero Deps in the
// Community build).
func Deps(h Host) ext.Deps {
	e, ok := ext.Registered()
	if !ok {
		return ext.Deps{}
	}
	return DepsFor(e, h)
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

// Grants returns the registered extension's grant provider, or nil when
// there is none. When the extension fails to build it, the error is logged
// and the core runs with no provider: an extension can never stop the
// server or switch off a Community feature, only leave its own grants off.
func Grants(ctx context.Context, d ext.Deps) limits.GrantProvider {
	e, ok := ext.Registered()
	if !ok || e.Grants == nil {
		return nil
	}
	p, err := e.Grants(ctx, d)
	if err != nil || p == nil {
		if err != nil && d.Log != nil {
			d.Log.Error("extension grant provider failed to start; every grant stays off", "edition", e.Name, "error", err)
		}
		return nil
	}
	return p
}

// Controllers returns the registered extension's controllers for the core
// controller manager (an Exclusive controller stays exclusive). An
// error stops the start.
func Controllers(ctx context.Context, d ext.Deps) ([]controller.Controller, error) {
	e, ok := ext.Registered()
	if !ok || e.Controllers == nil {
		return nil, nil
	}
	cs, err := e.Controllers(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("extension %q controllers: %w", e.Name, err)
	}
	out := make([]controller.Controller, 0, len(cs))
	for _, c := range cs {
		if c == nil {
			return nil, fmt.Errorf("extension %q returned a nil controller", e.Name)
		}
		out = append(out, c)
	}
	return out, nil
}
