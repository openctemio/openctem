// Package extensiontest gives an extension's tests the Deps the core would
// hand it, built by the core's own implementations (the scoped Store, the
// declared-keys Settings, the administrators' audit chain), on a test
// database. An extension's tests import this package and pkg/extension
// only. See docs/development/editions.md.
package extensiontest

import (
	"context"
	"database/sql"

	"github.com/openctemio/openctem/server/internal/extensionhost"
	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	ext "github.com/openctemio/openctem/server/pkg/extension"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Options tune the Deps.
type Options struct {
	// Env answers Settings.Get for the extension's declared keys.
	Env map[string]string
	// Grants answers Entitlements.RequireGrant (nil: every grant off).
	Grants func(tenantID shared.ID, key limits.GrantKey) bool
	// Production and ManagedService fill Deps.Env.
	Production, ManagedService bool
}

type grants func(shared.ID, limits.GrantKey) bool

func (g grants) RequireGrant(_ context.Context, tenantID shared.ID, key limits.GrantKey) error {
	if g != nil && g(tenantID, key) {
		return nil
	}
	return &limits.ErrGrantRequired{Key: key}
}

// Deps returns the Deps the core hands e, on db (nil: no Store and no
// AdminAudit).
func Deps(db *sql.DB, e ext.Extension, o Options) ext.Deps {
	return extensionhost.DepsFor(e, extensionhost.Host{
		DB: db, Log: logger.NewNop(), Production: o.Production, ManagedService: o.ManagedService,
		Entitlements: grants(o.Grants),
		Getenv:       func(k string) string { return o.Env[k] },
	})
}
