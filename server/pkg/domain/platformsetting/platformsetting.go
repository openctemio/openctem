// Package platformsetting is the store of the platform-wide settings an
// administrator changes in the admin console (table platform_settings, one row
// per key). Not tenant data: only the admin console writes it.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package platformsetting

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Errors of the store.
var (
	// ErrNotFound: nothing is stored under the key.
	ErrNotFound = errors.New("platform setting not found")
	// ErrVersionConflict: the row changed since the caller read it.
	ErrVersionConflict = errors.New("platform setting changed since it was read")
)

// Sources of a stored value.
const (
	SourceConsole     = "console"
	SourceEnvironment = "environment"
	// SourceMigration marks a row seeded by a migration (an upgrade default).
	SourceMigration = "migration"
)

// State is one stored setting.
type State struct {
	Value     json.RawMessage
	Version   int
	Source    string
	UpdatedBy *shared.ID
	UpdatedAt time.Time
}

// Repository stores settings by key. Update is a compare-and-swap on the
// version: a stale write is refused, never merged.
type Repository interface {
	Get(ctx context.Context, key string) (State, error)
	// CreateIfAbsent stores version 1 under key unless something is stored;
	// it reports whether it created the row.
	CreateIfAbsent(ctx context.Context, key string, s State) (bool, error)
	// Update replaces the value when the stored version is expectedVersion,
	// and returns the new state (version + 1, source console).
	Update(ctx context.Context, key string, value json.RawMessage, expectedVersion int, by shared.ID, at time.Time) (State, error)
}
