package extension

import (
	"context"
	"database/sql"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Deps is everything the core hands an extension. Every field is set by the
// core at start (Entitlements is a no-grant answer while Grants itself is
// being built); an extension gets no other access to the core.
type Deps struct {
	// Store is scoped database access (no raw pool).
	Store Store
	// Log is the server's structured logger.
	Log *logger.Logger
	// Settings reads the extension's declared configuration keys.
	Settings Settings
	// Entitlements answers whether a grant is on for an organization.
	Entitlements Entitlements
	// AdminAudit is read access to the administrators' audit chain, for an
	// audit sink.
	AdminAudit AdminAuditTrail
	// Env describes the installation.
	Env Environment
}

// Environment describes the installation the extension runs in.
type Environment struct {
	// Production is true when the server runs in production mode.
	Production bool
	// ManagedService is true on a hosted, multi-organization service.
	ManagedService bool
}

// Querier runs statements inside one Store transaction.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store is the extension's database access. Every call runs fn in one
// transaction that commits when fn returns nil and rolls back otherwise.
// Unqualified table names resolve in the extension's Schema first, then in
// the core schema. Core tables are read schema-qualified and only where the
// extension documents it; an extension never writes core tables.
type Store interface {
	// Schema is the extension's schema ("" when it declared none).
	Schema() string
	// InstanceTx is for installation-wide state (no organization).
	InstanceTx(ctx context.Context, fn func(ctx context.Context, q Querier) error) error
	// TenantTx is for one organization's data. The core marks the
	// transaction with the organization (app.current_tenant_id), but the
	// extension still filters every query by tenant_id, like core code.
	TenantTx(ctx context.Context, tenantID shared.ID, fn func(ctx context.Context, q Querier) error) error
}

// Settings reads configuration. Only the keys the extension listed in
// Extension.ConfigKeys are readable; any other key reads as "".
type Settings interface {
	Get(key string) string
}

// Entitlements answers for grants. RequireGrant returns nil when the grant
// is on for the organization and a *limits.ErrGrantRequired otherwise; a
// provider error counts as off.
type Entitlements interface {
	RequireGrant(ctx context.Context, tenantID shared.ID, key limits.GrantKey) error
}

// AuditCursor is a stream's position in the administrators' audit chain.
type AuditCursor struct {
	Position int64
	Hash     string
}

// AdminAuditTrail is read access to the administrators' audit chain (the
// tamper-evident log of platform administration) plus the forward cursor an
// audit sink keeps its position with. It cannot change or delete entries.
type AdminAuditTrail interface {
	// ReadChain returns up to limit chain entries after position, oldest
	// first, with the columns that may leave the installation.
	ReadChain(ctx context.Context, after int64, limit int) ([]admin.AuditChainEntry, error)
	// ChainHead returns the newest chain position and its hash.
	ChainHead(ctx context.Context) (position int64, hash string, err error)
	// VerifyChain recomputes the chain and reports breaks.
	VerifyChain(ctx context.Context) (*admin.AuditChainReport, error)
	// LoadCursor returns the last acknowledged position (zero when none).
	LoadCursor(ctx context.Context) (AuditCursor, error)
	// SaveCursor stores the position; it never moves backwards.
	SaveCursor(ctx context.Context, c AuditCursor) error
}

// Controller is a background reconciliation loop run by the core controller
// manager. Reconcile is idempotent and returns the number of items it
// processed.
type Controller interface {
	Name() string
	Interval() time.Duration
	Reconcile(ctx context.Context) (int, error)
}

// Exclusive is implemented by a controller whose work must run on one
// replica at a time; the core holds a lease for it.
type Exclusive interface {
	Exclusive() bool
}
