package extensionhost

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ext "github.com/openctemio/openctem/api/pkg/extension"
)

// store is the extension's scoped database access: one transaction per
// call, the extension schema first on the search path, the organization set
// on tenant transactions. The pool itself is never handed out.
type store struct {
	db     *sql.DB
	schema string
}

func (s *store) Schema() string { return s.schema }

func (s *store) InstanceTx(ctx context.Context, fn func(context.Context, ext.Querier) error) error {
	return s.run(ctx, nil, fn)
}

func (s *store) TenantTx(ctx context.Context, tenantID shared.ID, fn func(context.Context, ext.Querier) error) error {
	if tenantID.IsZero() {
		return fmt.Errorf("%w: tenant transaction without an organization", shared.ErrValidation)
	}
	return s.run(ctx, &tenantID, fn)
}

func (s *store) run(ctx context.Context, tenantID *shared.ID, fn func(context.Context, ext.Querier) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("extension store: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if s.schema != "" {
		// The schema name was validated at registration; quoted anyway.
		path := `"` + strings.ReplaceAll(s.schema, `"`, `""`) + `"`
		if _, err = tx.ExecContext(ctx, `SELECT set_config('search_path', $1 || ', ' || current_setting('search_path'), true)`, path); err != nil {
			return fmt.Errorf("extension store: search path: %w", err)
		}
	}
	tenant := ""
	if tenantID != nil {
		tenant = tenantID.String()
	}
	// Always set (empty for an installation transaction) so a pooled
	// connection never carries another organization's mark.
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.current_tenant_id', $1, true)`, tenant); err != nil {
		return fmt.Errorf("extension store: tenant: %w", err)
	}
	if fnErr := fn(ctx, tx); fnErr != nil {
		err = fnErr
		return err
	}
	if cErr := tx.Commit(); cErr != nil {
		err = fmt.Errorf("extension store: commit: %w", cErr)
		return err
	}
	return nil
}

// auditTrail adapts the core audit repository to ext.AdminAuditTrail.
type auditTrail struct {
	repo *postgres.AuditLogRepository
	db   *sql.DB
}

// adminAuditCursorName is the cursor row an extension's audit stream uses
// (the same row the core stream uses, so the position survives an edition
// change and the stream never runs twice: see Claims).
const adminAuditCursorName = "default"

func (a *auditTrail) ReadChain(ctx context.Context, after int64, limit int) ([]admin.AuditChainEntry, error) {
	if limit <= 0 || limit > 10000 {
		return nil, fmt.Errorf("%w: limit must be 1 to 10000", shared.ErrValidation)
	}
	return a.repo.ReadForwardRows(ctx, after, limit)
}

func (a *auditTrail) ChainHead(ctx context.Context) (int64, string, error) {
	return a.repo.ChainHead(ctx)
}

func (a *auditTrail) VerifyChain(ctx context.Context) (*admin.AuditChainReport, error) {
	return a.repo.VerifyChain(ctx)
}

func (a *auditTrail) LoadCursor(ctx context.Context) (ext.AuditCursor, error) {
	var c ext.AuditCursor
	err := a.db.QueryRowContext(ctx,
		`SELECT position, hash FROM admin_audit_forward_cursor WHERE name = $1`, adminAuditCursorName).
		Scan(&c.Position, &c.Hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return c, fmt.Errorf("read admin audit forward cursor: %w", err)
	}
	return c, nil
}

func (a *auditTrail) SaveCursor(ctx context.Context, c ext.AuditCursor) error {
	if c.Position < 0 {
		return errors.New("audit cursor position must not be negative")
	}
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO admin_audit_forward_cursor (name, position, hash) VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE
		   SET position = EXCLUDED.position, hash = EXCLUDED.hash, updated_at = now()
		 WHERE admin_audit_forward_cursor.position < EXCLUDED.position`,
		adminAuditCursorName, c.Position, c.Hash)
	if err != nil {
		return fmt.Errorf("save admin audit forward cursor: %w", err)
	}
	return nil
}
