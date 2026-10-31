package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CommandContentPinsRepository stores what a signed job pinned
// (commands.content_pins; docs/architecture/wordlists.md). The update is
// scoped to the command's tenant.
type CommandContentPinsRepository struct {
	db *DB
}

// NewCommandContentPinsRepository creates a CommandContentPinsRepository.
func NewCommandContentPinsRepository(db *DB) *CommandContentPinsRepository {
	return &CommandContentPinsRepository{db: db}
}

// RecordContentPins stores pins on the command; a retry overwrites them.
func (r *CommandContentPinsRepository) RecordContentPins(ctx context.Context, tenantID, commandID shared.ID, pins *scanrun.ContentPins) error {
	b, err := json.Marshal(pins)
	if err != nil {
		return fmt.Errorf("encode content pins: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE commands SET content_pins = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), commandID.String(), b); err != nil {
		return fmt.Errorf("record content pins: %w", err)
	}
	return nil
}
