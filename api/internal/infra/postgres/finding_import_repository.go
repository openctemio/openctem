package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// StampAssetsImport records importID (an upload receipt) as the producer of
// the tenant's assets ids (the last import that created or updated them).
func (r *FindingRepository) StampAssetsImport(ctx context.Context, tenantID, importID shared.ID, ids []shared.ID) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	res, err := r.db.ExecContext(ctx, `UPDATE assets SET import_id = $2 WHERE tenant_id = $1 AND id = ANY($3::uuid[])`,
		tenantID.String(), importID.String(), pq.Array(strs))
	if err != nil {
		return 0, fmt.Errorf("stamp assets import: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
