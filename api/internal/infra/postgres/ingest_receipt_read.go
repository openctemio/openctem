package postgres

// Reads of ingest receipts (docs/rfcs/RFC-122-ingest-receipts.md §4). Every
// statement is scoped by tenant_id; the per-finding reads apply the caller's
// data scope and the findings list's pentest visibility rule (the viewer
// recorded in ctx).

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// List returns a page of the tenant's receipts, newest first.
func (r *IngestReceiptRepository) List(ctx context.Context, tenantID shared.ID, f ingestreceipt.Filter, p pagination.Pagination) ([]*ingestreceipt.Receipt, int64, error) {
	args := []any{tenantID.String()}
	where := "tenant_id = $1"
	add := func(cond string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(" AND "+cond, len(args))
	}
	if f.SourceKind != "" {
		add("source_kind = $%d", string(f.SourceKind))
	}
	if f.SourceRef != "" {
		add("source_ref = $%d", f.SourceRef)
	}
	if f.ActorUserID != nil {
		add("actor_user_id = $%d", f.ActorUserID.String())
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM ingest_receipts WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count receipts: %w", err)
	}
	q := `SELECT ` + receiptColumns + ` FROM ingest_receipts WHERE ` + where +
		` ORDER BY updated_at DESC, id DESC LIMIT ` + strconv.Itoa(p.Limit()) + ` OFFSET ` + strconv.Itoa(p.Offset())
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list receipts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*ingestreceipt.Receipt, 0, p.Limit())
	for rows.Next() {
		rec, err := scanReceipt(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan receipt: %w", err)
		}
		out = append(out, rec)
	}
	return out, total, rows.Err()
}

// actionScope is the WHERE clause over finding_ingest_actions a (and the
// joined findings f) for one receipt, limited to what the caller may see.
func actionScope(ctx context.Context, tenantID, receiptID shared.ID, scope *shared.DataScope) (string, []any) {
	args := []any{tenantID.String(), receiptID.String()}
	cond, args := dataScopeCond("f.asset_id", scope, args)
	return `a.tenant_id = $1 AND a.receipt_id = $2 AND ` + cond + ` AND ` + pentestVisibilityCond(ctx, "f", "$1"), args
}

// ActionCountsBySeverity counts a receipt's actions per action and finding
// severity, over the findings the caller may see.
func (r *IngestReceiptRepository) ActionCountsBySeverity(ctx context.Context, tenantID, receiptID shared.ID, scope *shared.DataScope) (map[string]map[string]int, error) {
	where, args := actionScope(ctx, tenantID, receiptID, scope)
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.action, COALESCE(f.severity, 'none'), count(*)
		FROM finding_ingest_actions a
		JOIN findings f ON f.tenant_id = a.tenant_id AND f.id = a.finding_id
		WHERE `+where+`
		GROUP BY 1, 2`, args...)
	if err != nil {
		return nil, fmt.Errorf("count receipt actions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[string]int{}
	for rows.Next() {
		var action, sev string
		var n int
		if err := rows.Scan(&action, &sev, &n); err != nil {
			return nil, fmt.Errorf("scan receipt action count: %w", err)
		}
		if out[action] == nil {
			out[action] = map[string]int{}
		}
		out[action][sev] = n
	}
	return out, rows.Err()
}

// ListActions returns a page of a receipt's actions on findings the caller
// may see, optionally of one action.
func (r *IngestReceiptRepository) ListActions(ctx context.Context, tenantID, receiptID shared.ID, action ingestreceipt.Action,
	scope *shared.DataScope, p pagination.Pagination) ([]ingestreceipt.ActionRow, int64, error) {
	where, args := actionScope(ctx, tenantID, receiptID, scope)
	if action != "" {
		args = append(args, string(action))
		where += " AND a.action = $" + strconv.Itoa(len(args))
	}
	from := ` FROM finding_ingest_actions a JOIN findings f ON f.tenant_id = a.tenant_id AND f.id = a.finding_id WHERE ` + where
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*)`+from, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count receipt actions: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT a.finding_id::text, a.action, COALESCE(f.title, ''), COALESCE(f.severity, ''), a.created_at,
		COALESCE(a.policy, ''), a.policy_id::text, a.policy_version`+from+
		` ORDER BY a.created_at DESC, a.finding_id LIMIT `+strconv.Itoa(p.Limit())+` OFFSET `+strconv.Itoa(p.Offset()), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list receipt actions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]ingestreceipt.ActionRow, 0, p.Limit())
	for rows.Next() {
		var row ingestreceipt.ActionRow
		var id, action string
		var policyID sql.NullString
		var version sql.NullInt64
		if err := rows.Scan(&id, &action, &row.Title, &row.Severity, &row.At, &row.Policy, &policyID, &version); err != nil {
			return nil, 0, fmt.Errorf("scan receipt action: %w", err)
		}
		if policyID.Valid {
			if pid, err := shared.IDFromString(policyID.String); err == nil {
				row.PolicyID = &pid
			}
		}
		if version.Valid {
			v := version.Int64
			row.PolicyVersion = &v
		}
		row.FindingID, _ = shared.IDFromString(id)
		row.Action = ingestreceipt.Action(action)
		out = append(out, row)
	}
	return out, total, rows.Err()
}

// FindingActions returns the newest receipts that acted on one finding of
// the tenant (the caller has checked it may read the finding).
func (r *IngestReceiptRepository) FindingActions(ctx context.Context, tenantID, findingID shared.ID, limit int) ([]ingestreceipt.FindingAction, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.receipt_id::text, r.source_kind, r.source_ref, COALESCE(r.tool_name, ''), a.action, a.created_at
		FROM finding_ingest_actions a
		JOIN ingest_receipts r ON r.tenant_id = a.tenant_id AND r.id = a.receipt_id
		WHERE a.tenant_id = $1 AND a.finding_id = $2
		ORDER BY a.created_at DESC
		LIMIT $3`, tenantID.String(), findingID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list finding receipts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ingestreceipt.FindingAction
	for rows.Next() {
		var fa ingestreceipt.FindingAction
		var id, kind, action string
		var at time.Time
		if err := rows.Scan(&id, &kind, &fa.SourceRef, &fa.ToolName, &action, &at); err != nil {
			return nil, fmt.Errorf("scan finding receipt: %w", err)
		}
		fa.ReceiptID, _ = shared.IDFromString(id)
		fa.SourceKind = ingestreceipt.SourceKind(kind)
		fa.Action = ingestreceipt.Action(action)
		fa.At = at
		out = append(out, fa)
	}
	return out, rows.Err()
}

// itemScope is the visibility of a receipt's items: an item on an asset is
// visible when the asset is in the caller's scope; an item with no asset
// (rejected before it had one, quarantined) only to an unrestricted caller.
func itemScope(tenantID, receiptID shared.ID, scope *shared.DataScope) (string, []any) {
	args := []any{tenantID.String(), receiptID.String()}
	cond, args := dataScopeCond("i.asset_id", scope, args)
	if scope != nil {
		cond = "(i.asset_id IS NOT NULL AND " + cond + ")"
	}
	return `i.tenant_id = $1 AND i.receipt_id = $2 AND ` + cond, args
}

// ItemCounts counts a receipt's items per disposition, over the items the
// caller may see.
func (r *IngestReceiptRepository) ItemCounts(ctx context.Context, tenantID, receiptID shared.ID, scope *shared.DataScope) (map[string]int, error) {
	where, args := itemScope(tenantID, receiptID, scope)
	rows, err := r.db.QueryContext(ctx, `SELECT i.disposition, count(*) FROM ingest_receipt_items i WHERE `+where+` GROUP BY 1`, args...)
	if err != nil {
		return nil, fmt.Errorf("count receipt items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var d string
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			return nil, fmt.Errorf("scan receipt item count: %w", err)
		}
		out[d] = n
	}
	return out, rows.Err()
}

// ListItems lists a receipt's items the caller may see, newest first;
// disposition "" lists all.
func (r *IngestReceiptRepository) ListItems(ctx context.Context, tenantID, receiptID shared.ID, disposition ingestreceipt.Disposition,
	scope *shared.DataScope, p pagination.Pagination) ([]ingestreceipt.ItemRow, int64, error) {
	where, args := itemScope(tenantID, receiptID, scope)
	if disposition != "" {
		args = append(args, string(disposition))
		where += " AND i.disposition = $" + strconv.Itoa(len(args))
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM ingest_receipt_items i WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count receipt items: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT i.item_key, i.disposition, i.reason_code, i.asset_id::text, COALESCE(i.tool_name, ''),
		COALESCE(i.title, ''), COALESCE(i.severity, ''), COALESCE(i.policy, ''), i.policy_id::text, COALESCE(i.policy_version, 0), i.created_at
		FROM ingest_receipt_items i WHERE `+where+` ORDER BY i.created_at DESC, i.item_key LIMIT `+strconv.Itoa(p.Limit())+
		` OFFSET `+strconv.Itoa(p.Offset()), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list receipt items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]ingestreceipt.ItemRow, 0, p.Limit())
	for rows.Next() {
		var row ingestreceipt.ItemRow
		var disp string
		var assetID, policyID sql.NullString
		if err := rows.Scan(&row.Key, &disp, &row.ReasonCode, &assetID, &row.Tool, &row.Title, &row.Severity, &row.Policy,
			&policyID, &row.PolicyVersion, &row.At); err != nil {
			return nil, 0, fmt.Errorf("scan receipt item: %w", err)
		}
		row.Disposition = ingestreceipt.Disposition(disp)
		if assetID.Valid {
			if id, err := shared.IDFromString(assetID.String); err == nil {
				row.AssetID = &id
			}
		}
		if policyID.Valid {
			if id, err := shared.IDFromString(policyID.String); err == nil {
				row.PolicyID = &id
			}
		}
		out = append(out, row)
	}
	return out, total, rows.Err()
}
