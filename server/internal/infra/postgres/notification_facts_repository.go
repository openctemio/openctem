package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/notifymsg"
)

// NotificationFactsRepository reads what a channel message says about an
// event's object at send time (docs/architecture/notification-system.md,
// "Channel messages"). Every query is scoped to the event's tenant, joins
// included: an aggregate id of another tenant resolves to nothing.
type NotificationFactsRepository struct {
	db *DB
}

// NewNotificationFactsRepository builds the repository.
func NewNotificationFactsRepository(db *DB) *NotificationFactsRepository {
	return &NotificationFactsRepository{db: db}
}

// Organization returns the tenant's display name and default language.
func (r *NotificationFactsRepository) Organization(ctx context.Context, tenantID shared.ID) (name, language string, err error) {
	var lang sql.NullString
	err = r.db.QueryRowContext(ctx,
		`SELECT name, settings->'general'->>'language' FROM tenants WHERE id = $1`, tenantID.String()).Scan(&name, &lang)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("read organization for notification: %w", err)
	}
	return name, lang.String, nil
}

// Finding returns the facts of one finding of the tenant (nil: none).
func (r *NotificationFactsRepository) Finding(ctx context.Context, tenantID, findingID shared.ID) (*notifymsg.Facts, error) {
	var (
		title, cve, assetName, assetType sql.NullString
		kev                              sql.NullBool
		epss                             sql.NullFloat64
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT f.title, f.cve_id, f.is_in_kev, f.epss_score, a.name, a.asset_type
		FROM findings f
		LEFT JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
		WHERE f.tenant_id = $1 AND f.id = $2`, tenantID.String(), findingID.String()).
		Scan(&title, &cve, &kev, &epss, &assetName, &assetType)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read finding for notification: %w", err)
	}
	f := &notifymsg.Facts{Title: title.String, CVE: cve.String, KEV: kev.Bool,
		AssetName: assetName.String, AssetType: assetType.String}
	if epss.Valid {
		v := epss.Float64
		f.EPSS = &v
	}
	return f, nil
}

// Exposure returns the facts of one exposure of the tenant (nil: none).
func (r *NotificationFactsRepository) Exposure(ctx context.Context, tenantID, exposureID shared.ID) (*notifymsg.Facts, error) {
	var title, class, assetName, assetType sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT e.title, e.event_type, a.name, a.asset_type
		FROM exposure_events e
		LEFT JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
		WHERE e.tenant_id = $1 AND e.id = $2`, tenantID.String(), exposureID.String()).
		Scan(&title, &class, &assetName, &assetType)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read exposure for notification: %w", err)
	}
	return &notifymsg.Facts{Title: title.String, Class: class.String,
		AssetName: assetName.String, AssetType: assetType.String}, nil
}

// maxFactAssets bounds one lookup; a message lists far fewer.
const maxFactAssets = 50

// AssetSources returns the tenant's assets with these ids, in the order
// given, each with the first name (alphabetically) that resolves to it.
func (r *NotificationFactsRepository) AssetSources(ctx context.Context, tenantID shared.ID, ids []string) ([]notifymsg.AssetRef, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > maxFactAssets {
		ids = ids[:maxFactAssets]
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, COALESCE(src.name, '')
		FROM assets a
		LEFT JOIN LATERAL (
			SELECT s.name FROM asset_relationships rel
			JOIN assets s ON s.id = rel.source_asset_id AND s.tenant_id = rel.tenant_id
			WHERE rel.tenant_id = a.tenant_id AND rel.target_asset_id = a.id
			  AND rel.relationship_type = 'resolves_to' AND s.deleted_at IS NULL
			ORDER BY s.name LIMIT 1
		) src ON true
		WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND a.deleted_at IS NULL`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read assets for notification: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byID := map[string]notifymsg.AssetRef{}
	for rows.Next() {
		var a notifymsg.AssetRef
		if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.From); err != nil {
			return nil, fmt.Errorf("scan asset for notification: %w", err)
		}
		byID[a.ID] = a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets for notification: %w", err)
	}
	out := make([]notifymsg.AssetRef, 0, len(byID))
	for _, id := range ids {
		if a, ok := byID[id]; ok {
			out = append(out, a)
			delete(byID, id)
		}
	}
	// Ids that are not uuid-formatted the same way fall back to name order.
	rest := make([]notifymsg.AssetRef, 0, len(byID))
	for _, a := range byID {
		rest = append(rest, a)
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].Name < rest[j].Name })
	return append(out, rest...), nil
}
