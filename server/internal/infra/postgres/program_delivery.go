package postgres

// Outbound delivery of events about private program assets: routing
// decisions, program channels and the owner's organization-channel opt-in.
// Design: docs/rfcs/RFC-065-bug-bounty-programs.md §15.4.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// orgRestrictedAssetSQL is the condition "asset ra (an assets alias) may
// not reach organization-wide channels": it is program-only, linked to a
// private program that has not opted in, and to no public program. It is
// the one predicate every outbound path uses (the resolver, the EASM alert
// digest).
const orgRestrictedAssetSQL = `(ra.program_only
	AND EXISTS (SELECT 1 FROM asset_program_links rl
	            JOIN bounty_programs rp ON rp.tenant_id = rl.tenant_id AND rp.id = rl.program_id
	            WHERE rl.tenant_id = ra.tenant_id AND rl.asset_id = ra.id
	              AND rp.visibility = 'private' AND NOT rp.org_channels_opt_in)
	AND NOT EXISTS (SELECT 1 FROM asset_program_links rl
	            JOIN bounty_programs rp ON rp.tenant_id = rl.tenant_id AND rp.id = rl.program_id
	            WHERE rl.tenant_id = ra.tenant_id AND rl.asset_id = ra.id AND rp.visibility <> 'private'))`

// ProgramDeliveryRepository implements bp.DeliveryResolver and
// bp.DeliveryStore.
type ProgramDeliveryRepository struct{ db *DB }

// NewProgramDeliveryRepository creates the repository.
func NewProgramDeliveryRepository(db *DB) *ProgramDeliveryRepository {
	return &ProgramDeliveryRepository{db: db}
}

var (
	_ bp.DeliveryResolver = (*ProgramDeliveryRepository)(nil)
	_ bp.DeliveryStore    = (*ProgramDeliveryRepository)(nil)
)

func deliveryIDStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !id.IsZero() {
			out = append(out, id.String())
		}
	}
	return out
}

// subjectAssetsSQL resolves a subject to the tenant's asset ids ($1
// tenant, $2 assets, $3 findings, $4 exposure events, $5 finding status
// approvals).
const subjectAssetsSQL = `
	SELECT a.id FROM assets a WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])
	UNION SELECT f.asset_id FROM findings f WHERE f.tenant_id = $1 AND f.id = ANY($3::uuid[]) AND f.asset_id IS NOT NULL
	UNION SELECT e.asset_id FROM exposure_events e WHERE e.tenant_id = $1 AND e.id = ANY($4::uuid[]) AND e.asset_id IS NOT NULL
	UNION SELECT f.asset_id FROM finding_status_approvals fa
	      JOIN findings f ON f.tenant_id = fa.tenant_id AND f.id = fa.finding_id
	      WHERE fa.tenant_id = $1 AND fa.id = ANY($5::uuid[]) AND f.asset_id IS NOT NULL`

// Resolve returns the routing decision for an event about subject.
func (r *ProgramDeliveryRepository) Resolve(ctx context.Context, tenantID shared.ID, s bp.DeliverySubject) (bp.Delivery, error) {
	var d bp.Delivery
	if s.Empty() {
		return d, nil
	}
	// Most tenants have no private program: one cheap probe.
	var hasPrivate bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM bounty_programs WHERE tenant_id = $1 AND visibility = 'private')`,
		tenantID.String()).Scan(&hasPrivate); err != nil {
		return d, fmt.Errorf("probe private programs: %w", err)
	}
	if !hasPrivate {
		return d, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		WITH subj AS (`+subjectAssetsSQL+`)
		SELECT ra.id, `+orgRestrictedAssetSQL+`, p.id, p.name, COALESCE(p.handle, ''), t
		FROM `+programLinkTags+`
		JOIN assets ra ON ra.tenant_id = l.tenant_id AND ra.id = l.asset_id
		WHERE p.visibility = 'private' AND t LIKE 'program:%'
		  AND l.tenant_id = $1 AND ra.id IN (SELECT id FROM subj)`,
		tenantID.String(), pq.Array(deliveryIDStrings(s.AssetIDs)), pq.Array(deliveryIDStrings(s.FindingIDs)),
		pq.Array(deliveryIDStrings(s.ExposureIDs)), pq.Array(deliveryIDStrings(s.ApprovalIDs)))
	if err != nil {
		return d, fmt.Errorf("resolve delivery: %w", err)
	}
	defer rows.Close()
	restricted := map[string][]shared.ID{}
	seen := map[shared.ID]bool{}
	var order []string
	for rows.Next() {
		var assetID, programID, name, handle, tag string
		var isRestricted bool
		if err := rows.Scan(&assetID, &isRestricted, &programID, &name, &handle, &tag); err != nil {
			return d, fmt.Errorf("scan delivery: %w", err)
		}
		pid, err := shared.IDFromString(programID)
		if err != nil {
			return d, fmt.Errorf("program id: %w", err)
		}
		if isRestricted {
			if _, ok := restricted[assetID]; !ok {
				order = append(order, assetID)
			}
			restricted[assetID] = append(restricted[assetID], pid)
		}
		if !seen[pid] {
			seen[pid] = true
			d.Programs = append(d.Programs, bp.DeliveryProgram{ID: pid, Name: name, Handle: handle, Tag: tag})
		}
	}
	if err := rows.Err(); err != nil {
		return d, fmt.Errorf("read delivery: %w", err)
	}
	for _, a := range order {
		d.Restricted = append(d.Restricted, restricted[a])
	}
	if len(d.Programs) == 0 {
		return d, nil
	}
	ids := make([]shared.ID, 0, len(d.Programs))
	for _, p := range d.Programs {
		ids = append(ids, p.ID)
	}
	d.Channels, err = r.channelMap(ctx, tenantID, ids)
	return d, err
}

func (r *ProgramDeliveryRepository) channelMap(ctx context.Context, tenantID shared.ID, programIDs []shared.ID) (map[shared.ID]map[shared.ID]bool, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT integration_id, program_id FROM bounty_program_channels
		WHERE tenant_id = $1 AND program_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(deliveryIDStrings(programIDs)))
	if err != nil {
		return nil, fmt.Errorf("list program channels: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID]map[shared.ID]bool{}
	for rows.Next() {
		var iid, pid string
		if err := rows.Scan(&iid, &pid); err != nil {
			return nil, fmt.Errorf("scan program channel: %w", err)
		}
		i, err1 := shared.IDFromString(iid)
		p, err2 := shared.IDFromString(pid)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("program channel ids: %s %s", iid, pid)
		}
		if out[i] == nil {
			out[i] = map[shared.ID]bool{}
		}
		out[i][p] = true
	}
	return out, rows.Err()
}

// RestrictedAssets returns the ids (of assetIDs) of the tenant's assets
// that may not reach organization-wide channels.
func (r *ProgramDeliveryRepository) RestrictedAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	ids := deliveryIDStrings(assetIDs)
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT ra.id FROM assets ra
		WHERE ra.tenant_id = $1 AND ra.id = ANY($2::uuid[]) AND `+orgRestrictedAssetSQL,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("restricted assets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan restricted asset: %w", err)
		}
		if sid, err := shared.IDFromString(id); err == nil {
			out[sid] = true
		}
	}
	return out, rows.Err()
}

// Channels lists the integrations attached to the program.
func (r *ProgramDeliveryRepository) Channels(ctx context.Context, tenantID, programID shared.ID) ([]bp.Channel, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.integration_id, i.name, i.provider, c.created_by
		FROM bounty_program_channels c
		JOIN integrations i ON i.tenant_id = c.tenant_id AND i.id = c.integration_id
		WHERE c.tenant_id = $1 AND c.program_id = $2
		ORDER BY i.name, c.integration_id`, tenantID.String(), programID.String())
	if err != nil {
		return nil, fmt.Errorf("list program channels: %w", err)
	}
	defer rows.Close()
	out := []bp.Channel{}
	for rows.Next() {
		var iid, name, provider string
		var by sql.NullString
		if err := rows.Scan(&iid, &name, &provider, &by); err != nil {
			return nil, fmt.Errorf("scan program channel: %w", err)
		}
		c := bp.Channel{Name: name, Provider: provider}
		if c.IntegrationID, err = shared.IDFromString(iid); err != nil {
			return nil, fmt.Errorf("integration id: %w", err)
		}
		if by.Valid {
			if u, err := shared.IDFromString(by.String); err == nil {
				c.CreatedBy = &u
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AttachChannel attaches a notification integration of the tenant. The
// integration is looked up in the caller's tenant, so another tenant's id
// attaches nothing (ErrChannelNotFound).
func (r *ProgramDeliveryRepository) AttachChannel(ctx context.Context, tenantID, programID, integrationID shared.ID, by *shared.ID) error {
	var byArg any
	if by != nil && !by.IsZero() {
		byArg = by.String()
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO bounty_program_channels (tenant_id, program_id, integration_id, created_by)
		SELECT i.tenant_id, p.id, i.id, $4
		FROM integrations i
		JOIN bounty_programs p ON p.tenant_id = i.tenant_id AND p.id = $2
		WHERE i.tenant_id = $1 AND i.id = $3 AND i.category = 'notification'
		ON CONFLICT DO NOTHING`, tenantID.String(), programID.String(), integrationID.String(), byArg)
	if err != nil {
		return fmt.Errorf("attach program channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	// Nothing inserted: already attached (fine) or no such integration.
	var exists bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM bounty_program_channels
		WHERE tenant_id = $1 AND program_id = $2 AND integration_id = $3)`,
		tenantID.String(), programID.String(), integrationID.String()).Scan(&exists); err != nil {
		return fmt.Errorf("check program channel: %w", err)
	}
	if !exists {
		return bp.ErrChannelNotFound
	}
	return nil
}

// DetachChannel detaches the integration from the program.
func (r *ProgramDeliveryRepository) DetachChannel(ctx context.Context, tenantID, programID, integrationID shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM bounty_program_channels
		WHERE tenant_id = $1 AND program_id = $2 AND integration_id = $3`,
		tenantID.String(), programID.String(), integrationID.String())
	if err != nil {
		return fmt.Errorf("detach program channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return bp.ErrChannelNotFound
	}
	return nil
}

// OrgChannels reports whether the program allows organization channels.
func (r *ProgramDeliveryRepository) OrgChannels(ctx context.Context, tenantID, programID shared.ID) (bool, error) {
	var on bool
	err := r.db.QueryRowContext(ctx, `SELECT org_channels_opt_in FROM bounty_programs WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), programID.String()).Scan(&on)
	if errors.Is(err, sql.ErrNoRows) {
		return false, bp.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("read org channels: %w", err)
	}
	return on, nil
}

// SetOrgChannels sets whether the program allows organization channels.
func (r *ProgramDeliveryRepository) SetOrgChannels(ctx context.Context, tenantID, programID shared.ID, enabled bool) error {
	res, err := r.db.ExecContext(ctx, `UPDATE bounty_programs SET org_channels_opt_in = $3, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), programID.String(), enabled)
	if err != nil {
		return fmt.Errorf("set org channels: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return bp.ErrNotFound
	}
	return nil
}
