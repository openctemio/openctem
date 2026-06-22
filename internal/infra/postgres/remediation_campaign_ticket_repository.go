package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
)

// RemediationCampaignTicketRepository implements remediation.CampaignTicketRepository.
type RemediationCampaignTicketRepository struct {
	db *DB
}

// NewRemediationCampaignTicketRepository creates a new repository.
func NewRemediationCampaignTicketRepository(db *DB) *RemediationCampaignTicketRepository {
	return &RemediationCampaignTicketRepository{db: db}
}

const rctSelectCols = `id, tenant_id, campaign_id, provider, issue_key, issue_url, created_at, updated_at`

func (r *RemediationCampaignTicketRepository) Create(ctx context.Context, t *remediation.CampaignTicket) error {
	query := `INSERT INTO remediation_campaign_tickets (
		id, tenant_id, campaign_id, provider, issue_key, issue_url, created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`

	_, err := r.db.ExecContext(ctx, query,
		t.ID().String(), t.TenantID().String(), t.CampaignID().String(),
		t.Provider(), t.IssueKey(), t.IssueURL(), t.CreatedAt(), t.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create campaign ticket: %w", err)
	}
	return nil
}

func (r *RemediationCampaignTicketRepository) GetByCampaignAndProvider(ctx context.Context, tenantID, campaignID shared.ID, provider string) (*remediation.CampaignTicket, error) {
	query := "SELECT " + rctSelectCols + ` FROM remediation_campaign_tickets
		WHERE tenant_id = $1 AND campaign_id = $2 AND provider = $3`
	return r.scanOne(ctx, query, tenantID.String(), campaignID.String(), provider)
}

func (r *RemediationCampaignTicketRepository) GetByIssueKey(ctx context.Context, tenantID shared.ID, provider, issueKey string) (*remediation.CampaignTicket, error) {
	query := "SELECT " + rctSelectCols + ` FROM remediation_campaign_tickets
		WHERE tenant_id = $1 AND provider = $2 AND issue_key = $3`
	return r.scanOne(ctx, query, tenantID.String(), provider, issueKey)
}

func (r *RemediationCampaignTicketRepository) ListByCampaignIDs(ctx context.Context, tenantID shared.ID, campaignIDs []shared.ID) (map[string]*remediation.CampaignTicket, error) {
	out := make(map[string]*remediation.CampaignTicket, len(campaignIDs))
	if len(campaignIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(campaignIDs))
	for i, id := range campaignIDs {
		ids[i] = id.String()
	}

	query := "SELECT " + rctSelectCols + ` FROM remediation_campaign_tickets
		WHERE tenant_id = $1 AND campaign_id = ANY($2)`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to list campaign tickets: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		t, serr := scanCampaignTicketRow(rows.Scan)
		if serr != nil {
			return nil, serr
		}
		out[t.CampaignID().String()] = t
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate campaign tickets: %w", err)
	}
	return out, nil
}

func (r *RemediationCampaignTicketRepository) scanOne(ctx context.Context, query string, args ...any) (*remediation.CampaignTicket, error) {
	t, err := scanCampaignTicketRow(r.db.QueryRowContext(ctx, query, args...).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, remediation.ErrCampaignTicketNotFound
		}
		return nil, fmt.Errorf("failed to get campaign ticket: %w", err)
	}
	return t, nil
}

// scanCampaignTicketRow scans one row (rctSelectCols order) into a CampaignTicket.
func scanCampaignTicketRow(scan func(dest ...any) error) (*remediation.CampaignTicket, error) {
	var (
		id, tid, cid             string
		prov, issueKey, issueURL string
		createdAt, updatedAt     = sql.NullTime{}, sql.NullTime{}
	)
	if err := scan(&id, &tid, &cid, &prov, &issueKey, &issueURL, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	parsedID, _ := shared.IDFromString(id)
	parsedTenant, _ := shared.IDFromString(tid)
	parsedCampaign, _ := shared.IDFromString(cid)
	return remediation.ReconstituteCampaignTicket(
		parsedID, parsedTenant, parsedCampaign, prov, issueKey, issueURL,
		createdAt.Time, updatedAt.Time,
	), nil
}
