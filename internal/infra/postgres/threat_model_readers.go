package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatmodel"
)

// AttackerProfileReader reads attacker profiles as neutral generation inputs.
// The attacker_profiles table has no DDD repository (the CRUD handler uses direct
// SQL), so this thin reader implements the threatmodel.AttackerProfileReader port
// for the generation service.
type AttackerProfileReader struct {
	db *DB
}

// NewAttackerProfileReader creates an AttackerProfileReader.
func NewAttackerProfileReader(db *DB) *AttackerProfileReader {
	return &AttackerProfileReader{db: db}
}

var _ threatmodel.AttackerProfileReader = (*AttackerProfileReader)(nil)

// capabilitiesJSON mirrors the attacker_profiles.capabilities JSONB shape.
type capabilitiesJSON struct {
	NetworkAccess   string `json:"network_access"`
	CredentialLevel string `json:"credential_level"`
	Persistence     bool   `json:"persistence"`
}

// ListAttackerProfiles returns every attacker profile for the tenant, default
// profiles first.
func (r *AttackerProfileReader) ListAttackerProfiles(ctx context.Context, tenantID shared.ID) ([]threatmodel.AttackerProfileFact, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, profile_type, capabilities, is_default
		   FROM attacker_profiles
		  WHERE tenant_id = $1
		  ORDER BY is_default DESC, created_at ASC`,
		tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list attacker profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]threatmodel.AttackerProfileFact, 0)
	for rows.Next() {
		var (
			id, name, profileType string
			capsRaw               []byte
			isDefault             bool
		)
		if err := rows.Scan(&id, &name, &profileType, &capsRaw, &isDefault); err != nil {
			return nil, fmt.Errorf("failed to scan attacker profile: %w", err)
		}
		pid, _ := shared.IDFromString(id)
		var caps capabilitiesJSON
		if len(capsRaw) > 0 {
			_ = json.Unmarshal(capsRaw, &caps)
		}
		out = append(out, threatmodel.AttackerProfileFact{
			ID:          pid,
			Name:        name,
			ProfileType: profileType,
			IsDefault:   isDefault,
			Capabilities: threatmodel.AttackerCapabilities{
				NetworkAccess:   caps.NetworkAccess,
				CredentialLevel: caps.CredentialLevel,
				Persistence:     caps.Persistence,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating attacker profiles: %w", err)
	}
	return out, nil
}

// ListThreatFindings implements threatmodel.FindingReader: it returns the
// status-relevant findings for the given assets, tenant-scoped, as neutral
// FindingFact projections. Returns no rows (without querying) for an empty set.
func (r *FindingRepository) ListThreatFindings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]threatmodel.FindingFact, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, asset_id, COALESCE(mitre_technique_id, ''), COALESCE(cwe_ids, '{}'),
		        COALESCE(finding_type, ''), status, acceptance_expires_at
		   FROM findings
		  WHERE tenant_id = $1
		    AND asset_id = ANY($2)`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to list threat findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]threatmodel.FindingFact, 0)
	for rows.Next() {
		var (
			id, assetID, techniqueID, category, status string
			cweIDs                                     pq.StringArray
			acceptanceExpires                          sql.NullTime
		)
		if err := rows.Scan(&id, &assetID, &techniqueID, &cweIDs, &category, &status, &acceptanceExpires); err != nil {
			return nil, fmt.Errorf("failed to scan threat finding: %w", err)
		}
		fid, _ := shared.IDFromString(id)
		aid, _ := shared.IDFromString(assetID)
		fact := threatmodel.FindingFact{
			ID:          fid,
			AssetID:     aid,
			TechniqueID: techniqueID,
			CWEIDs:      []string(cweIDs),
			Category:    category,
			Status:      status,
		}
		if acceptanceExpires.Valid {
			t := acceptanceExpires.Time
			fact.AcceptanceExpiresAt = &t
		}
		out = append(out, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating threat findings: %w", err)
	}
	return out, nil
}
