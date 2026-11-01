package postgres

// Per-use-case AI settings in tenant_ai_settings.use_cases
// (docs/architecture/ai-use-cases.md), and the person decisions on the
// requests an organization's AI filed, which drive the automatic downgrade.
// Every query is scoped by tenant_id, except ListAutoApply (a system job).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ aidom.UseCaseRepository = (*TenantAISettingsRepository)(nil)

// useCaseJSON is one use case's stored setting.
type useCaseJSON struct {
	Mode               string     `json:"mode"`
	Ceiling            string     `json:"ceiling"`
	MinConfidence      float64    `json:"min_confidence"`
	AutoApplySince     *time.Time `json:"auto_apply_since,omitempty"`
	DowngradedAt       *time.Time `json:"downgraded_at,omitempty"`
	DowngradeReason    string     `json:"downgrade_reason,omitempty"`
	DowngradeDecisions int        `json:"downgrade_decisions,omitempty"`
	DowngradeOverrides int        `json:"downgrade_overrides,omitempty"`
	UpdatedAt          *time.Time `json:"updated_at,omitempty"`
	UpdatedBy          string     `json:"updated_by,omitempty"`
}

func toUseCaseJSON(s aidom.UseCaseSetting) useCaseJSON {
	return useCaseJSON{
		Mode: string(s.Mode), Ceiling: string(s.Ceiling), MinConfidence: s.MinConfidence,
		AutoApplySince: s.AutoApplySince, DowngradedAt: s.DowngradedAt, DowngradeReason: s.DowngradeReason,
		DowngradeDecisions: s.DowngradeDecisions, DowngradeOverrides: s.DowngradeOverrides,
		UpdatedAt: s.UpdatedAt, UpdatedBy: s.UpdatedBy,
	}
}

func (j useCaseJSON) setting() aidom.UseCaseSetting {
	return aidom.UseCaseSetting{
		Mode: aidom.UseCaseMode(j.Mode), Ceiling: aidom.DataClass(j.Ceiling), MinConfidence: j.MinConfidence,
		AutoApplySince: j.AutoApplySince, DowngradedAt: j.DowngradedAt, DowngradeReason: j.DowngradeReason,
		DowngradeDecisions: j.DowngradeDecisions, DowngradeOverrides: j.DowngradeOverrides,
		UpdatedAt: j.UpdatedAt, UpdatedBy: j.UpdatedBy,
	}
}

// GetUseCases returns the organization's stored use case settings; a use
// case it never saved is absent (the caller applies the default).
func (r *TenantAISettingsRepository) GetUseCases(ctx context.Context, tenantID shared.ID) (aidom.UseCasePolicy, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT use_cases FROM tenant_ai_settings WHERE tenant_id = $1`, tenantID.String()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return aidom.UseCasePolicy{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read AI use cases: %w", err)
	}
	var stored map[string]useCaseJSON
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("decode AI use cases: %w", err)
	}
	out := make(aidom.UseCasePolicy, len(stored))
	for k, v := range stored {
		uc, err := aidom.ParseUseCase(k)
		if err != nil {
			continue // a retired use case: ignored
		}
		out[uc] = v.setting()
	}
	return out, nil
}

// SaveUseCase writes one use case's setting (the other keys are kept). A
// missing settings row is created with the column defaults (AI stays off
// until an administrator consents); the row's updated_at is left alone.
func (r *TenantAISettingsRepository) SaveUseCase(ctx context.Context, tenantID shared.ID, uc aidom.UseCase, s aidom.UseCaseSetting) error {
	raw, err := json.Marshal(toUseCaseJSON(s))
	if err != nil {
		return fmt.Errorf("encode AI use case: %w", err)
	}
	const q = `
		INSERT INTO tenant_ai_settings (tenant_id, use_cases) VALUES ($1, jsonb_build_object($2::text, $3::jsonb))
		ON CONFLICT (tenant_id) DO UPDATE
		SET use_cases = tenant_ai_settings.use_cases || jsonb_build_object($2::text, $3::jsonb)`
	if _, err := r.db.ExecContext(ctx, q, tenantID.String(), string(uc), raw); err != nil {
		return fmt.Errorf("save AI use case: %w", err)
	}
	return nil
}

// DowngradeUseCase writes next only while the stored value still equals
// expected (JSON equality), so a downgrade never overwrites a change an
// administrator made after the sweep read the setting, and two sweeps
// downgrade once.
func (r *TenantAISettingsRepository) DowngradeUseCase(ctx context.Context, tenantID shared.ID, uc aidom.UseCase, expected, next aidom.UseCaseSetting) (bool, error) {
	exp, err := json.Marshal(toUseCaseJSON(expected))
	if err != nil {
		return false, fmt.Errorf("encode AI use case: %w", err)
	}
	nxt, err := json.Marshal(toUseCaseJSON(next))
	if err != nil {
		return false, fmt.Errorf("encode AI use case: %w", err)
	}
	const q = `
		UPDATE tenant_ai_settings
		SET use_cases = use_cases || jsonb_build_object($2::text, $4::jsonb)
		WHERE tenant_id = $1 AND use_cases -> $2::text = $3::jsonb`
	res, err := r.db.ExecContext(ctx, q, tenantID.String(), string(uc), exp, nxt)
	if err != nil {
		return false, fmt.Errorf("downgrade AI use case: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("downgrade AI use case: %w", err)
	}
	return n == 1, nil
}

// ListAutoApply lists every organization's use cases in auto_apply while AI
// is turned on (the downgrade sweep; a system job across organizations).
func (r *TenantAISettingsRepository) ListAutoApply(ctx context.Context, limit int) ([]aidom.AutoApplyUseCase, error) {
	if limit <= 0 {
		limit = 1000
	}
	const q = `
		SELECT s.tenant_id::text, u.key, u.value
		FROM tenant_ai_settings s, jsonb_each(s.use_cases) AS u(key, value)
		WHERE s.enabled_at IS NOT NULL AND u.value ->> 'mode' = 'auto_apply'
		ORDER BY s.tenant_id, u.key
		LIMIT $1`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("list auto-apply AI use cases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []aidom.AutoApplyUseCase
	for rows.Next() {
		var tid, key string
		var raw []byte
		if err := rows.Scan(&tid, &key, &raw); err != nil {
			return nil, fmt.Errorf("scan auto-apply AI use case: %w", err)
		}
		uc, err := aidom.ParseUseCase(key)
		if err != nil {
			continue
		}
		id, err := shared.IDFromString(tid)
		if err != nil {
			continue
		}
		var v useCaseJSON
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		out = append(out, aidom.AutoApplyUseCase{TenantID: id, UseCase: uc, Setting: v.setting()})
	}
	return out, rows.Err()
}

var _ aidom.OverrideStatsReader = (*TenantAISettingsRepository)(nil)

// OverrideStats counts the person decisions (approved or rejected) on
// requests the organization's AI filed since a time, newest first, at most
// window of them; a rejection is an override. Requests filed by AI: a
// false-positive request whose requester is one of the organization's AI
// agents or the built-in AI triage actor, and a severity request whose
// requester is one of its AI agents. Every such request comes from the
// triage use case; the other use cases file none, so they have no
// decisions.
func (r *TenantAISettingsRepository) OverrideStats(ctx context.Context, tenantID shared.ID, uc aidom.UseCase, since time.Time, window int) (aidom.OverrideStats, error) {
	if uc != aidom.UseCaseTriage {
		return aidom.OverrideStats{}, nil
	}
	if window <= 0 {
		window = aidom.DowngradeWindow
	}
	const q = `
		WITH agents AS (SELECT user_id FROM ai_agents WHERE tenant_id = $1),
		decided AS (
			SELECT a.status, COALESCE(a.approved_at, a.rejected_at) AS decided_at
			FROM finding_status_approvals a
			WHERE a.tenant_id = $1 AND a.status IN ('approved', 'rejected') AND a.created_at >= $2
			  AND (a.requested_by_actor = 'ai_triage' OR a.requested_by IN (SELECT user_id FROM agents))
			UNION ALL
			SELECT q.status, q.decided_at
			FROM finding_severity_requests q
			WHERE q.tenant_id = $1 AND q.status IN ('approved', 'rejected') AND q.created_at >= $2
			  AND q.requested_by IN (SELECT user_id FROM agents)
		),
		recent AS (SELECT status FROM decided ORDER BY decided_at DESC NULLS LAST LIMIT $3)
		SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'rejected') FROM recent`
	var st aidom.OverrideStats
	if err := r.db.QueryRowContext(ctx, q, tenantID.String(), since, window).Scan(&st.Decisions, &st.Overrides); err != nil {
		return aidom.OverrideStats{}, fmt.Errorf("count AI override decisions: %w", err)
	}
	return st, nil
}
