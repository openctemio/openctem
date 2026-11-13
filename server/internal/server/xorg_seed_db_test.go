package server

// Rows organization A owns, one set per matrix case so a case that deletes or
// changes its victim never disturbs another. Every name carries xoMarker.

import (
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func (h *xoStack) uid() string { return shared.NewID().String() }

func xoName(kind string) string {
	return xoMarker + "-" + kind + "-" + xoShort(shared.NewID().String())
}

func (h *xoStack) seedAsset(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
		id, tenant.String(), xoName("asset")+".example.com")
	return id
}

func (h *xoStack) seedFinding(tenant shared.ID, asset string) string {
	id := h.uid()
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 'xo-tool', $4, 'high', $1::text, 'confirmed')`, id, tenant.String(), asset, xoName("finding"))
	return id
}

func (h *xoStack) seedScan(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets, status) VALUES ($1, $2, $3, 'single', 'nuclei', ARRAY['xo-target.example.com'], 'active')`,
		id, tenant.String(), xoName("scan"))
	// The scan's own target is in scope, so A's own edit is accepted.
	h.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) SELECT $1, 'domain', 'xo-target.example.com'
		WHERE NOT EXISTS (SELECT 1 FROM scope_targets WHERE tenant_id = $1 AND pattern = 'xo-target.example.com')`, tenant.String())
	return id
}

func (h *xoStack) seedScanRun(tenant shared.ID, scan string) string {
	id := h.uid()
	h.exec(`INSERT INTO scan_runs (id, tenant_id, scan_id, trigger_type, kind, status) VALUES ($1, $2, $3, 'manual', 'system', 'completed')`,
		id, tenant.String(), scan)
	return id
}

func (h *xoStack) seedAssetGroup(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, $3)`, id, tenant.String(), xoName("group"))
	return id
}

func (h *xoStack) seedScopeTarget(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO scope_targets (id, tenant_id, target_type, pattern) VALUES ($1, $2, 'domain', $3)`, id, tenant.String(), xoName("target")+".example.com")
	return id
}

func (h *xoStack) seedScopeExclusion(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO scope_exclusions (id, tenant_id, exclusion_type, pattern, reason) VALUES ($1, $2, 'domain', $3, 'xo')`, id, tenant.String(), xoName("excl")+".example.com")
	return id
}

func (h *xoStack) seedSavedView(tenant, owner shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO saved_views (id, tenant_id, owner_id, page, name) VALUES ($1, $2, $3, 'findings', $4)`, id, tenant.String(), owner.String(), xoName("view"))
	return id
}

func (h *xoStack) seedDashboard(tenant, owner shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO user_dashboards (id, tenant_id, user_id, name) VALUES ($1, $2, $3, $4)`, id, tenant.String(), owner.String(), xoName("dash"))
	return id
}

func (h *xoStack) seedAPIKey(tenant, owner shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix) VALUES ($1, $2, $3, $4, $5, 'xo_')`,
		id, tenant.String(), owner.String(), xoName("key"), "xo-hash-"+id)
	return id
}

func (h *xoStack) seedIntegration(tenant shared.ID, category, provider string) string {
	id := h.uid()
	h.exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, auth_type, status) VALUES ($1, $2, $3, $4, $5, 'token', 'connected')`,
		id, tenant.String(), xoName("integration"), category, provider)
	return id
}

func (h *xoStack) seedRemediationAction(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin) VALUES ($1, $2, $3, 'manual', $4, 'manual')`,
		id, tenant.String(), "xo-"+id, xoName("action"))
	return id
}

func (h *xoStack) seedRemediationTask(tenant shared.ID) string {
	action := h.seedRemediationAction(tenant)
	id := h.uid()
	h.exec(`INSERT INTO remediation_tasks (id, tenant_id, action_id, title) VALUES ($1, $2, $3, $4)`, id, tenant.String(), action, xoName("task"))
	return id
}

func (h *xoStack) seedRole(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level) VALUES ($1, $2, $3, $4, 10)`, id, tenant.String(), "xo-role-"+xoShort(id), xoName("role"))
	return id
}

// xoShort is the random tail of a uuid: the head of a time-ordered id repeats
// within a millisecond.
func xoShort(id string) string { return id[len(id)-8:] }

func (h *xoStack) seedSuggestion(tenant shared.ID) string {
	id := h.uid()
	finding := h.seedFinding(tenant, h.seedAsset(tenant))
	h.exec(`INSERT INTO remediation_suggestions (id, tenant_id, kind, algorithm, algorithm_version, action_key, key_kind, title, identity, confidence, state, finding_ids, member_count)
		VALUES ($1, $2, 'new_group', 'xo', 1, $3, 'upgrade', $4, $3, 0.9, 'proposed', ARRAY[$5::uuid], 1)`, id, tenant.String(), "xo-"+id, xoName("suggestion"), finding)
	return id
}

func (h *xoStack) seedApproval(tenant shared.ID, finding string, requester shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, requested_by, justification, status)
		VALUES ($1, $2, $3, 'accepted', $4, $5, 'pending')`, id, tenant.String(), finding, requester.String(), xoName("approval"))
	return id
}

func (h *xoStack) seedExploration(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO explorations (id, tenant_id, kind, title) VALUES ($1, $2, 'investigation', $3)`, id, tenant.String(), xoName("exploration"))
	return id
}

func (h *xoStack) seedLead(tenant shared.ID, asset string) string {
	id := h.uid()
	h.exec(`INSERT INTO exploration_leads (id, tenant_id, exploration_id, lead_type, state, reason_code, origin, origin_ref, dedup_key, subject_asset_id)
		VALUES ($1, $2, $3, 'web.probe', 'proposed', $4, 'rule', 'xo', $5, $6)`,
		id, tenant.String(), h.seedExploration(tenant), xoName("reason"), "xo-"+id, asset)
	return id
}

func (h *xoStack) seedEvidenceItem(tenant shared.ID, finding string) string {
	id := h.uid()
	h.exec(`INSERT INTO finding_evidence (id, tenant_id, finding_id, origin, kind, content, content_sha256)
		VALUES ($1, $2, $3, 'manual', 'note', jsonb_build_object('text', $4::text), $5)`, id, tenant.String(), finding, xoName("evidence"), "sha-"+id)
	return id
}

func (h *xoStack) seedScanWindowPolicy(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO scan_window_policies (id, tenant_id, name, kind, timezone, slots)
		VALUES ($1, $2, $3, 'blackout', 'UTC', '[{"days":[1],"start":"00:00","end":"01:00"}]'::jsonb)`, id, tenant.String(), xoName("window"))
	return id
}

func (h *xoStack) seedScanWindowOverride(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO scan_window_overrides (id, tenant_id, reason, starts_at, ends_at)
		VALUES ($1, $2, $3, now() - interval '1 hour', now() + interval '1 hour')`, id, tenant.String(), xoName("override")+" long reason")
	return id
}

// seedConnector is a Tenable.sc connector that has everything a "scan now"
// needs, so a request gets as far as the assets.
func (h *xoStack) seedConnector(tenant shared.ID) string {
	id, sensor := h.uid(), h.uid()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status, scope) VALUES ($1, $2, $3, $4, 'xo_', 'active', 'organization')`,
		sensor, tenant.String(), xoName("sensor"), "xo-hash-"+sensor)
	h.exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, auth_type, status, config)
		VALUES ($1, $2, $3, 'security', 'tenable', 'api_key', 'connected',
		 ('{"engine":"tenable_sc","execution_mode":"sensor","coverage_policy_id":1,"coverage_repository_id":1,"sensor_id":"' || $4::text || '"}')::jsonb)`,
		id, tenant.String(), xoName("connector"), sensor)
	return id
}

// seedAccessGroup is a team (the groups table), not an asset group.
func (h *xoStack) seedAccessGroup(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, $3, $4)`, id, tenant.String(), xoName("team"), "xo-"+id)
	return id
}

func (h *xoStack) seedApprovalBatch(tenant shared.ID, requester shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO approval_batches (id, tenant_id, source_type, source_id, requested_status, closure_reason, justification, tier,
		risk_class, required_approvals, decide_by, member_count, status, requested_by, expires_at)
		VALUES ($1, $2, 'vulnerability_selection', $3, 'accepted', 'accepted_risk', $4, 'peer', 'low', 1, now() + interval '3 days', 1, 'pending', $5, now() + interval '30 days')`,
		id, tenant.String(), h.uid(), xoName("batch"), requester.String())
	return id
}

// seedWaitingLead is a lead that waits for approval (it names its step).
func (h *xoStack) seedWaitingLead(tenant shared.ID, asset string) string {
	id := h.uid()
	h.exec(`INSERT INTO exploration_leads (id, tenant_id, exploration_id, lead_type, state, reason_code, origin, origin_ref, dedup_key,
		subject_asset_id, capability, tier, action_hash)
		VALUES ($1, $2, $3, 'web.probe', 'awaiting_approval', $4, 'rule', 'xo', $5, $6, 'web.probe', 1, repeat('a', 64))`,
		id, tenant.String(), h.seedExploration(tenant), xoName("reason"), "xo-"+id, asset)
	return id
}

func (h *xoStack) seedAccessGroupA() string { return h.seedAccessGroup(h.tenantA) }

// enableAITriage records the consent an organization administrator gives:
// without it the AI routes answer for both organizations alike, before they
// look at any finding.
func (h *xoStack) enableAITriage(tenants ...shared.ID) {
	for _, tn := range tenants {
		h.exec(`INSERT INTO tenant_ai_settings (tenant_id, source, provider, enabled_at, enabled_by) VALUES ($1, 'own', 'claude', now(), 'xo')
			ON CONFLICT (tenant_id) DO UPDATE SET enabled_at = now(), source = 'own'`, tn.String())
	}
}

// seedRepository is a repository asset; seedBranch a branch of it.
func (h *xoStack) seedRepository(tenant shared.ID) string {
	id := h.uid()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'repository', 'private', 'high')`,
		id, tenant.String(), xoName("repo"))
	h.exec(`INSERT INTO asset_repositories (asset_id) VALUES ($1)`, id)
	return id
}

func (h *xoStack) seedBranch(repository string, isDefault bool) string {
	id := h.uid()
	h.exec(`INSERT INTO repository_branches (id, repository_id, name, branch_type, is_default) VALUES ($1, $2, $3, 'feature', $4)`,
		id, repository, xoName("branch"), isDefault)
	return id
}
