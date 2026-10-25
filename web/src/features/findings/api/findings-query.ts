import type { FindingApiFilters } from './finding-api.types'

export function buildFindingsEndpoint(filters?: FindingApiFilters): string {
  const baseUrl = '/api/v1/findings'
  if (!filters) return baseUrl
  const queryString = buildFindingsQuery(filters).toString()
  return queryString ? `${baseUrl}?${queryString}` : baseUrl
}

/** The list query (RFC-048 param names) for a filter set; shared by list, stats and export. */
export function buildFindingsQuery(filters: FindingApiFilters): URLSearchParams {
  const params = new URLSearchParams()

  // The list query contract's param names (RFC-048): the singular response
  // field names. The old plural names still work on the server, as
  // deprecated aliases.
  if (filters.asset_id) params.set('asset_id', filters.asset_id)
  if (filters.branch_id) params.set('branch_id', filters.branch_id)
  if (filters.branch_id && filters.branch_status && filters.branch_status !== 'all')
    params.set('branch_status', filters.branch_status)
  if (filters.component_id) params.set('component_id', filters.component_id)
  if (filters.vulnerability_id) params.set('vulnerability_id', filters.vulnerability_id)
  if (filters.tool_name) params.set('tool_name', filters.tool_name)
  if (filters.rule_id) params.set('rule_id', filters.rule_id)
  if (filters.scan_id) params.set('scan_id', filters.scan_id)
  if (filters.file_path) params.set('file_path', filters.file_path)
  if (filters.search) params.set('q', filters.search)
  if (filters.page) params.set('page', String(filters.page))
  if (filters.per_page) params.set('per_page', String(filters.per_page))

  if (filters.severities?.length) params.set('severity', filters.severities.join(','))
  if (filters.statuses?.length) params.set('status', filters.statuses.join(','))
  if (filters.exclude_statuses?.length) params.set('status_not', filters.exclude_statuses.join(','))
  if (filters.sources?.length) params.set('source', filters.sources.join(','))

  // CTEM prioritization filters (RFC-017)
  if (filters.priority_classes?.length)
    params.set('priority_class', filters.priority_classes.join(','))
  if (filters.is_in_kev) params.set('is_in_kev', 'true')
  if (filters.is_reachable) params.set('is_reachable', 'true')
  if (filters.branch_only) params.set('branch_only', 'true')
  if (filters.assigned_to_me) params.set('related_to', 'me')
  if (filters.sla_statuses?.length) params.set('sla_status', filters.sla_statuses.join(','))
  if (filters.sla_deadline_gt) params.set('sla_deadline_gt', filters.sla_deadline_gt)
  if (filters.sla_deadline_lte) params.set('sla_deadline_lte', filters.sla_deadline_lte)
  if (filters.epss_min != null) params.set('epss_score_gte', String(filters.epss_min))
  if (filters.finding_ids?.length) params.set('id', filters.finding_ids.join(','))
  if (filters.cve_ids?.length) params.set('cve_id', filters.cve_ids.join(','))
  if (filters.cve_id_unset) params.set('cve_id_null', 'true')
  if (filters.finding_types?.length) params.set('finding_type', filters.finding_types.join(','))
  if (filters.families?.length) params.set('family', filters.families.join(','))
  if (filters.state) params.set('state', filters.state)
  if (filters.asset_owner_id) params.set('asset_owner_id', filters.asset_owner_id)
  if (filters.asset_owner_unassigned) params.set('asset_owner_id_null', 'true')
  if (filters.asset_group_id) params.set('asset_group_id', filters.asset_group_id)
  if (filters.pending_approval !== undefined)
    params.set('pending_approval', String(filters.pending_approval))
  if (filters.informational !== undefined)
    params.set('informational', String(filters.informational))
  if (filters.acceptance_expires_at_lte)
    params.set('acceptance_expires_at_lte', filters.acceptance_expires_at_lte)
  if (filters.asset_crown_jewel) params.set('asset_crown_jewel', 'true')
  if (filters.view) params.set('view', filters.view)
  if (filters.sort) params.set('sort', filters.sort)
  // Filters the page carries as they are (the filter contract names them).
  for (const [name, value] of Object.entries(filters.extra ?? {})) {
    if (!params.has(name)) params.set(name, value)
  }
  return params
}
