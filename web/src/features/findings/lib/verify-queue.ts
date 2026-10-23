import type { FindingApiFilters } from '../api/finding-api.types'

/**
 * The verification queue: findings whose owner marked the fix applied and a
 * verifier has not yet approved or rejected. One definition for the page's
 * "Awaiting verification" count and for the view it opens, so the figure and
 * the list cannot disagree.
 */

/** The filters the count and the view share: the page's context scope. */
export function queueContextFilters(f: FindingApiFilters): FindingApiFilters {
  return {
    asset_id: f.asset_id,
    scan_id: f.scan_id,
    cve_ids: f.cve_ids,
    rule_id: f.rule_id,
    families: f.families,
    finding_types: f.finding_types,
    component_id: f.component_id,
    asset_owner_id: f.asset_owner_id,
    asset_owner_unassigned: f.asset_owner_unassigned,
    asset_group_id: f.asset_group_id,
    asset_crown_jewel: f.asset_crown_jewel,
  }
}

/**
 * The queue's list filter: claimed fixes in the context scope. Pentest
 * findings are verified in their own module, so the queue (and its count)
 * leave them out.
 */
export function verifyQueueQuery(context: FindingApiFilters): FindingApiFilters {
  return {
    ...queueContextFilters(context),
    statuses: ['fix_applied'],
    extra: { source_not: 'pentest' },
  }
}

/** The queue findings that have no CVE: the by-CVE groups leave them out. */
export function verifyQueueNoCveQuery(context: FindingApiFilters): FindingApiFilters {
  return { ...verifyQueueQuery(context), cve_id_unset: true }
}
