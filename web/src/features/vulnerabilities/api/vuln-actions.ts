/**
 * Bulk actions on vulnerabilities (api/docs/architecture/vulnerability-page.md,
 * "Bulk actions"): an exception through the approval policy, a retest and an
 * export, each over the open findings of the selected CVEs that the list's
 * filters select. The API resolves the findings as the signed-in person;
 * nothing here sends a tenant or a scope.
 */

import { post } from '@/lib/api/client'
import type {
  ApprovalBatch,
  GroupExceptionInput,
  GroupExceptionPreview,
} from '@/features/findings/api/use-approval-batches'
import { downloadFindingsExport } from '@/features/findings/api/export-findings'

const BASE = '/api/v1/vulnerability-exposures'

/** The selected CVEs and the list's query (filters, saved view). */
export interface VulnSelection {
  cveIds: string[]
  params: string
}

export type RetestOutcome =
  'queued' | 'in_flight' | 'rate_limited' | 'not_eligible' | 'no_sensor' | 'not_found' | 'failed'

export interface VulnRetestResult {
  open_findings: number
  attempted: number
  counts: Partial<Record<RetestOutcome, number>>
  items: { finding_id: string; outcome: RetestOutcome; retest_id?: string }[]
}

function body(sel: VulnSelection) {
  return { cve_ids: sel.cveIds, ...(sel.params ? { params: sel.params } : {}) }
}

export const vulnActionsApi = {
  previewException: (sel: VulnSelection, input: GroupExceptionInput) =>
    post<GroupExceptionPreview>(`${BASE}/exception/preview`, { ...body(sel), ...input }),
  requestException: (sel: VulnSelection, input: GroupExceptionInput) =>
    post<ApprovalBatch>(`${BASE}/exception`, { ...body(sel), ...input }),
  retest: (sel: VulnSelection) => post<VulnRetestResult>(`${BASE}/retests`, body(sel)),
  /** Downloads the findings behind the rows (CSV), `cveIds` narrowing to selected rows. */
  exportCsv: (params: URLSearchParams, cveIds?: string[]) => {
    const q = new URLSearchParams(params)
    if (cveIds?.length) q.set('cve_id', cveIds.join(','))
    q.set('format', 'csv')
    return downloadFindingsExport(`${BASE}/export?${q}`, 'csv')
  },
}
