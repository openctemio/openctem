/** A pending Ready to close proposal (GET /findings/closure/proposals). */
export interface ClosureProposal {
  id: string
  finding_id: string
  /** covered_scan today; obsolete_asset and others later. */
  method: string
  evidence: ClosureEvidence
  proposed_at: string
  evidence_at: string
  finding_title: string
  severity: string
  status: string
  tool_name?: string
  asset_id?: string
  asset_name?: string
  /** standard, high or critical (critical: severity critical, P0 or KEV). */
  tier: 'standard' | 'high' | 'critical' | string
}

/** A finding the platform closed by itself in the last 7 days. */
export interface AutoClosedFinding {
  finding_id: string
  finding_title: string
  severity: string
  tool_name?: string
  asset_id?: string
  asset_name?: string
  verification: string
  resolved_at: string
  evidence: ClosureEvidence
}

/** What proved the close: the scan behind it. Values are untrusted strings. */
export interface ClosureEvidence {
  command_id?: string
  scan_id?: string
  tool?: string
  scanner?: string
  profile_id?: string
  templates_digest?: string
  held?: boolean
  observed_at?: string
  sensor_ids?: string[]
  [key: string]: unknown
}

export interface PagedList<T> {
  data: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export type DismissReason =
  'still_present_manual_check' | 'scan_not_trustworthy' | 'wrong_asset' | 'other'

export const DISMISS_REASONS: DismissReason[] = [
  'still_present_manual_check',
  'scan_not_trustworthy',
  'wrong_asset',
  'other',
]

export interface DecideResult {
  applied: string[]
  skipped: Record<string, 'not_found' | 'not_eligible' | string>
  finding_ids: string[]
}

/** Most proposals one decision may carry (the API refuses more). */
export const MAX_DECISION_BATCH = 200
