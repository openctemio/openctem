/** One finding a "mark fixed" did not update, and why. */
export interface MarkFixedRow {
  finding_id: string
  outcome: 'skipped' | 'failed'
  reason: string
}

/** The outcome of marking a remediation group or a campaign fixed. */
export interface MarkFixedResult {
  updated: number
  skipped: number
  failed: number
  validations_queued: number
  rows: MarkFixedRow[]
}

/** A "mark fixed" request: the note is required. */
export interface MarkFixedRequest {
  resolution: string
  approved?: boolean
}
