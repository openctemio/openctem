/**
 * Body of POST /api/v1/findings/bulk/status and /bulk/assign. Both answer 200
 * even when some or all findings were refused, so success must be read from
 * the counts, not the HTTP status.
 */
export interface BulkFindingResult {
  updated?: number
  failed?: number
  errors?: string[]
}

export interface BulkSummary {
  kind: 'success' | 'warning' | 'error'
  message: string
  description?: string
}

// Server errors are "<finding id>: <reason>". The id means nothing in a toast.
function reasonOf(error: string | undefined): string | undefined {
  if (!error) return undefined
  const i = error.indexOf(': ')
  return i >= 0 ? error.slice(i + 2) : error
}

/**
 * Turns a bulk result into what to tell the user. `verb` is the past tense of
 * the action ("Updated", "Assigned").
 */
export function summarizeBulkResult(
  result: BulkFindingResult | undefined,
  requested: number,
  verb: string
): BulkSummary {
  const failed = result?.failed ?? 0
  const updated = result?.updated ?? (failed > 0 ? requested - failed : requested)
  if (failed === 0) {
    return { kind: 'success', message: `${verb} ${updated} findings` }
  }
  const description = reasonOf(result?.errors?.[0])
  if (updated === 0) {
    return { kind: 'error', message: 'No findings were changed', description }
  }
  return {
    kind: 'warning',
    message: `${verb} ${updated} of ${requested} findings. ${failed} not changed`,
    description,
  }
}
