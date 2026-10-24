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

type Translate = (
  key: string,
  fallback?: string,
  params?: Record<string, string | number>
) => string

/**
 * Turns a bulk result into what to tell the user, in the app's language.
 * `action` names what was done to each finding.
 */
export function summarizeBulkResult(
  result: BulkFindingResult | undefined,
  requested: number,
  action: 'assigned' | 'updated',
  t: Translate
): BulkSummary {
  const failed = result?.failed ?? 0
  const updated = result?.updated ?? (failed > 0 ? requested - failed : requested)
  if (failed === 0) {
    return {
      kind: 'success',
      message:
        action === 'assigned'
          ? t(
              'findings.bulk.result.assigned',
              '{count, plural, one {Assigned # finding} other {Assigned # findings}}',
              { count: updated }
            )
          : t(
              'findings.bulk.result.updated',
              '{count, plural, one {Updated # finding} other {Updated # findings}}',
              { count: updated }
            ),
    }
  }
  const description = reasonOf(result?.errors?.[0])
  if (updated === 0) {
    return {
      kind: 'error',
      message: t('findings.bulk.result.none', 'No findings were changed'),
      description,
    }
  }
  return {
    kind: 'warning',
    message:
      action === 'assigned'
        ? t(
            'findings.bulk.result.assignedPartial',
            'Assigned {updated} of {requested} findings. {failed} not changed',
            { updated, requested, failed }
          )
        : t(
            'findings.bulk.result.updatedPartial',
            'Updated {updated} of {requested} findings. {failed} not changed',
            { updated, requested, failed }
          ),
    description,
  }
}
