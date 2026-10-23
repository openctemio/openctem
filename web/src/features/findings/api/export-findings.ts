/**
 * Findings export. The API streams every finding the list's filter selects
 * (GET /api/v1/findings/export, findings:export, scoped like the list, at most
 * X-Export-Max-Rows rows, one export per user at a time); the browser only
 * saves the file. There is no client-side fallback: without the permission
 * the console offers no export.
 */

import { getApiBaseUrl } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'

/** Header with the most rows one export holds. */
export const FINDINGS_EXPORT_MAX_ROWS_HEADER = 'X-Export-Max-Rows'

export interface FindingsExportResult {
  filename: string
  /** The cap the API applied, when it said (compare with the list total). */
  maxRows?: number
}

/** The API's refusal as an ApiClientError (code, status, details, request id). */
async function exportError(res: Response): Promise<ApiClientError> {
  let code = `HTTP_${res.status}`
  let message = res.statusText || `Export failed (${res.status})`
  let details: Record<string, unknown> | undefined
  let requestId = res.headers.get('x-request-id') ?? undefined
  try {
    const body = (await res.json()) as {
      code?: unknown
      error?: unknown
      message?: unknown
      details?: unknown
      request_id?: unknown
    }
    const inner =
      body.error && typeof body.error === 'object'
        ? (body.error as typeof body)
        : (body as typeof body)
    if (typeof inner.code === 'string') code = inner.code
    else if (typeof body.error === 'string') code = body.error
    if (typeof inner.message === 'string' && inner.message) message = inner.message
    if (inner.details && typeof inner.details === 'object')
      details = inner.details as Record<string, unknown>
    if (typeof inner.request_id === 'string' && inner.request_id.length <= 128)
      requestId = inner.request_id
  } catch {
    // not JSON
  }
  return new ApiClientError(message, code, res.status, details, requestId)
}

function fileNameOf(res: Response, format: 'csv' | 'ndjson'): string {
  const match = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') ?? '')
  return match?.[1] ?? `findings-${new Date().toISOString().slice(0, 10)}.${format}`
}

/**
 * Downloads the export at `path` (from buildFindingsExportUrl). GET is not a
 * mutation, so no CSRF header is needed; `credentials: 'include'` carries the
 * session cookies. Throws an ApiClientError on a non-2xx.
 */
export async function downloadFindingsExport(
  path: string,
  format: 'csv' | 'ndjson'
): Promise<FindingsExportResult> {
  const res = await fetch(`${getApiBaseUrl()}${path}`, { credentials: 'include' })
  if (!res.ok) throw await exportError(res)
  const rawMax = Number.parseInt(res.headers.get(FINDINGS_EXPORT_MAX_ROWS_HEADER) ?? '', 10)
  const blob = await res.blob()
  const filename = fileNameOf(res, format)
  let objectUrl: string | null = null
  try {
    objectUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = objectUrl
    a.download = filename
    a.rel = 'noopener'
    a.click()
  } finally {
    if (objectUrl) URL.revokeObjectURL(objectUrl)
  }
  return { filename, maxRows: Number.isFinite(rawMax) && rawMax > 0 ? rawMax : undefined }
}

/** True when the list holds more findings than the export could carry. */
export function exportTruncated(listTotal: number | undefined, maxRows: number | undefined) {
  return typeof listTotal === 'number' && typeof maxRows === 'number' && listTotal > maxRows
}
