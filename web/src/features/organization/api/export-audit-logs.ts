/**
 * Audit log export. The API streams the filtered log as CSV or JSON lines
 * (GET /api/v1/audit-logs/export, audit:read, newest first, capped); the
 * browser only saves the file. The filters are the ones the list uses.
 */

import { getApiBaseUrl } from '@/lib/api/client'

import type { AuditLogFilters } from '../types/audit.types'
import { buildAuditFilterParams } from './use-audit-logs'

export type AuditExportFormat = 'csv' | 'jsonl'

/** Header the API sets when more rows matched than one export holds. */
export const AUDIT_EXPORT_TRUNCATED_HEADER = 'X-Export-Truncated'

/** The export URL for the current filters (paging and sort do not apply). */
export function buildAuditExportUrl(format: AuditExportFormat, filters?: AuditLogFilters): string {
  const params = new URLSearchParams({ format })
  buildAuditFilterParams(filters).forEach((value, key) => params.append(key, value))
  return `${getApiBaseUrl()}/api/v1/audit-logs/export?${params.toString()}`
}

/** The API's error message, if the body carries one. */
async function errorMessage(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { message?: string; error?: string }
    if (body.message) return body.message
    if (body.error) return body.error
  } catch {
    // not JSON
  }
  return `Export failed (${res.status})`
}

function fileNameOf(res: Response, format: AuditExportFormat): string {
  const match = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') ?? '')
  return match?.[1] ?? `audit-log-${new Date().toISOString().slice(0, 10)}.${format}`
}

export interface AuditExportResult {
  filename: string
  /** True when more events matched than the export holds (the newest are in it). */
  truncated: boolean
}

/**
 * Download the audit log with the given filters. GET is not a mutation, so no
 * CSRF header is needed; `credentials: 'include'` carries the session cookies.
 * Throws with the API message on a non-2xx.
 */
export async function downloadAuditLog(
  format: AuditExportFormat,
  filters?: AuditLogFilters
): Promise<AuditExportResult> {
  const res = await fetch(buildAuditExportUrl(format, filters), { credentials: 'include' })
  if (!res.ok) {
    throw new Error(await errorMessage(res))
  }
  const truncated = res.headers.get(AUDIT_EXPORT_TRUNCATED_HEADER) === 'true'
  const blob = await res.blob()
  const filename = fileNameOf(res, format)
  let objectUrl: string | null = null
  try {
    objectUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = objectUrl
    a.download = filename
    a.click()
  } finally {
    if (objectUrl) URL.revokeObjectURL(objectUrl)
  }
  return { filename, truncated }
}
