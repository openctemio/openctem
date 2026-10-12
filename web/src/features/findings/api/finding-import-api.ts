/**
 * POST /api/v1/findings/import: results exported by other tools (Nessus,
 * Qualys, CycloneDX, SPDX, OSV, CSAF, OpenVEX, DefectDojo, or a ZIP of them).
 * The server detects the format from the content; `dryRun` only parses and
 * counts.
 */

import { csrfFetch } from '@/lib/api/client'
import type { components } from '@/lib/api/generated/api.types'

export type FindingImportResponse =
  components['schemas']['internal_infra_http_handler.FindingImportResponse']
export type ImportFileResponse =
  components['schemas']['internal_infra_http_handler.ImportFileResponse']

export type ImportMinSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface FindingImportOptions {
  file: File
  /** Qualys KnowledgeBase XML, sent before the file (the server needs it first). */
  knowledgeBase?: File | null
  dryRun: boolean
  /** Drop findings below this severity (server default: keep all). */
  minSeverity?: ImportMinSeverity
}

/** An import the server refused, with the refused file's details when it sent them. */
export class FindingImportError extends Error {
  readonly status: number
  readonly file?: ImportFileResponse

  constructor(message: string, status: number, file?: ImportFileResponse) {
    super(message)
    this.name = 'FindingImportError'
    this.status = status
    this.file = file
  }
}

export async function importFindings(opts: FindingImportOptions): Promise<FindingImportResponse> {
  const form = new FormData()
  if (opts.knowledgeBase) form.append('knowledge_base', opts.knowledgeBase)
  form.append('file', opts.file)
  const params = new URLSearchParams()
  if (opts.dryRun) params.set('dry_run', 'true')
  if (opts.minSeverity) params.set('min_severity', opts.minSeverity)
  const qs = params.toString()
  const query = qs ? `?${qs}` : ''
  const res = await csrfFetch(`/api/v1/findings/import${query}`, { method: 'POST', body: form })
  let body: unknown = null
  try {
    body = await res.json()
  } catch {
    body = null
  }
  if (!res.ok) {
    const err = (body ?? {}) as { message?: string; details?: ImportFileResponse }
    const message =
      typeof err.message === 'string' && err.message
        ? err.message
        : res.status === 413
          ? 'The file is too large'
          : res.status === 429
            ? 'Too many imports for your organization; try again in a minute'
            : `Import failed (HTTP ${res.status})`
    throw new FindingImportError(message, res.status, err.details)
  }
  return body as FindingImportResponse
}
