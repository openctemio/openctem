/**
 * POST /api/v1/findings/imports: results exported by other tools (Nessus,
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
  /** A format to use instead of detecting it, e.g. `mapping:<name>` for a saved import mapping. */
  format?: string
}

/** An import the server refused, with the refused file's details when it sent them. */
export class FindingImportError extends Error {
  readonly status: number
  readonly file?: ImportFileResponse
  /** Fixed code of a stored upload the server could not import (e.g. apply_failed). */
  readonly code?: string

  constructor(message: string, status: number, file?: ImportFileResponse, code?: string) {
    super(message)
    this.name = 'FindingImportError'
    this.status = status
    this.file = file
    this.code = code
  }
}

/** How long the client waits for a stored upload to be imported. */
const RESULT_POLLS = 60

/**
 * A committed upload is stored (202) and imported by the server's ingest
 * worker: read its result (each read waits up to 10 s on the server) until
 * it is applied or failed, and return it merged into the first answer.
 */
async function waitForResult(accepted: FindingImportResponse): Promise<FindingImportResponse> {
  const id = accepted.receipt_id
  if (!id) return accepted
  for (let i = 0; i < RESULT_POLLS; i++) {
    const res = await csrfFetch(`/api/v1/findings/imports/${encodeURIComponent(id)}/result?wait=10`)
    if (!res.ok) {
      throw new FindingImportError(`Import failed (HTTP ${res.status})`, res.status)
    }
    const body = (await res.json()) as FindingImportResponse
    if (body.status === 'failed') {
      throw new FindingImportError(
        body.error_code ?? 'apply_failed',
        res.status,
        undefined,
        body.error_code ?? 'apply_failed'
      )
    }
    if (body.status === 'applied') {
      return { ...accepted, ...body, dry_run: false }
    }
  }
  throw new FindingImportError('timeout', 504, undefined, 'timeout')
}

export async function importFindings(opts: FindingImportOptions): Promise<FindingImportResponse> {
  const form = new FormData()
  if (opts.knowledgeBase) form.append('knowledge_base', opts.knowledgeBase)
  form.append('file', opts.file)
  const params = new URLSearchParams()
  if (opts.dryRun) params.set('dry_run', 'true')
  if (opts.minSeverity) params.set('min_severity', opts.minSeverity)
  if (opts.format) params.set('format', opts.format)
  const qs = params.toString()
  const query = qs ? `?${qs}` : ''
  const res = await csrfFetch(`/api/v1/findings/imports${query}`, { method: 'POST', body: form })
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
  const resp = body as FindingImportResponse
  if (res.status === 202) {
    return waitForResult(resp)
  }
  return resp
}
