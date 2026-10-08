/**
 * SBOM download. The API builds the document (GET /api/v1/components/sbom):
 * CycloneDX 1.6 JSON or SPDX 2.3 JSON, from the components the caller may
 * see. The browser only saves the file.
 */

import { getApiBaseUrl } from '@/lib/api/client'

import type { SbomFormat } from '../types'

/** File name suffix per format (CycloneDX and SPDX conventions). */
export const SBOM_FILE_EXTENSION: Record<SbomFormat, string> = {
  cyclonedx: '.cdx.json',
  spdx: '.spdx.json',
}

export function sbomUrl(format: SbomFormat, assetId?: string): string {
  const params = new URLSearchParams({ format })
  if (assetId) params.set('asset_id', assetId)
  return `${getApiBaseUrl()}/api/v1/components/sbom?${params}`
}

export function sbomFileName(format: SbomFormat, now: Date = new Date()): string {
  return `sbom-${now.toISOString().slice(0, 10)}${SBOM_FILE_EXTENSION[format]}`
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

/**
 * Download the SBOM. GET is not a mutation, so no CSRF header is needed;
 * `credentials: 'include'` carries the session cookies. Throws with the API
 * message on a non-2xx (for example more components than one export holds).
 */
export async function downloadSbom(format: SbomFormat, assetId?: string): Promise<string> {
  const res = await fetch(sbomUrl(format, assetId), { credentials: 'include' })
  if (!res.ok) {
    throw new Error(await errorMessage(res))
  }
  const blob = await res.blob()
  const filename = sbomFileName(format)
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
  return filename
}
