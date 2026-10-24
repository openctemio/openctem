'use client'

/**
 * Tenant import mappings API (/api/v1/import-mappings). The tenant comes from
 * the token; the API checks every permission (reads: integrations:read or
 * assets:import; writes and preview: integrations:manage).
 */

import useSWR, { mutate, type SWRConfiguration } from 'swr'
import { csrfFetch, del, get, patch, post } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import type {
  ImportMapping,
  ImportMappingDetail,
  MappingDocument,
  MappingTemplate,
  MappingWithVersion,
  PreviewResult,
  ValidateResult,
} from '../types/import-mapping.types'

export const IMPORT_MAPPINGS_BASE = '/api/v1/import-mappings'
const BASE = IMPORT_MAPPINGS_BASE

const quiet: SWRConfiguration = { revalidateOnFocus: false, shouldRetryOnError: false }

/** `enabled` false skips the request (for people without a read permission). */
export function useImportMappings(enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? BASE : null
  return useSWR<{ items: ImportMapping[] }>(
    key,
    (u: string) => get<{ items: ImportMapping[] }>(u),
    quiet
  )
}

export function useImportMapping(id: string | undefined) {
  const { currentTenant } = useTenant()
  const key = currentTenant && id ? `${BASE}/${encodeURIComponent(id)}` : null
  return useSWR<ImportMappingDetail>(key, (u: string) => get<ImportMappingDetail>(u), quiet)
}

export function useImportMappingTemplates(enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? `${BASE}/templates` : null
  return useSWR<{ items: MappingTemplate[] }>(
    key,
    (u: string) => get<{ items: MappingTemplate[] }>(u),
    { ...quiet, dedupingInterval: 300_000 }
  )
}

export function invalidateImportMappings() {
  return mutate((key) => typeof key === 'string' && key.startsWith(BASE), undefined, {
    revalidate: true,
  })
}

export const IDENTITY_CHANGE_CODE = 'identity_change_unconfirmed'

export interface IdentityChange {
  previous: string[]
  next: string[]
}

/** The identity change a 409 describes, or null for any other error. */
export function identityChangeOf(err: unknown): IdentityChange | null {
  if (!(err instanceof ApiClientError) || err.statusCode !== 409) return null
  if ((err.code ?? '').toLowerCase() !== IDENTITY_CHANGE_CODE) return null
  const d = (err.details ?? {}) as { previous_identity?: unknown; identity?: unknown }
  const list = (v: unknown) =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
  return { previous: list(d.previous_identity), next: list(d.identity) }
}

/** Validation reasons from a 422, when the API sent them. */
export function validationErrorsOf(err: unknown): string[] {
  if (!(err instanceof ApiClientError)) return []
  const errors = (err.details as { errors?: unknown } | undefined)?.errors
  return Array.isArray(errors) ? errors.filter((x): x is string => typeof x === 'string') : []
}

export interface CreateInput {
  name: string
  description?: string
  mapping: MappingDocument
  note?: string
}

export const importMappingsApi = {
  create: (input: CreateInput) => post<MappingWithVersion>(BASE, input),
  getVersion: (id: string, version: number) =>
    get<MappingWithVersion>(`${BASE}/${encodeURIComponent(id)}/versions/${version}`),
  createVersion: (
    id: string,
    input: { mapping: MappingDocument; note?: string; confirm_identity_change?: boolean }
  ) => post<MappingWithVersion>(`${BASE}/${encodeURIComponent(id)}/versions`, input),
  update: (id: string, input: { name?: string; description?: string }) =>
    patch<ImportMapping>(`${BASE}/${encodeURIComponent(id)}`, input),
  /** The API client asks for step-up and retries when the API requires it. */
  remove: (id: string) => del<void>(`${BASE}/${encodeURIComponent(id)}`),
  validate: (mapping: MappingDocument) => post<ValidateResult>(`${BASE}/verify`, { mapping }),
}

/** A preview the API refused; `errors` holds the validation reasons of a 422. */
export class PreviewError extends Error {
  readonly status: number
  readonly errors: string[]

  constructor(message: string, status: number, errors: string[] = []) {
    super(message)
    this.name = 'PreviewError'
    this.status = status
    this.errors = errors
  }
}

export type PreviewMapping = { document: MappingDocument } | { mappingId: string; version: number }

/**
 * POST /import-mappings/preview (multipart). Nothing is stored. Raw fetch:
 * the body is multipart and a 422 or 429 is an expected answer, not a toast.
 */
export async function previewMapping(
  mapping: PreviewMapping,
  file: File,
  signal?: AbortSignal
): Promise<PreviewResult> {
  const form = new FormData()
  if ('document' in mapping) {
    form.append('mapping', JSON.stringify(mapping.document))
  } else {
    form.append('mapping_id', mapping.mappingId)
    form.append('version', String(mapping.version))
  }
  form.append('file', file)
  const res = await csrfFetch(`${BASE}/preview`, { method: 'POST', body: form, signal })
  let body: unknown = null
  try {
    body = await res.json()
  } catch {
    body = null
  }
  if (!res.ok) {
    const err = (body ?? {}) as {
      message?: string
      details?: { errors?: unknown }
      error?: { message?: string; details?: { errors?: unknown } }
    }
    const details = err.details ?? err.error?.details
    const errors = Array.isArray(details?.errors)
      ? details.errors.filter((x): x is string => typeof x === 'string')
      : []
    const message = err.message ?? err.error?.message ?? `HTTP ${res.status}`
    throw new PreviewError(message, res.status, errors)
  }
  return body as PreviewResult
}
