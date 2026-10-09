/**
 * Letters of authorization (RFC-065 §13, /api/v1/scope/letters). A letter
 * authorizes nothing by itself: scope entries with the authorization source
 * "authorization_letter" name it, go through the approval policy, and
 * authorize only while it is valid. Revoking narrows, so it needs the scope
 * approval permission; the API is the authority for all of it.
 */

'use client'

import useSWR from 'swr'
import { csrfFetch, get, getApiBaseUrl, post } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import { Permission, useHasPermission } from '@/lib/permissions'

export interface LetterActorRef {
  kind: string
  id?: string
  name?: string
}

export interface AuthorizationLetter {
  id: string
  title: string
  issuer: string
  reference: string
  valid_from: string
  valid_until: string
  in_effect: boolean
  file_sha256: string
  uploaded_by?: LetterActorRef
  created_at: string
  revoked_at?: string
  revoked_by?: LetterActorRef
}

export interface LetterUploadInput {
  file: File
  title: string
  issuer: string
  reference: string
  /** YYYY-MM-DD */
  validFrom: string
  /** YYYY-MM-DD */
  validUntil: string
}

const BASE = '/api/v1/scope/letters'

export function useLetters() {
  const { currentTenant } = useTenant()
  const can = useHasPermission(Permission.ScopeRead)
  const key = currentTenant && can ? ['scope-letters', currentTenant.id] : null
  return useSWR<AuthorizationLetter[]>(
    key,
    async () => (await get<{ data: AuthorizationLetter[] }>(`${BASE}/`))?.data ?? [],
    { revalidateOnFocus: false }
  )
}

async function errorFrom(res: Response, fallback: string): Promise<ApiClientError> {
  let message = fallback
  try {
    const body = (await res.json()) as { message?: string }
    if (typeof body?.message === 'string' && body.message) message = body.message
  } catch {
    // keep the fallback
  }
  return new ApiClientError(message, 'LETTER_REQUEST_FAILED', res.status)
}

export async function uploadLetter(input: LetterUploadInput): Promise<AuthorizationLetter> {
  const form = new FormData()
  form.append('title', input.title)
  form.append('issuer', input.issuer)
  form.append('reference', input.reference)
  form.append('valid_from', input.validFrom)
  form.append('valid_until', input.validUntil)
  form.append('file', input.file)
  const res = await csrfFetch(`${BASE}/`, { method: 'POST', body: form })
  if (!res.ok) throw await errorFrom(res, `Upload failed (HTTP ${res.status})`)
  return (await res.json()) as AuthorizationLetter
}

export function revokeLetter(id: string) {
  return post<AuthorizationLetter>(`${BASE}/${encodeURIComponent(id)}/revoke`, {})
}

/** Saves the letter's file as uploaded. */
export async function downloadLetter(letter: AuthorizationLetter): Promise<void> {
  const res = await fetch(`${getApiBaseUrl()}${BASE}/${encodeURIComponent(letter.id)}/file`, {
    credentials: 'include',
  })
  if (!res.ok) throw await errorFrom(res, `Download failed (HTTP ${res.status})`)
  const blob = await res.blob()
  let objectUrl: string | null = null
  try {
    objectUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = objectUrl
    a.download = letter.title.replace(/[^\w.-]+/g, '_').slice(0, 80) || 'authorization-letter'
    a.click()
  } finally {
    if (objectUrl) URL.revokeObjectURL(objectUrl)
  }
}
