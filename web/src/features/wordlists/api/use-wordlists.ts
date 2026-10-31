/**
 * Organization wordlist hooks: /api/v1/wordlists. Pass `enabled: false` when
 * the caller lacks scans:content:read so no request (and no 403) is made.
 * The API is the authority on every write.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'
import { del, get, patch, post } from '@/lib/api/client'
import { API_BASE, wordlistEndpoints } from '@/lib/api/endpoints'

import type {
  CreateWordlistRequest,
  UpdateWordlistRequest,
  Wordlist,
  WordlistList,
  WordlistPreview,
  WordlistSaveResponse,
} from '../types'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

/** The organization's lists (without their labels). */
export function useWordlists(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<WordlistList>(
    currentTenant && enabled ? wordlistEndpoints.list() : null,
    (url: string) => get<WordlistList>(url),
    defaultConfig
  )
}

/** The counts of the label list an enumeration job of root would carry. */
export function useWordlistPreview(root: string | null, depth: 'standard' | 'deep' = 'standard') {
  const { currentTenant } = useTenant()
  return useSWR<WordlistPreview>(
    currentTenant && root ? wordlistEndpoints.preview(root, depth) : null,
    (url: string) => get<WordlistPreview>(url),
    defaultConfig
  )
}

/** Revalidates every wordlist request, keeping the data on screen. */
export async function invalidateWordlists() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.startsWith(API_BASE.WORDLISTS))
}

export function getWordlist(id: string) {
  return get<Wordlist>(wordlistEndpoints.get(id))
}

export function createWordlist(body: CreateWordlistRequest) {
  return post<WordlistSaveResponse>(wordlistEndpoints.create(), body)
}

export function updateWordlist(id: string, body: UpdateWordlistRequest) {
  return patch<WordlistSaveResponse>(wordlistEndpoints.update(id), body)
}

export function deleteWordlist(id: string) {
  return del<void>(wordlistEndpoints.delete(id))
}
