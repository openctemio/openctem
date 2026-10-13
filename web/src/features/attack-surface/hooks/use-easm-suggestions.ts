'use client'

import useSWR, { mutate as globalMutate } from 'swr'
import { get } from '@/lib/api/client'
import { useBootstrapPending } from '@/context/bootstrap-provider'
import type { EASMSuggestionCards } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import { EASM_SUGGESTIONS_COUNT_URL } from '@/context/bootstrap-session'

/** GET /api/v1/easm/suggestions: the attack surface suggestion cards. */
export const EASM_SUGGESTIONS_URL = '/api/v1/easm/suggestions'

/**
 * The scope decisions that still need a person, one card each (research/117),
 * narrowed by the server to the caller's data scope. Read only: accepting a
 * card is a bulk add of scope entries.
 */
export function useEASMSuggestions(enabled = true) {
  const { can } = usePermissions()
  const key = enabled && can(Permission.AssetsRead) ? EASM_SUGGESTIONS_URL : null
  const { data, error, isLoading, mutate } = useSWR<EASMSuggestionCards>(key, get, {
    revalidateOnFocus: false,
  })
  return { cards: data, error, isLoading, mutate }
}

/** Refetches every suggestion read (the cards and the tab badge). */
export function refreshEASMSuggestions() {
  return globalMutate((key) => typeof key === 'string' && key.startsWith(EASM_SUGGESTIONS_URL))
}

/**
 * How many decisions wait (the Suggestions tab and sidebar badge): one per
 * card, never one per row. The session bootstrap seeds it; cached a minute.
 */
export function useEASMSuggestionCount(enabled = true) {
  const bootstrapPending = useBootstrapPending()
  const key = enabled && !bootstrapPending ? EASM_SUGGESTIONS_COUNT_URL : null
  const { data } = useSWR<EASMSuggestionCards>(key, get, {
    revalidateOnFocus: false,
    revalidateIfStale: false,
    dedupingInterval: 60000,
  })
  return data?.total
}
