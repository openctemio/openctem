/**
 * Watchers of a finding or a remediation task (RFC-120): the People section
 * reads `participants`, the bell writes `subscription`, adding and removing
 * people write `watchers`. The API decides what the caller may see (names only
 * with the member list, never emails) and who can be added; this only renders
 * its answers.
 */

import useSWR from 'swr'
import { get, put, post, del } from '@/lib/api/client'
import { handleApiError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import { useState } from 'react'

export type WorkItemKind = 'finding' | 'task'

export type WatcherReason =
  | 'manual'
  | 'added'
  | 'assigned'
  | 'commented'
  | 'status_changed'
  | 'fix_claimed'
  | 'mentioned'
  | 'approval'
  | 'created'

export interface Watcher {
  user_id: string
  name: string
  avatar_url?: string
  reason: WatcherReason
  added_by?: string
  /** Who added this watcher; absent when they took part themselves or the adder left. */
  added_by_name?: string
  since: string
}

export interface AssetOwner {
  user_id: string
  name: string
  avatar_url?: string
  type: string
}

export interface Participants {
  /** Watchers who can still read the item. */
  watcher_count: number
  /** false: only the count is shown (no member-list permission, or a pentest client). */
  names_visible: boolean
  watchers: Watcher[]
  asset_owners: AssetOwner[]
  /** The caller (`user_id`, to find their own row) and their own subscription. */
  me: { user_id?: string; state: '' | 'subscribed' | 'unsubscribed'; reason?: string }
}

export function participantsBase(kind: WorkItemKind, id: string): string {
  const seg = encodeURIComponent(id)
  return kind === 'finding' ? `/api/v1/findings/${seg}` : `/api/v1/remediation/tasks/${seg}`
}

export function participantsKey(kind: WorkItemKind, id: string): string {
  return `${participantsBase(kind, id)}/participants`
}

export interface UseParticipantsOptions {
  /** The toast when a write fails without a message from the API (translated by the caller). */
  errorMessage?: string
}

/** A null id disables the request. */
export function useParticipants(
  kind: WorkItemKind,
  id: string | null | undefined,
  { errorMessage = 'Could not update watchers' }: UseParticipantsOptions = {}
) {
  const { currentTenant } = useTenant()
  const [busy, setBusy] = useState(false)
  const key = currentTenant && id ? participantsKey(kind, id) : null
  const { data, isLoading, mutate } = useSWR<Participants>(
    key,
    (url: string) => get<Participants>(url),
    { revalidateOnFocus: false }
  )

  // Each write answers the fresh list: it replaces the cache without a refetch.
  async function write(call: () => Promise<Participants>) {
    if (!id) return false
    setBusy(true)
    try {
      await mutate(await call(), { revalidate: false })
      return true
    } catch (error) {
      handleApiError(error, { showToast: true, fallbackMessage: errorMessage })
      return false
    } finally {
      setBusy(false)
    }
  }

  return {
    participants: data,
    isLoading,
    busy,
    setWatching: (watching: boolean) =>
      id
        ? write(() =>
            put<Participants>(`${participantsBase(kind, id)}/subscription`, {
              state: watching ? 'subscribed' : 'unsubscribed',
            })
          )
        : Promise.resolve(false),
    addWatchers: (userIds: string[]) =>
      id
        ? write(() =>
            post<Participants>(`${participantsBase(kind, id)}/watchers`, { user_ids: userIds })
          )
        : Promise.resolve(false),
    removeWatcher: (userId: string) =>
      id
        ? write(() =>
            del<Participants>(
              `${participantsBase(kind, id)}/watchers/${encodeURIComponent(userId)}`
            )
          )
        : Promise.resolve(false),
  }
}
