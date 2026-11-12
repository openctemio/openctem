'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import { storyUrl, type Story } from '../lib/story'

/**
 * GET /api/v1/{findings|assets}/{id}/story: how the subject was found. The
 * API answers 404 for a subject the caller may not read and hides every step
 * outside their data scope or permissions.
 */
export function useStory(kind: 'finding' | 'asset', id: string | null) {
  const { can } = usePermissions()
  const allowed = can(kind === 'finding' ? Permission.FindingsRead : Permission.AssetsRead)
  const key = id && allowed ? storyUrl(kind, id) : null
  const { data, error, isLoading, mutate } = useSWR<Story>(key, get, { revalidateOnFocus: false })
  return { story: data, error, isLoading, mutate }
}
