'use client'

import { useCallback, useState } from 'react'
import useSWR from 'swr'
import { get, post, put } from '@/lib/api/client'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  POSTURE_REFRESH_URL,
  POSTURE_SCHEDULE_URL,
  postureUrl,
  type PostureResponse,
  type PostureSchedule,
  type PostureState,
} from '../lib/posture'

const swrConfig = {
  revalidateOnFocus: false,
  keepPreviousData: true,
  shouldRetryOnError: (error: { statusCode?: number }) =>
    !((error?.statusCode ?? 0) >= 400 && (error?.statusCode ?? 0) < 500),
}

/** The posture of the caller's scope (one root domain when given); nothing without assets:read. */
export function usePosture(rootDomain?: string, enabled = true) {
  const { can } = usePermissions()
  const key = enabled && can(Permission.AssetsRead) ? postureUrl(rootDomain) : null
  const { data, error, isLoading, mutate } = useSWR<PostureResponse>(
    key,
    (u: string) => get<PostureResponse>(u),
    swrConfig
  )
  return { posture: data, error, isLoading, mutate }
}

/** Recalculate now (budgeted by the API: 429 with Retry-After). */
export function useRecalculatePosture(onDone?: () => void) {
  const [running, setRunning] = useState(false)
  const run = useCallback(async (): Promise<PostureState> => {
    setRunning(true)
    try {
      const st = await post<PostureState>(POSTURE_REFRESH_URL, {})
      onDone?.()
      return st
    } finally {
      setRunning(false)
    }
  }, [onDone])
  return { run, running }
}

/** Change the refresh schedule (settings:write). */
export async function setPostureSchedule(refresh: PostureSchedule): Promise<PostureState> {
  return put<PostureState>(POSTURE_SCHEDULE_URL, { refresh_every: refresh })
}
