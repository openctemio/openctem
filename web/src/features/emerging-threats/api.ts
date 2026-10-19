'use client'

import { useCallback } from 'react'
import useSWR, { useSWRConfig, type SWRConfiguration } from 'swr'
import { get, post, put } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type {
  EmergingThreatDetail,
  EmergingThreatsPage,
  EmergingThreatsSettings,
  ListFilters,
  NotAffectedReason,
  TargetState,
} from './types'

export const EMERGING_THREATS_ENDPOINT = '/api/v1/emerging-threats'
export const EMERGING_SETTINGS_ENDPOINT = '/api/v1/organization/settings/emerging-threats'
const TASKS_ENDPOINT = '/api/v1/remediation/tasks'

export const DEFAULT_PER_PAGE = 25

const quietConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

/** The list request for a set of filters; the default state is "open". */
export function listUrl(f: ListFilters): string {
  const p = new URLSearchParams()
  if (f.level) p.set('level', f.level)
  p.set('state', f.state ?? 'open')
  if (f.tier) p.set('tier', f.tier)
  if (f.internetOnly) p.set('exposure', 'internet')
  if (f.search?.trim()) p.set('search', f.search.trim())
  p.set('page', String(f.page ?? 1))
  p.set('per_page', String(f.perPage ?? DEFAULT_PER_PAGE))
  return `${EMERGING_THREATS_ENDPOINT}?${p.toString()}`
}

export function detailUrl(id: string): string {
  return `${EMERGING_THREATS_ENDPOINT}/${encodeURIComponent(id)}`
}

export function useEmergingThreats(filters: ListFilters, config?: SWRConfiguration) {
  return useSWR<EmergingThreatsPage>(listUrl(filters), (url: string) => get(url), {
    ...quietConfig,
    keepPreviousData: true,
    ...config,
  })
}

export function useEmergingThreat(id: string | undefined, config?: SWRConfiguration) {
  return useSWR<EmergingThreatDetail>(id ? detailUrl(id) : null, (url: string) => get(url), {
    ...quietConfig,
    ...config,
  })
}

/** Re-reads every cached emerging-threat list and record. */
export function useRevalidateEmergingThreats() {
  const { mutate } = useSWRConfig()
  return useCallback(
    () => mutate((key) => typeof key === 'string' && key.startsWith(EMERGING_THREATS_ENDPOINT)),
    [mutate]
  )
}

/** Moves an alert to a state; the API answers the updated alert. */
export function setAlertState(
  id: string,
  state: TargetState,
  extra?: { reason: NotAffectedReason; note?: string }
): Promise<EmergingThreatDetail> {
  const body: Record<string, string> = { state }
  if (extra) {
    body.reason = extra.reason
    if (extra.note?.trim()) body.note = extra.note.trim()
  }
  return post<EmergingThreatDetail>(`${detailUrl(id)}/state`, body)
}

/** A remediation task over the given findings (the API refuses findings already in a task). */
export function createRemediationTask(
  title: string,
  findingIds: string[]
): Promise<{ id: string }> {
  return post<{ id: string }>(TASKS_ENDPOINT, { title, finding_ids: findingIds })
}

/** The organization's emerging-threat policy (owners and admins). */
export function useEmergingThreatsSettings(config?: SWRConfiguration) {
  const { can } = usePermissions()
  const key = can(Permission.TeamUpdate) ? EMERGING_SETTINGS_ENDPOINT : null
  return useSWR<EmergingThreatsSettings>(key, (url: string) => get(url), {
    ...quietConfig,
    ...config,
  })
}

export function updateEmergingThreatsSettings(
  payload: EmergingThreatsSettings
): Promise<EmergingThreatsSettings> {
  return put<EmergingThreatsSettings>(EMERGING_SETTINGS_ENDPOINT, payload)
}
