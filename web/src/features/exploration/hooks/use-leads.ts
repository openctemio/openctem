'use client'

import { useMemo } from 'react'
import useSWR, { useSWRConfig } from 'swr'
import useSWRInfinite from 'swr/infinite'
import { get, post } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import {
  LEADS_URL,
  SUMMARY_URL,
  leadUrl,
  leadsUrl,
  type Lead,
  type LeadBulkResult,
  type LeadDetail,
  type LeadGroup,
  type LeadPage,
  type LeadSummary,
} from '../lib/leads'

/**
 * Leads of one group (and optionally one asset), newest change first,
 * following `next_before`. The API applies the caller's data scope; the
 * page needs assets:read.
 */
export function useLeads(group: LeadGroup, assetId?: string, limit = 50) {
  const { can } = usePermissions()
  const allowed = can(Permission.AssetsRead)
  const { data, error, isLoading, isValidating, size, setSize, mutate } = useSWRInfinite<LeadPage>(
    (index, previous: LeadPage | null) => {
      if (!allowed) return null
      if (index === 0) return leadsUrl({ group, assetId, limit })
      if (!previous?.next_before) return null
      return leadsUrl({ group, assetId, limit, before: previous.next_before })
    },
    get,
    { revalidateOnFocus: false, revalidateFirstPage: false }
  )
  const pages = useMemo(() => data ?? [], [data])
  const leads = useMemo(() => pages.flatMap((p) => p.data ?? []), [pages])
  return {
    leads,
    error,
    isLoading,
    allowed,
    loadingMore: isValidating && size > pages.length,
    hasMore: pages.length > 0 && !!pages[pages.length - 1]?.next_before,
    loadMore: () => setSize(size + 1),
    mutate,
  }
}

/** The few leads the asset card shows (one request, no paging). */
export function useAssetLeads(assetId: string | null, limit = 3) {
  const { can } = usePermissions()
  const key = assetId && can(Permission.AssetsRead) ? leadsUrl({ assetId, limit }) : null
  const { data, error, isLoading, mutate } = useSWR<LeadPage>(key, get, {
    revalidateOnFocus: false,
  })
  return { leads: data?.data ?? [], error, isLoading, mutate }
}

/** One lead with its links and verdicts. */
export function useLead(id: string | null) {
  const { can } = usePermissions()
  const key = id && can(Permission.AssetsRead) ? leadUrl(id) : null
  const { data, error, isLoading } = useSWR<LeadDetail>(key, get, { revalidateOnFocus: false })
  return { lead: data, error, isLoading }
}

/** The exploration figures for the viewer (organization-wide or their own scope). */
export function useLeadSummary() {
  const { can } = usePermissions()
  const key = can(Permission.AssetsRead) ? SUMMARY_URL : null
  const { data, error, isLoading, mutate } = useSWR<LeadSummary>(key, get, {
    revalidateOnFocus: false,
  })
  const refresh = async () => {
    const fresh = await post<LeadSummary>(`${SUMMARY_URL}/refresh`, {})
    await mutate(fresh, { revalidate: false })
    return fresh
  }
  return { summary: data, error, isLoading, mutate, refresh }
}

/** Revalidates every exploration list, card, lead and the summary. */
export function useRevalidateLeads() {
  const { mutate } = useSWRConfig()
  return () =>
    mutate(
      (key) =>
        (typeof key === 'string' && key.startsWith('/api/v1/exploration/')) ||
        // useSWRInfinite keys are prefixed by swr itself.
        (typeof key === 'string' && key.includes(LEADS_URL)),
      undefined,
      { revalidate: true }
    )
}

export function approveLeads(ids: string[]) {
  // scans:approve and a recent step-up: the shared client asks for the
  // step-up and retries once.
  return post<{ results: LeadBulkResult[] }>(`${LEADS_URL}/approve`, { ids })
}

export function dismissLeads(ids: string[], reason?: string) {
  return post<{ results: LeadBulkResult[] }>(`${LEADS_URL}/dismiss`, {
    ids,
    ...(reason ? { reason } : {}),
  })
}

export function askLead(input: { lead_type: string; asset_id: string; rationale: string }) {
  return post<Lead>(LEADS_URL, input)
}
