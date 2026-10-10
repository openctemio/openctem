'use client'

/**
 * POST /api/v1/scope/check: a dry run of the whole active-probe gate for the
 * caller (RFC-054 §6.4). Nothing is dispatched, audited or logged. It is the
 * one authority the web asks "may these targets be probed, and if not, what
 * would fix it"; there is no client-side scope matching.
 */

import { useMemo } from 'react'
import useSWR from 'swr'
import { post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import type { ApiCheckScopeResponse, ApiScopeCheckResult, CheckScopeInput } from './scope-api.types'

/** Targets per POST /scope/check request (the API's limit). */
export const SCOPE_CHECK_BATCH = 200

/** Targets the hook checks at most (a scan takes up to 1000). */
export const SCOPE_CHECK_MAX = 1000

/** Trimmed, de-duplicated (case-insensitive), non-empty, in order. */
export function normalizeCheckTargets(targets: readonly string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of targets) {
    const t = raw.trim()
    const k = t.toLowerCase()
    if (!t || seen.has(k)) continue
    seen.add(k)
    out.push(t)
    if (out.length >= SCOPE_CHECK_MAX) break
  }
  return out
}

export async function checkScope(
  targets: string[],
  opts: Omit<CheckScopeInput, 'targets'> = {}
): Promise<ApiScopeCheckResult[]> {
  return (await checkScopeAt(targets, opts)).results
}

/** The results, and the probe tier the server checked them at. */
export async function checkScopeAt(
  targets: string[],
  opts: Omit<CheckScopeInput, 'targets'> = {}
): Promise<{ results: ApiScopeCheckResult[]; tier?: number }> {
  const results: ApiScopeCheckResult[] = []
  let tier: number | undefined
  for (let i = 0; i < targets.length; i += SCOPE_CHECK_BATCH) {
    const res = await post<ApiCheckScopeResponse>('/api/v1/scope/check', {
      ...opts,
      targets: targets.slice(i, i + SCOPE_CHECK_BATCH),
    })
    results.push(...(res?.results ?? []))
    tier ??= res?.tier
  }
  return { results, tier }
}

export interface UseScopeCheckOptions extends Omit<CheckScopeInput, 'targets'> {
  /** false skips the request (for example while the user is still typing). */
  enabled?: boolean
}

/**
 * Checks `targets` (debounce them in the caller). Results are keyed by the
 * target string the caller sent. Callers without scope:read get no request
 * and `available: false`, so they can hide the preview.
 */
export function useScopeCheck(targets: readonly string[], opts: UseScopeCheckOptions = {}) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const available = can(Permission.ScopeRead)
  const { enabled = true, sensor_preference, tier, scanner_name } = opts
  const list = normalizeCheckTargets(targets)
  const key =
    currentTenant && available && enabled && list.length > 0
      ? [
          'scope-check',
          currentTenant.id,
          sensor_preference ?? '',
          tier ?? '',
          scanner_name ?? '',
          ...list,
        ]
      : null
  const {
    data: answer,
    error,
    isLoading,
    mutate,
  } = useSWR(key, () => checkScopeAt(list, { sensor_preference, tier, scanner_name }), {
    revalidateOnFocus: false,
    keepPreviousData: true,
    shouldRetryOnError: false,
  })
  const data = answer?.results
  // Stable between renders while the answer is unchanged, so tables can put
  // `resultFor` in their column memo.
  const resultFor = useMemo(() => {
    const byTarget = new Map<string, ApiScopeCheckResult>()
    for (const r of data ?? []) {
      if (r.target) byTarget.set(r.target.toLowerCase(), r)
    }
    return (target: string) => byTarget.get(target.trim().toLowerCase())
  }, [data])
  return {
    available,
    results: data,
    /** The probe tier the server checked at (0 passive, 1 safe active, 2 intrusive). */
    tier: answer?.tier,
    /** The result for a target (case-insensitive), if checked. */
    resultFor,
    error,
    isLoading,
    recheck: mutate,
  }
}
