/**
 * Scan window hooks (RFC-067): policies, the draft-policy preview, the
 * evaluation of targets and assets, and overrides. Tenant from the session.
 * Reads need scans:read; policy writes scans:windows:manage; overrides
 * scans:windows:override (and a fresh authenticator code). The API is the
 * authority: these hooks only skip requests the caller cannot make.
 */

'use client'

import { useMemo } from 'react'
import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'
import { del, get, patch, post } from '@/lib/api/client'

import type {
  ScanWindowEvaluateRequest,
  ScanWindowEvaluateResponse,
  ScanWindowOverride,
  ScanWindowOverrideList,
  ScanWindowOverrideRequest,
  ScanWindowPolicy,
  ScanWindowPolicyList,
  ScanWindowPolicyPreview,
  ScanWindowPolicyRequest,
} from '../types'

export const POLICIES_URL = '/api/v1/scan-window-policies'
export const OVERRIDES_URL = '/api/v1/scan-window-overrides'
export const EVALUATE_URL = '/api/v1/scan-windows/preview'
export const POLICY_PREVIEW_URL = `${POLICIES_URL}/preview`

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

/**
 * The organization's policies. Pass `enabled: false` when the caller cannot
 * read scans, so no request (and no 403) is made. Whether each window is
 * open is computed by the server at read time, so the list refreshes every
 * minute.
 */
export function useScanWindowPolicies(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<ScanWindowPolicyList>(
    currentTenant && enabled ? POLICIES_URL : null,
    (url: string) => get<ScanWindowPolicyList>(url),
    { ...defaultConfig, refreshInterval: 60_000 }
  )
}

/** The organization's 50 most recent overrides. */
export function useScanWindowOverrides(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<ScanWindowOverrideList>(
    currentTenant && enabled ? OVERRIDES_URL : null,
    (url: string) => get<ScanWindowOverrideList>(url),
    defaultConfig
  )
}

/**
 * What the windows mean now for targets and assets. Skipped when disabled
 * or when there is nothing to evaluate. An asset outside the caller's data
 * scope answers 404 (shown as no decision).
 */
export function useWindowDecisions(req: ScanWindowEvaluateRequest, enabled = true) {
  const { currentTenant } = useTenant()
  const body = JSON.stringify(req)
  const empty = (req.targets?.length ?? 0) + (req.asset_ids?.length ?? 0) === 0
  const key = currentTenant && enabled && !empty ? [EVALUATE_URL, body] : null
  return useSWR<ScanWindowEvaluateResponse>(
    key,
    () => post<ScanWindowEvaluateResponse>(EVALUATE_URL, JSON.parse(body)),
    { ...defaultConfig, shouldRetryOnError: false }
  )
}

/**
 * The preview of a draft policy (its matching assets and next openings).
 * The caller debounces the draft; null skips the request.
 */
export function usePolicyPreview(draft: ScanWindowPolicyRequest | null) {
  const body = useMemo(() => (draft ? JSON.stringify(draft) : null), [draft])
  return useSWR<ScanWindowPolicyPreview>(
    body ? [POLICY_PREVIEW_URL, body] : null,
    () => post<ScanWindowPolicyPreview>(POLICY_PREVIEW_URL, JSON.parse(body as string)),
    { revalidateOnFocus: false, shouldRetryOnError: false, keepPreviousData: true }
  )
}

/** Revalidates every policy, override and evaluation request. */
export async function invalidateScanWindows() {
  const { mutate } = await import('swr')
  await mutate(
    (key) => {
      const k = Array.isArray(key) ? key[0] : key
      return (
        typeof k === 'string' &&
        (k.startsWith(POLICIES_URL) || k.startsWith(OVERRIDES_URL) || k === EVALUATE_URL)
      )
    },
    undefined,
    { revalidate: true }
  )
}

export function createScanWindowPolicy(body: ScanWindowPolicyRequest) {
  return post<ScanWindowPolicy>(POLICIES_URL, body)
}

export function updateScanWindowPolicy(id: string, body: ScanWindowPolicyRequest) {
  return patch<ScanWindowPolicy>(`${POLICIES_URL}/${encodeURIComponent(id)}`, body)
}

export function deleteScanWindowPolicy(id: string) {
  return del<void>(`${POLICIES_URL}/${encodeURIComponent(id)}`)
}

export function createScanWindowOverride(body: ScanWindowOverrideRequest) {
  return post<ScanWindowOverride>(OVERRIDES_URL, body)
}

export function revokeScanWindowOverride(id: string) {
  return del<void>(`${OVERRIDES_URL}/${encodeURIComponent(id)}`)
}
