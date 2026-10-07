'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import type { EASMDecisionResult, EASMReviewPage } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import type { AttributionDecision, AttributionState } from '@/features/assets/lib/attribution'

export interface EASMReviewQuery {
  states: AttributionState[]
  search?: string
  /** The rule that put the names in the queue (RFC-054 §6.6). */
  reason?: string
  page: number
  perPage: number
}

/** The URL of GET /api/v1/easm/candidates for a query. */
export function reviewQueueURL(q: EASMReviewQuery): string {
  const sp = new URLSearchParams()
  if (q.states.length > 0) sp.set('states', q.states.join(','))
  if (q.search) sp.set('search', q.search)
  if (q.reason) sp.set('reason', q.reason)
  sp.set('page', String(q.page))
  sp.set('per_page', String(q.perPage))
  return `/api/v1/easm/candidates?${sp.toString()}`
}

/**
 * GET /api/v1/easm/candidates — the attribution review queue (RFC-036 §6.4),
 * narrowed by the server to the caller's data scope.
 */
export function useEASMReviewQueue(q: EASMReviewQuery) {
  const { can } = usePermissions()
  const key = can(Permission.AssetsRead) ? reviewQueueURL(q) : null
  const { data, error, isLoading, mutate } = useSWR<EASMReviewPage>(key, get, {
    revalidateOnFocus: false,
    keepPreviousData: true,
  })
  return { page: data, error, isLoading, mutate }
}

/** Largest batch POST /easm/candidates/decisions accepts. */
export const MAX_DECISION_BATCH = 200

/**
 * POST /api/v1/easm/candidates/decisions — one decision on many assets
 * (audited per asset). Assets the caller may not act on come back in
 * not_found.
 */
export function useDecideReviewBatch() {
  const [saving, setSaving] = useState(false)
  const decide = async (assetIds: string[], state: AttributionDecision, note?: string) => {
    setSaving(true)
    try {
      return await post<EASMDecisionResult>('/api/v1/easm/candidates/decisions', {
        asset_ids: assetIds.slice(0, MAX_DECISION_BATCH),
        state,
        ...(note ? { note } : {}),
      })
    } finally {
      setSaving(false)
    }
  }
  return { decide, saving }
}

/** The review queue's states: what waits for a person. */
export const REVIEW_QUEUE_STATES: AttributionState[] = ['needs_review', 'candidate']

/**
 * How many names wait in the review queue (research/22 P0-12): the same
 * query and data scope as the queue's "Awaiting review" tab, so the sidebar
 * badge, the tab count and the queue always agree. Cached for a minute.
 */
export function useEASMReviewCount(enabled = true) {
  const key = enabled ? reviewQueueURL({ states: REVIEW_QUEUE_STATES, page: 1, perPage: 1 }) : null
  const { data } = useSWR<EASMReviewPage>(key, get, {
    revalidateOnFocus: false,
    dedupingInterval: 60000,
  })
  return data?.total
}
