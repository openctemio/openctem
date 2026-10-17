/**
 * Small pure helpers of the lifecycle settings (api/docs/rfcs/RFC-110-tenant-lifecycles.md).
 * The API validates every value again; these only shape input and read limits.
 */

import { ApiClientError } from '@/lib/api/error-handler'

/** The key pattern of sub-statuses, lifecycles and transitions (api keyPattern). */
export const LIFECYCLE_KEY_PATTERN = /^[a-z][a-z0-9_]{1,39}$/

/** A key derived from a name: lower case, underscores, starting with a letter, at most 40. */
export function slugKey(name: string): string {
  const base = name
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/^[0-9_]+/, '')
  return base.slice(0, 40).replace(/_+$/, '')
}

export interface PlanLimitRow {
  key: string
  limit: number
  used: number
}

/** A plan limit as the page shows it: unlimited (-1 or absent) is null. */
export function planLimit(
  limits: PlanLimitRow[] | undefined,
  key: 'lifecycle_sub_statuses' | 'lifecycle_schemes'
): { limit: number; used: number; reached: boolean } | null {
  const row = limits?.find((l) => l.key === key)
  if (!row || row.limit < 0) return null
  return { limit: row.limit, used: row.used, reached: row.used >= row.limit }
}

/** Whether an API error is a plan-limit refusal. */
export function isPlanLimitError(err: unknown): boolean {
  return err instanceof ApiClientError && err.code === 'PLAN_LIMIT'
}

/** Whether an API error is the draft's If-Match conflict. */
export function isConflictError(err: unknown): boolean {
  return err instanceof ApiClientError && err.statusCode === 409
}
