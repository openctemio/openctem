/**
 * Optimistic concurrency on finding writes.
 *
 * Every write of a finding moves its row_version. A write sent with
 * If-Match: "<row_version>" is refused with 409 FINDING_CHANGED when someone
 * else changed the finding since it was loaded; the page then reloads the
 * finding and says so, instead of overwriting the other person's change.
 */

import { ApiClientError } from '@/lib/api/error-handler'
import type { ApiRequestOptions } from '@/lib/api/types'

export const FINDING_CHANGED_CODE = 'FINDING_CHANGED'

/** A finding write the API refused because the finding changed meanwhile. */
export function isFindingChanged(error: unknown): boolean {
  return error instanceof ApiClientError && error.code === FINDING_CHANGED_CODE
}

/** Request options that make a write conditional on the version shown. */
export function ifMatchRowVersion(rowVersion?: number): ApiRequestOptions | undefined {
  if (rowVersion === undefined || rowVersion === null || !Number.isFinite(rowVersion)) {
    return undefined
  }
  return { headers: { 'If-Match': `"${rowVersion}"` } }
}

/** A write's input with the version of the finding it was decided on. */
export type WithRowVersion<T> = T & { rowVersion?: number }

/** Splits the version off a write's input. */
export function splitRowVersion<T extends object>(
  arg: WithRowVersion<T>
): [Omit<WithRowVersion<T>, 'rowVersion'>, number | undefined] {
  const { rowVersion, ...body } = arg
  return [body, rowVersion]
}
