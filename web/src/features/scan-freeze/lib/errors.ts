import { ApiClientError } from '@/lib/api/error-handler'

/** The API code of a trigger refused by an active scan freeze window. */
export const SCAN_FREEZE_ACTIVE = 'SCAN_FREEZE_ACTIVE'

/** Was the trigger refused because a scan freeze window is active (409)? */
export function isFreezeRefusal(err: unknown): boolean {
  if (!(err instanceof ApiClientError)) return false
  const fromDetails = (err.details as { code?: unknown } | undefined)?.code
  return err.code === SCAN_FREEZE_ACTIVE || fromDetails === SCAN_FREEZE_ACTIVE
}
