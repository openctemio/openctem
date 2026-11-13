/**
 * The widest range one scan target of the organization may name, in host
 * bits: its scope setting max_range_prefix (a /16 unless the organization
 * opted in to wider ranges). The API enforces it; New scan uses it to say
 * why a range is too wide before create. Without scope:read, or while the
 * settings load, the /16 default applies. Design:
 * server/docs/rfcs/RFC-151-large-range-targets.md.
 */

import { useScopeSettingsApi } from '@/features/scope'
import { rangeHostBitsOf } from '../lib/target-format'

export function useRangeHostBits(canReadScope: boolean): number {
  const { data } = useScopeSettingsApi(canReadScope)
  return rangeHostBitsOf(data?.max_range_prefix)
}
