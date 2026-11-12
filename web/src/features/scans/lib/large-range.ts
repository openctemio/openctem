/**
 * The size of the large ranges (wider than a /16) of a scan, for the
 * confirmation New scan asks before such a scan is created: how many
 * addresses, how many /16 chunks the platform dispatches, and a rough
 * duration of the host discovery pass. The platform cuts each range at
 * dispatch (to the organization's scope, minus exclusions); the numbers here
 * are the upper bound. Design: api/docs/rfcs/RFC-151-large-range-targets.md.
 */

import { cidrAddressCount, isLargeRange, LARGE_RANGE_HOST_BITS } from './target-format'

/**
 * The sweep rate the estimate assumes for one sensor's host discovery, in
 * addresses a second. A planning figure shown with the estimate, not a
 * measurement: the sensor's own rate and concurrency limits decide.
 */
export const ESTIMATE_ADDRESSES_PER_SECOND = 1000

export interface LargeRangeSummary {
  /** The large ranges, as typed. */
  ranges: string[]
  /** Addresses in them. */
  addresses: bigint
  /** The /16 chunks they are dispatched as (at most). */
  chunks: number
  /** Seconds of host discovery on one sensor at ESTIMATE_ADDRESSES_PER_SECOND. */
  seconds: number
}

/** The large ranges among targets, or null when there are none. */
export function largeRangeSummary(targets: readonly string[]): LargeRangeSummary | null {
  const chunk = BigInt(1) << BigInt(LARGE_RANGE_HOST_BITS)
  const ranges: string[] = []
  let addresses = BigInt(0)
  let chunks = 0
  for (const t of targets) {
    if (!isLargeRange(t)) continue
    const n = cidrAddressCount(t) ?? BigInt(0)
    ranges.push(t)
    addresses += n
    chunks += Number(n / chunk)
  }
  if (ranges.length === 0) return null
  return {
    ranges,
    addresses,
    chunks,
    seconds: Math.ceil(Number(addresses) / ESTIMATE_ADDRESSES_PER_SECOND),
  }
}

/** A duration as hours and minutes (at least one minute). */
export function durationParts(seconds: number): { hours: number; minutes: number } {
  const minutes = Math.max(1, Math.ceil(seconds / 60))
  return { hours: Math.floor(minutes / 60), minutes: minutes % 60 }
}

/** The key a confirmation is for: the large ranges, in order. */
export function largeRangeKey(summary: LargeRangeSummary): string {
  return summary.ranges.join(',')
}
