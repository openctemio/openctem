import type { ProxyPool, SetProxyAssignmentRequest } from '../types'

export const POOL_PREFIX = 'pool:'

/** The select value for a request, and back. */
export function pathValue(mode?: string, poolId?: string | null): string {
  if (mode === 'direct') return 'direct'
  if (mode === 'pool' && poolId) return `${POOL_PREFIX}${poolId}`
  return 'inherit'
}

export function pathRequest(value: string): SetProxyAssignmentRequest {
  if (value === 'direct') return { mode: 'direct' }
  if (value.startsWith(POOL_PREFIX))
    return { mode: 'pool', pool_id: value.slice(POOL_PREFIX.length) }
  return { mode: 'inherit' }
}

/** Capabilities the platform needs before a pooled sensor gets jobs. */
const CAP_UPSTREAM = 'egress.upstream@1'
const CAP_CONFINED = 'net.confined@1'
const CAP_VALIDATE = 'egress.validate@1'

/**
 * What the sensor's path means for its jobs right now, from the platform's
 * dispatch rules (api internal/app/command/egress.go):
 * - pool-disabled: its own pool is disabled, so its scans fail closed;
 * - unsupported: a pool applies and the sensor does not report proxy
 *   support, so it receives no scan or validation jobs;
 * - validate-waits: scans run through the pool, validation jobs wait for a
 *   sensor version that sends them through it too.
 * `capabilities` is what the sensor reported (null: never reported).
 */
export type PathWarning = 'pool-disabled' | 'unsupported' | 'validate-waits'

export function pathWarning(
  value: string,
  pools: Pick<ProxyPool, 'id' | 'enabled' | 'is_default'>[],
  capabilities: string[] | null | undefined
): PathWarning | null {
  let applies = false
  if (value.startsWith(POOL_PREFIX)) {
    const own = pools.find((p) => p.id === value.slice(POOL_PREFIX.length))
    if (own && !own.enabled) return 'pool-disabled'
    applies = true
  } else if (value === 'inherit') {
    applies = pools.some((p) => p.is_default && p.enabled)
  }
  if (!applies) return null
  const caps = capabilities ?? []
  if (!caps.includes(CAP_UPSTREAM) || !caps.includes(CAP_CONFINED)) return 'unsupported'
  if (!caps.includes(CAP_VALIDATE)) return 'validate-waits'
  return null
}
