import type { ProxyEndpoint, ProxyPool } from '../types'

/** How many proxies are in each health state. Disabled proxies count only as disabled. */
export interface HealthSummary {
  total: number
  healthy: number
  probation: number
  quarantined: number
  disabled: number
}

const EMPTY: HealthSummary = { total: 0, healthy: 0, probation: 0, quarantined: 0, disabled: 0 }

/** The health counts of a list of proxies (one pool's endpoints). */
export function summarizeEndpoints(endpoints: Pick<ProxyEndpoint, 'enabled' | 'health'>[]) {
  const out = { ...EMPTY }
  for (const e of endpoints) {
    out.total++
    if (!e.enabled) out.disabled++
    else if (e.health.state === 'healthy') out.healthy++
    else if (e.health.state === 'probation') out.probation++
    else out.quarantined++
  }
  return out
}

/**
 * The health counts across the pools that can carry traffic: enabled pools
 * only, since a disabled pool's proxies carry no scan.
 */
export function summarizePools(pools: Pick<ProxyPool, 'enabled' | 'endpoints'>[]) {
  return pools
    .filter((p) => p.enabled)
    .map((p) => summarizeEndpoints(p.endpoints))
    .reduce(
      (a, b) => ({
        total: a.total + b.total,
        healthy: a.healthy + b.healthy,
        probation: a.probation + b.probation,
        quarantined: a.quarantined + b.quarantined,
        disabled: a.disabled + b.disabled,
      }),
      { ...EMPTY }
    )
}
