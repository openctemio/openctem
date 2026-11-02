/**
 * Coverage gaps and ledger outcomes that an edge protection or a rate limit
 * caused (api pkg/domain/scanrun CoverageGap, pkg/domain/coverage Verdict).
 * The vendor is a sensor-supplied token; it is shown as text, as sent.
 */

export type EdgeGapKind = 'edge_blocked' | 'edge_challenged' | 'rate_limited'

/** Where each fix is applied. The scanner-addresses card ships on the proxies page. */
export const EDGE_FIX_HREFS = {
  allow: '/settings/scanning/proxies#scanner-addresses',
  proxy: '/settings/scanning/proxies',
  rate: '/settings/scanning/tool-defaults',
} as const

/** The fixes of each kind, in the order they are offered. */
export const EDGE_FIXES: Record<EdgeGapKind, readonly (keyof typeof EDGE_FIX_HREFS)[]> = {
  edge_blocked: ['allow', 'proxy', 'rate'],
  edge_challenged: ['allow', 'proxy', 'rate'],
  rate_limited: ['rate', 'proxy'],
}

/** The kind of a run task's coverage gap, or null when it has no fix here. */
export function gapEdgeKind(gap: { reason?: string; edge?: string }): EdgeGapKind | null {
  if (gap.reason === 'rate_floor') return 'rate_limited'
  if (gap.reason === 'blocked')
    return gap.edge === 'challenged' ? 'edge_challenged' : 'edge_blocked'
  return null
}

/**
 * The one set of fixes to offer for a task's gaps: the edge fixes when any
 * host was stopped by an edge protection, else the rate fixes, else none.
 */
export function gapsFixKind(
  gaps: readonly { reason?: string; edge?: string }[]
): EdgeGapKind | null {
  let kind: EdgeGapKind | null = null
  for (const g of gaps) {
    const k = gapEdgeKind(g)
    if (k === 'edge_blocked' || k === 'edge_challenged') return k
    if (k) kind = k
  }
  return kind
}

/** The kind of a ledger pair's last outcome, or null for any other outcome. */
export function outcomeEdgeKind(outcome: string | undefined): EdgeGapKind | null {
  return outcome === 'edge_blocked' || outcome === 'edge_challenged' || outcome === 'rate_limited'
    ? outcome
    : null
}
