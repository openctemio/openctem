/**
 * What "Mark out of scope" offers for a selection (research/124): the exact
 * names and addresses, or rules that also catch what discovery finds next
 * under the same parent domain or in the same /24. The server previews and
 * validates every item; this only proposes.
 */

import { scopeItemsForAssets } from '@/features/scope/lib/scope-from-asset'
import type { ExclusionItem } from '../api/triage-api'

/** A rule proposal and how many selected names it covers. */
export interface RuleProposal {
  item: ExclusionItem
  covers: number
}

/** The exact exclusion of each selected name or address. */
export function exactExclusions(names: string[]): {
  items: ExclusionItem[]
  skipped: number
} {
  const { items, skipped } = scopeItemsForAssets(names)
  const out: ExclusionItem[] = []
  for (const i of items) {
    if (
      i.target_type === 'domain' ||
      i.target_type === 'ip_address' ||
      i.target_type === 'ip_range'
    ) {
      out.push({ exclusion_type: i.target_type, pattern: i.pattern })
    }
  }
  const skippedCount = Object.values(skipped).reduce((a, b) => a + (b ?? 0), 0)
  return { items: out, skipped: skippedCount }
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/**
 * Rules for the selection: `*.parent` for every parent domain (with at
 * least two labels, so never a bare top-level domain) that holds a selected
 * name, and the /24 of every selected IPv4 address. Most covering first.
 */
export function ruleProposals(names: string[]): RuleProposal[] {
  const { items } = exactExclusions(names)
  const parents = new Map<string, number>()
  const nets = new Map<string, number>()
  for (const i of items) {
    if (i.exclusion_type === 'domain') {
      const labels = i.pattern.split('.')
      if (labels.length >= 3) {
        const parent = labels.slice(1).join('.')
        parents.set(parent, (parents.get(parent) ?? 0) + 1)
      }
    } else if (i.exclusion_type === 'ip_address') {
      const m = IPV4.exec(i.pattern)
      if (m) {
        const net = `${m[1]}.${m[2]}.${m[3]}.0/24`
        nets.set(net, (nets.get(net) ?? 0) + 1)
      }
    }
  }
  const out: RuleProposal[] = [
    ...[...parents].map(([p, n]) => ({
      item: { exclusion_type: 'domain' as const, pattern: `*.${p}` },
      covers: n,
    })),
    ...[...nets].map(([p, n]) => ({
      item: { exclusion_type: 'cidr' as const, pattern: p },
      covers: n,
    })),
  ]
  return out.sort((a, b) => b.covers - a.covers || a.item.pattern.localeCompare(b.item.pattern))
}
