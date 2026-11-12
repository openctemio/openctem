/**
 * The Targets step's result column groups what a scan will probe by kind, so
 * each kind's setting sits next to it: domains (with the coverage level),
 * wildcards, address ranges (with how ranges are scanned), single addresses,
 * URLs, picked assets and asset groups. Pure: scope answers are looked up by
 * each row's `checkAs`, the target as it is sent to the scope check.
 */

import { isRefusedKind, type ClassifiedTarget } from './target-format'
import type { CoverageLevel } from './coverage-expansion'

export type TargetGroupKind =
  'domains' | 'wildcards' | 'ranges' | 'addresses' | 'urls' | 'assets' | 'groups'

/** Display order: what a person types most, then picked sources. */
export const TARGET_GROUP_ORDER: readonly TargetGroupKind[] = [
  'domains',
  'wildcards',
  'ranges',
  'addresses',
  'urls',
  'assets',
  'groups',
]

export interface TargetRow {
  key: string
  /** As typed or picked. */
  label: string
  /** The target the scope check answered for; none for an asset group. */
  checkAs?: string
  /** The coverage level scans the entry as something else (a domain as *.domain). */
  scannedAs?: string
  /** Added by the coverage level (an address a name resolves to), not typed. */
  added?: boolean
}

export interface TargetGroup {
  kind: TargetGroupKind
  rows: TargetRow[]
}

export interface GroupTargetsInput {
  /** The typed entries, classified (invalid ones are skipped). */
  typed: readonly ClassifiedTarget[]
  coverage: CoverageLevel
  assets: readonly { id: string; name: string }[]
  groups: readonly { id: string; name: string }[]
  /** Addresses the `subdomains_ips` level adds. */
  addedAddresses?: readonly string[]
}

function kindGroup(kind: ClassifiedTarget['kind']): TargetGroupKind | null {
  switch (kind) {
    case 'domain':
      return 'domains'
    case 'wildcard':
      return 'wildcards'
    case 'cidr':
      return 'ranges'
    case 'ipv4':
    case 'ipv6':
      return 'addresses'
    case 'url':
    case 'host:port':
      return 'urls'
    default:
      return null
  }
}

/** The non-empty groups in display order, each entry once. */
export function groupTargets(input: GroupTargetsInput): TargetGroup[] {
  const by = new Map<TargetGroupKind, TargetRow[]>()
  const push = (kind: TargetGroupKind, row: TargetRow) => {
    const rows = by.get(kind) ?? []
    rows.push(row)
    by.set(kind, rows)
  }
  const seen = new Set<string>()
  for (const entry of input.typed) {
    if (isRefusedKind(entry.kind)) continue
    const kind = kindGroup(entry.kind)
    if (!kind || seen.has(entry.value)) continue
    seen.add(entry.value)
    const wide = kind === 'domains' && input.coverage !== 'host'
    const checkAs = wide ? `*.${entry.value}` : entry.value
    push(kind, {
      key: `t:${entry.value}`,
      label: entry.input,
      checkAs,
      scannedAs: wide ? checkAs : undefined,
    })
  }
  for (const address of input.addedAddresses ?? []) {
    if (seen.has(address)) continue
    seen.add(address)
    push('addresses', { key: `e:${address}`, label: address, checkAs: address, added: true })
  }
  for (const a of input.assets) {
    push('assets', { key: `a:${a.id}`, label: a.name, checkAs: a.name })
  }
  for (const g of input.groups) {
    push('groups', { key: `g:${g.id}`, label: g.name })
  }
  return TARGET_GROUP_ORDER.filter((k) => by.has(k)).map((kind) => ({
    kind,
    rows: by.get(kind) ?? [],
  }))
}
