/**
 * Plain-language verbs for an asset's relationships, read from the asset being
 * viewed. An edge has one stored direction (source -> target); the same edge
 * reads "Resolves to 203.0.113.21" on the name and "Names that resolve here:
 * portal.example.com" on the address. Each (type, direction) pair has its own
 * phrase so the reader never has to decode an arrow or a title-cased label.
 */
import type { RelationshipType } from '../types'

export type RelationDirection = 'outgoing' | 'incoming'

/** English text of each verb; the en/vi dictionaries hold the same keys. */
export const RELATION_VERBS: Record<RelationshipType, Record<RelationDirection, string>> = {
  resolves_to: { outgoing: 'Resolves to', incoming: 'Names that resolve here' },
  cname_of: { outgoing: 'Alias (CNAME) of', incoming: 'Aliases (CNAME) pointing here' },
  exposes: { outgoing: 'Exposes', incoming: 'Exposed through' },
  serves_certificate: { outgoing: 'Serves certificate', incoming: 'Served by' },
  runs_on: { outgoing: 'Runs on', incoming: 'Hosts' },
  contains: { outgoing: 'Contains', incoming: 'Part of' },
  deployed_to: { outgoing: 'Deployed to', incoming: 'Deployments from' },
  load_balances: { outgoing: 'Balances traffic to', incoming: 'Behind load balancer' },
  protected_by: { outgoing: 'Protected by', incoming: 'Protects' },
  depends_on: { outgoing: 'Depends on', incoming: 'Used by' },
  stores_data_in: { outgoing: 'Stores data in', incoming: 'Holds data for' },
  sends_data_to: { outgoing: 'Sends data to', incoming: 'Receives data from' },
  replicates_to: { outgoing: 'Replicates to', incoming: 'Replica of' },
  authenticates_to: { outgoing: 'Signs in to', incoming: 'Accepts sign-ins from' },
  has_access_to: { outgoing: 'Has access to', incoming: 'Accessible by' },
  granted_to: { outgoing: 'Granted to', incoming: 'Holds grants' },
  peer_of: { outgoing: 'Peer of', incoming: 'Peer of' },
  monitors: { outgoing: 'Monitors', incoming: 'Monitored by' },
  manages: { outgoing: 'Manages', incoming: 'Managed by' },
}

/**
 * Reading order of the groups: how the asset is reached and what it serves
 * first (the exposure story), then where it runs and what it belongs to, then
 * data and identity flows, then operations.
 */
const ORDER: RelationshipType[] = [
  'resolves_to',
  'cname_of',
  'exposes',
  'serves_certificate',
  'load_balances',
  'protected_by',
  'runs_on',
  'contains',
  'deployed_to',
  'depends_on',
  'stores_data_in',
  'sends_data_to',
  'replicates_to',
  'authenticates_to',
  'has_access_to',
  'granted_to',
  'peer_of',
  'monitors',
  'manages',
]

export function relationVerbKey(type: string, direction: RelationDirection): string {
  return `assets.related.verb.${type}.${direction}`
}

/** English fallback for a verb; unknown types read as their humanised key. */
export function relationVerbFallback(type: string, direction: RelationDirection): string {
  const v = (RELATION_VERBS as Record<string, Record<RelationDirection, string>>)[type]
  if (v) return v[direction]
  const words = type.replace(/_/g, ' ')
  return direction === 'outgoing'
    ? words.charAt(0).toUpperCase() + words.slice(1)
    : `${words} (incoming)`
}

/** Sort key for a group: registry order, outgoing before incoming. */
export function relationGroupRank(type: string, direction: RelationDirection): number {
  const i = ORDER.indexOf(type as RelationshipType)
  return (i < 0 ? ORDER.length : i) * 2 + (direction === 'outgoing' ? 0 : 1)
}

/** An edge not reported again for this long is shown as possibly stale. */
export const STALE_EDGE_DAYS = 30

export type EdgeSource = 'scanner' | 'import' | 'manual' | 'inferred'

/** Who recorded an edge, in words a reader knows. */
export function edgeSource(discoveryMethod: string): EdgeSource {
  switch (discoveryMethod) {
    case 'automatic':
      return 'scanner'
    case 'imported':
      return 'import'
    case 'inferred':
      return 'inferred'
    default:
      return 'manual'
  }
}
