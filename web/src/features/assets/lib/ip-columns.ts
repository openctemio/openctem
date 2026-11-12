/**
 * The IP addresses tab's columns: Network, Names and Open ports. The values are
 * scan output (names resolving to the address, services on its ports), so they
 * are shown as text only.
 */
import type { Asset } from '../types/asset.types'

/** Names shown before "+N". */
export const IP_NAMES_SHOWN = 3
/** Ports shown before "+N". */
export const IP_PORTS_SHOWN = 5

type IPPort = NonNullable<Asset['ip']>['ports'][number]

/** `443/tcp https`: the port, its transport and the service on it, when known. */
export function formatPort(p: IPPort): string {
  const base = p.transport ? `${p.port}/${p.transport}` : String(p.port)
  return p.service ? `${base} ${p.service}` : base
}

/** What a list of values shows: the first ones, and how many more there are. */
export function shownWithMore<T>(
  values: readonly T[],
  total: number,
  shown: number
): { shown: T[]; more: number } {
  const head = values.slice(0, shown)
  return { shown: head, more: Math.max(0, Math.max(total, values.length) - head.length) }
}

/** The network as a filter value: a CIDR the `network` field takes. */
export function networkFilter(network: string | undefined): string | undefined {
  return network && /^[0-9a-fA-F:.]+\/\d{1,3}$/.test(network) ? network : undefined
}
