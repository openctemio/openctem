/**
 * Which service-cell facts an asset type shows, in ONE place.
 *
 * The rich service cells (status with redirect chain, IP / CNAME, technology,
 * TLS …) describe the external surface only. Repositories, cloud, k8s,
 * identities, databases and the other types keep their own typed cells;
 * the label chips and the "issues found" chip apply to every type and are
 * not listed here.
 *
 * This map is the seam for the asset-type registry (RFC-042, in design):
 * when the registry lands, it supplies the cell list per type and this
 * file becomes a lookup into it. Do not add `if (type === …)` checks for
 * these cells anywhere else.
 */

import type { AssetPropertyKey } from '@/features/asset-types/lib/property-schema'

export type SurfaceCell =
  /** HTTP status with redirect chain. */
  | 'status'
  /** Port and protocol of a service. */
  | 'port'
  /** Service product / version (nmap, naabu). */
  | 'product'
  /** IP addresses with "+N". */
  | 'ip'
  /** CNAME targets with "+N". */
  | 'cname'
  /** A DNS name's CNAMEs and IPs. */
  | 'dns'
  /** ASN of an IP. */
  | 'asn'
  /** Open ports of an IP. */
  | 'ports'
  /** Technology chips. */
  | 'tech'
  /** TLS on a service (certificate expiry, issuer, SAN). */
  | 'tls'
  /** Expiry of a certificate asset. */
  | 'cert'

const WEB: readonly SurfaceCell[] = ['status', 'ip', 'cname', 'tech', 'tls']
const HTTP_SERVICE: readonly SurfaceCell[] = ['status', 'port', 'ip', 'cname', 'tech', 'tls']
const SERVICE: readonly SurfaceCell[] = ['port', 'product', 'status', 'ip', 'tech', 'tls']
const OPEN_PORT: readonly SurfaceCell[] = ['port', 'product']
const DISCOVERED_URL: readonly SurfaceCell[] = ['status']
const DNS_NAME: readonly SurfaceCell[] = ['dns']
const IP: readonly SurfaceCell[] = ['asn', 'ports']
const CERTIFICATE: readonly SurfaceCell[] = ['cert']
const API: readonly SurfaceCell[] = ['status', 'tech', 'tls']

/**
 * Keyed by `type:sub_type`, then by a bare name that is either a type or a
 * consolidated sub-type (ingest stores `http_service` as `service` / `http`,
 * `website` as `application` / `website`; see api `asset.TypeAliases`).
 */
export const SURFACE_CELLS: Readonly<Record<string, readonly SurfaceCell[]>> = {
  'service:http': HTTP_SERVICE,
  'service:open_port': OPEN_PORT,
  'service:discovered_url': DISCOVERED_URL,
  'application:website': WEB,
  'application:web_application': WEB,
  'application:api': API,
  website: WEB,
  web_application: WEB,
  http_service: HTTP_SERVICE,
  service: SERVICE,
  open_port: OPEN_PORT,
  discovered_url: DISCOVERED_URL,
  domain: DNS_NAME,
  subdomain: DNS_NAME,
  ip_address: IP,
  certificate: CERTIFICATE,
  api: API,
}

/**
 * The service-cell facts for an asset type, or null when the type is not
 * part of the external surface (it keeps its own typed cells).
 */
export function cellsForType(type: string, subType?: string): readonly SurfaceCell[] | null {
  if (subType) {
    const exact = SURFACE_CELLS[`${type}:${subType}`]
    if (exact) return exact
  }
  return SURFACE_CELLS[type] ?? null
}

/**
 * The property keys each surface fact shows. A one-type inventory whose own
 * columns already show every fact of its cells drops the "Service facts"
 * column (a certificate list has "Valid until"; it needs no expiry chip too).
 */
const SURFACE_CELL_KEYS: Readonly<Record<SurfaceCell, readonly AssetPropertyKey[]>> = {
  status: ['status_code'],
  port: ['port'],
  product: ['product'],
  ip: ['ip_addresses'],
  cname: ['cname_target'],
  dns: ['cname_target', 'ip_addresses'],
  asn: ['asn', 'asn_org'],
  ports: ['ports'],
  tech: ['technologies'],
  tls: ['has_tls', 'tls_version'],
  cert: ['not_after'],
}

/** True when `columns` already show every fact of `cells`. */
export function surfaceCellsCovered(
  cells: readonly SurfaceCell[],
  columns: readonly string[]
): boolean {
  return cells.every((c) => SURFACE_CELL_KEYS[c].some((k) => columns.includes(k)))
}
