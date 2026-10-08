import type { Asset } from '../types'
import { CERT_EXPIRING_DAYS, type CertStatus } from './certificate-facts'
import {
  IP_ADDRESSES_KEY,
  propertyStrings,
  propertyValue,
  type AssetPropertyKey,
} from '@/features/asset-types/lib/property-schema'

/**
 * Read the facts scanners store on external-surface assets (web services,
 * ports, domains, IPs, certificates) from `asset.metadata` (the API's
 * `properties`).
 *
 * Every reader accepts both shapes that exist in the database:
 *
 *  - **Flat schema keys** (api/configs/asset-types.yaml): `status_code`,
 *    `title`, `server`, `technologies`, `ip_addresses`, `port`, `not_after`,
 *    … Every write path folds the old names into them (the synonyms), so a
 *    reader names only the canonical key, through `prop()`, whose key type
 *    is the registry's `AssetPropertyKey`: a key outside the schema does not
 *    compile (docs/architecture/asset-inventory-v2.md, "Property names").
 *  - **CTIS technical blocks**, one object per block under a common key,
 *    built by ingest `mappers.go`: `service.{name,port,protocol,…,tls}`,
 *    `ip_address.{version,hostname,asn,asn_org,country,ports[]}`,
 *    `domain.{registrar,expires_at,nameservers,dns_records[]}` and
 *    `certificate.{subject_cn,sans,issuer_cn,issuer_org,not_after,…}`. Their
 *    field names are the CTIS ones.
 *
 * A fact the asset does not carry is `null` / `undefined` / an empty list.
 * It is never shown as a default value (no "200", no "TCP", no "valid"):
 * see RFC-036 E8 and PR #829. Lists render nothing for it, and a drawer
 * names it once in a "Not collected yet: …" line (ui-style-contract §7,
 * "Unknown facts"). Where a reader tells "not collected" (`null`) from
 * "collected, none found" (`[]`, `{ kind: 'none' }`), the second is data
 * and is shown ("No technologies detected", "No open ports", "No TLS").
 *
 * All values here are scanner-supplied text. Render them as React text
 * children only, never as HTML.
 */

type Meta = Record<string, unknown>

function meta(asset: Pick<Asset, 'metadata'>): Meta {
  const m = asset.metadata
  return m && typeof m === 'object' ? (m as Meta) : {}
}

/** The value of a schema key. */
function prop(asset: Pick<Asset, 'metadata'>, key: AssetPropertyKey): unknown {
  return propertyValue(meta(asset), key)
}

function isMap(v: unknown): v is Meta {
  return !!v && typeof v === 'object' && !Array.isArray(v)
}

/** A CTIS technical block (`service`, `ip_address`, …), or `{}`. */
export function nested(
  asset: Pick<Asset, 'metadata'>,
  key: Extract<AssetPropertyKey, 'service' | 'ip_address' | 'domain' | 'certificate'>
): Meta {
  const v = prop(asset, key)
  return isMap(v) ? v : {}
}

function str(v: unknown): string | undefined {
  if (typeof v === 'string') {
    const t = v.trim()
    return t === '' ? undefined : t
  }
  return undefined
}

/** A positive number, from a number or a numeric string. 0 is "not recorded". */
function posNum(v: unknown): number | null {
  const n = typeof v === 'string' ? Number(v.trim()) : v
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : null
}

/** A list of non-empty strings from an array or a comma-separated string. */
function strList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => (typeof x === 'string' ? x.trim() : '')).filter(Boolean)
  if (typeof v === 'string')
    return v
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  return []
}

function uniq<T>(xs: T[]): T[] {
  return Array.from(new Set(xs))
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/** The last HTTP status a probe recorded, or null. httpx writes `status_code`. */
export function httpStatusCode(asset: Pick<Asset, 'metadata'>): number | null {
  return posNum(prop(asset, 'status_code'))
}

/**
 * The redirect hops before the final status (httpx `-fr` writes
 * `chain_status_codes`), e.g. [301, 302] for "301, 302, 200". Empty when no
 * chain was recorded: the final status alone is then all we know.
 */
export function redirectChain(asset: Pick<Asset, 'metadata'>): number[] {
  const raw = prop(asset, 'chain_status_codes')
  if (!Array.isArray(raw)) return []
  const codes = raw.map(posNum).filter((n): n is number => n !== null)
  // httpx lists the final status last; the chip shows it separately.
  const final = httpStatusCode(asset)
  if (codes.length > 0 && codes[codes.length - 1] === final) codes.pop()
  return codes
}

/** Where the service redirects to, when a probe recorded it. */
export function redirectTarget(asset: Pick<Asset, 'metadata'>): string | undefined {
  return str(prop(asset, 'redirect_url'))
}

/** The page title httpx recorded. */
export function pageTitle(asset: Pick<Asset, 'metadata'>): string | undefined {
  return str(prop(asset, 'title'))
}

/** Whether this asset is an HTTP(S) service (so `service.name` is the web server). */
export function isHttpService(asset: Pick<Asset, 'metadata' | 'subType' | 'name'>): boolean {
  const scheme = str(nested(asset, 'service').protocol)?.toLowerCase()
  if (scheme === 'http' || scheme === 'https') return true
  if (asset.subType === 'http') return true
  return /^https?:\/\//i.test(asset.name ?? '')
}

/** The web server banner (httpx `webserver`), e.g. "nginx/1.25.3". */
export function webServer(asset: Pick<Asset, 'metadata' | 'subType' | 'name'>): string | undefined {
  const fromService = isHttpService(asset) ? str(nested(asset, 'service').name) : undefined
  return str(prop(asset, 'server')) ?? fromService
}

export function contentType(asset: Pick<Asset, 'metadata'>): string | undefined {
  return str(prop(asset, 'content_type'))
}

export function cdnName(asset: Pick<Asset, 'metadata'>): string | undefined {
  return str(prop(asset, 'cdn'))
}

export function responseTimeMs(asset: Pick<Asset, 'metadata'>): number | null {
  return posNum(prop(asset, 'response_time_ms'))
}

// ---------------------------------------------------------------------------
// Technologies
// ---------------------------------------------------------------------------

export interface Technology {
  name: string
  version?: string
}

/**
 * Parse one httpx technology string. httpx `-td` writes "Name:version"
 * ("jQuery:3.3.1"); a name alone has no version. The split only happens
 * when what follows the last colon looks like a version, so a name that
 * contains a colon is kept whole.
 */
export function parseTechnology(raw: string): Technology {
  const s = raw.trim()
  const i = s.lastIndexOf(':')
  if (i > 0) {
    const version = s.slice(i + 1).trim()
    if (/^v?\d[\w.+-]*$/i.test(version)) return { name: s.slice(0, i).trim(), version }
  }
  return { name: s }
}

/**
 * The technologies fingerprinted on the asset.
 *
 * - `null`: nothing fingerprinted this asset (no `technologies` key): "not
 *   collected".
 * - `[]`: a probe ran and found none. The sensor writes `technologies: null`
 *   when httpx reported no technology, so a present-but-empty key counts as
 *   "no technologies".
 */
export function technologies(asset: Pick<Asset, 'metadata'>): Technology[] | null {
  const v = prop(asset, 'technologies')
  if (v === undefined) return null
  return uniq(strList(v)).map(parseTechnology)
}

export function formatTechnology(t: Technology): string {
  return t.version ? `${t.name} ${t.version}` : t.name
}

// ---------------------------------------------------------------------------
// Service (port, protocol, product)
// ---------------------------------------------------------------------------

export function servicePort(asset: Pick<Asset, 'metadata'>): number | null {
  return posNum(nested(asset, 'service').port) ?? posNum(prop(asset, 'port'))
}

/**
 * The service's protocol as recorded: the application protocol (`https`,
 * `ssh`) from `service.protocol`, else the flat form key (`tcp` / `udp`).
 * Lower case. Undefined when nothing recorded it (never assume TCP).
 */
export function serviceProtocol(asset: Pick<Asset, 'metadata'>): string | undefined {
  return (str(nested(asset, 'service').protocol) ?? str(prop(asset, 'protocol')))?.toLowerCase()
}

/** The transport (`tcp` / `udp`) when recorded. */
export function serviceTransport(asset: Pick<Asset, 'metadata'>): string | undefined {
  const t = str(nested(asset, 'service').transport)?.toLowerCase()
  if (t) return t
  const flat = (str(prop(asset, 'transport')) ?? str(prop(asset, 'protocol')))?.toLowerCase()
  return flat === 'tcp' || flat === 'udp' ? flat : undefined
}

export function serviceVersion(asset: Pick<Asset, 'metadata'>): string | undefined {
  return str(nested(asset, 'service').version) ?? str(prop(asset, 'version'))
}

export function serviceProduct(asset: Pick<Asset, 'metadata'>): string | undefined {
  return str(nested(asset, 'service').product) ?? str(prop(asset, 'product'))
}

export function serviceBanner(asset: Pick<Asset, 'metadata'>): string | undefined {
  return str(nested(asset, 'service').banner) ?? str(prop(asset, 'banner'))
}

/** The service name nmap/naabu recorded ("ssh", "http"), not the web server. */
export function serviceName(
  asset: Pick<Asset, 'metadata' | 'subType' | 'name'>
): string | undefined {
  if (isHttpService(asset)) return undefined
  const flat = prop(asset, 'service')
  return str(nested(asset, 'service').name) ?? (typeof flat === 'string' ? str(flat) : undefined)
}

// ---------------------------------------------------------------------------
// Network: IPs, CNAMEs, ASN, ports
// ---------------------------------------------------------------------------

export interface DnsRecord {
  type: string
  name?: string
  value: string
  ttl?: number
}

/** DNS records ingest stored under `domain.dns_records`. */
export function dnsRecords(asset: Pick<Asset, 'metadata'>): DnsRecord[] {
  const raw = nested(asset, 'domain').dns_records ?? prop(asset, 'dns_records')
  if (!Array.isArray(raw)) return []
  const out: DnsRecord[] = []
  for (const r of raw) {
    if (!isMap(r)) continue
    const type = str(r.type)?.toUpperCase()
    const value = str(r.value)
    if (!type || !value) continue
    out.push({ type, value, name: str(r.name), ttl: posNum(r.ttl) ?? undefined })
  }
  return out
}

/** Distinct DNS record types, from the records or the flat summary key. */
export function dnsRecordTypes(asset: Pick<Asset, 'metadata'>): string[] {
  const fromRecords = uniq(dnsRecords(asset).map((r) => r.type))
  if (fromRecords.length > 0) return fromRecords
  return uniq(strList(prop(asset, 'dns_record_types')).map((t) => t.toUpperCase()))
}

/**
 * Every IP address the asset is known to resolve to or be served from:
 * `ip_addresses` and the synonyms an older row still holds (the property
 * schema, RFC-042 §6.3.9), and the A/AAAA records.
 */
export function ipAddresses(asset: Pick<Asset, 'metadata'>): string[] {
  const fromDns = dnsRecords(asset)
    .filter((r) => r.type === 'A' || r.type === 'AAAA')
    .map((r) => r.value)
  return uniq([...propertyStrings(meta(asset), IP_ADDRESSES_KEY), ...fromDns])
}

/** CNAME targets: dnsx records and the flat `cname_target`. */
export function cnames(asset: Pick<Asset, 'metadata'>): string[] {
  const fromDns = dnsRecords(asset)
    .filter((r) => r.type === 'CNAME')
    .map((r) => r.value)
  return uniq([...fromDns, ...strList(prop(asset, 'cname_target'))])
}

/** "AS13335" style ASN and its organisation, when recorded. */
export function asnInfo(asset: Pick<Asset, 'metadata'>): { asn?: string; org?: string } {
  const ip = nested(asset, 'ip_address')
  const rawAsn = ip.asn ?? prop(asset, 'asn')
  let asn: string | undefined
  const n = posNum(rawAsn)
  if (n !== null && typeof rawAsn !== 'string') asn = `AS${n}`
  else if (typeof rawAsn === 'string') {
    const s = str(rawAsn)
    asn = s ? (/^\d+$/.test(s) ? `AS${s}` : s) : undefined
  }
  const org = str(ip.asn_org) ?? str(prop(asset, 'asn_org'))
  return { asn, org }
}

export interface OpenPort {
  port: number
  protocol?: string
  service?: string
}

/**
 * Open ports on an IP: naabu/nmap write `ip_address.ports[]`. A port is a
 * service of its own (a `host:port` asset), never a property of the host, so
 * there is no flat key for it. `null` when no port scan recorded anything
 * (not "no open ports").
 */
export function openPorts(asset: Pick<Asset, 'metadata'>): OpenPort[] | null {
  const ip = nested(asset, 'ip_address')
  if (Array.isArray(ip.ports)) {
    const out: OpenPort[] = []
    for (const p of ip.ports) {
      if (!isMap(p)) continue
      const port = posNum(p.port)
      if (port === null) continue
      out.push({ port, protocol: str(p.protocol)?.toLowerCase(), service: str(p.service) })
    }
    return out.sort((a, b) => a.port - b.port)
  }
  return null
}

export function formatPort(p: OpenPort): string {
  return p.protocol ? `${p.port}/${p.protocol}` : String(p.port)
}

// ---------------------------------------------------------------------------
// Domain registration
// ---------------------------------------------------------------------------

export function registrar(asset: Pick<Asset, 'metadata'>): string | undefined {
  return str(nested(asset, 'domain').registrar) ?? str(prop(asset, 'registrar'))
}

export function domainExpiry(asset: Pick<Asset, 'metadata'>): Date | null {
  const raw = str(nested(asset, 'domain').expires_at) ?? str(prop(asset, 'expires_at'))
  if (!raw) return null
  const d = new Date(raw)
  return Number.isNaN(d.getTime()) ? null : d
}

export function nameservers(asset: Pick<Asset, 'metadata'>): string[] {
  const fromDomain = strList(nested(asset, 'domain').nameservers)
  const fromNs = dnsRecords(asset)
    .filter((r) => r.type === 'NS')
    .map((r) => r.value)
  return uniq([...fromDomain, ...fromNs, ...strList(prop(asset, 'nameservers'))])
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

export interface TlsCertificate {
  notAfter: Date | null
  daysLeft: number | null
  status: CertStatus
  issuer?: string
  subject?: string
  sans: string[]
}

/**
 * What we know about TLS on a service, in four honest states:
 *
 * - `cert`: a certificate was recorded (expiry, issuer, SANs);
 * - `tls`: the service is served over TLS but no certificate was collected;
 * - `none`: a probe reached it over plain HTTP ("No TLS");
 * - `not_collected`: nothing recorded either way.
 *
 * `service.tls === false` is deliberately not read as "no TLS": the sensor
 * fills it from an httpx field that is absent unless `-tls-grab` runs, so a
 * false there means "unknown". The scheme is what the probe actually used.
 */
export type TlsFacts =
  | { kind: 'cert'; cert: TlsCertificate }
  | { kind: 'tls' }
  | { kind: 'none' }
  | { kind: 'not_collected' }

function dateOf(v: unknown): Date | null {
  const s = str(v)
  if (!s) return null
  const d = new Date(s)
  return Number.isNaN(d.getTime()) ? null : d
}

function certFrom(
  notAfterRaw: unknown,
  issuer: string | undefined,
  subject: string | undefined,
  sans: string[],
  expiredFlag: unknown,
  now: number
): TlsCertificate | null {
  const notAfter = dateOf(notAfterRaw)
  if (!notAfter && !issuer && sans.length === 0 && !subject) return null
  const daysLeft = notAfter ? Math.ceil((notAfter.getTime() - now) / (24 * 60 * 60 * 1000)) : null
  let status: CertStatus
  if (daysLeft === null) status = expiredFlag === true ? 'expired' : 'unknown'
  else if (daysLeft < 0) status = 'expired'
  else if (daysLeft <= CERT_EXPIRING_DAYS) status = 'expiring'
  else status = 'valid'
  return { notAfter, daysLeft, status, issuer, subject, sans }
}

/** The certificate recorded on the asset itself: its flat schema keys, or a CTIS block. */
export function recordedCertificate(
  asset: Pick<Asset, 'metadata'>,
  now: number = Date.now()
): TlsCertificate | null {
  const c = nested(asset, 'certificate')
  const svc = nested(asset, 'service')
  const candidates: (TlsCertificate | null)[] = [
    // A certificate asset's own keys (CT monitor, CTIS flat properties, the form).
    certFrom(
      prop(asset, 'not_after'),
      str(prop(asset, 'issuer_org')) ?? str(prop(asset, 'issuer_cn')),
      str(prop(asset, 'subject_cn')),
      strList(prop(asset, 'sans')),
      prop(asset, 'is_expired'),
      now
    ),
    // The CTIS technical certificate block (ingest).
    certFrom(
      c.not_after,
      str(c.issuer_org) ?? str(c.issuer_cn),
      str(c.subject_cn),
      strList(c.sans),
      c.expired,
      now
    ),
    // nmap-style service TLS fields (the CTIS technical service block).
    certFrom(
      svc.tls_cert_expiry,
      str(svc.tls_cert_issuer),
      str(svc.tls_cert_subject),
      [],
      undefined,
      now
    ),
  ]
  return candidates.find((x) => x !== null) ?? null
}

export function tlsFacts(asset: Pick<Asset, 'metadata'>, now: number = Date.now()): TlsFacts {
  const cert = recordedCertificate(asset, now)
  if (cert) return { kind: 'cert', cert }

  const svc = nested(asset, 'service')
  const scheme = str(svc.protocol)?.toLowerCase()
  const hasTls = prop(asset, 'has_tls')

  // The scheme the probe used, or the recorded `has_tls` flag. The asset's own
  // URL is not read: a typed-in "https://" is a claim, not an observation.
  if (scheme === 'https' || svc.tls === true || hasTls === true) return { kind: 'tls' }
  if (scheme === 'http' || hasTls === false) return { kind: 'none' }
  return { kind: 'not_collected' }
}
