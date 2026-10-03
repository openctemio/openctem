import type { Asset } from '../types'

/**
 * Read certificate and website facts from an asset's properties.
 *
 * Two shapes exist and both must be read:
 *  - the manual form writes flat keys (`cert_not_after`, `cert_issuer`,
 *    `http_status`, `ssl`);
 *  - ingest (scanners, CTIS) writes a nested `certificate` map with
 *    `not_after`, `issuer_cn`/`issuer_org`, `expired` (api
 *    internal/app/ingest/mappers.go buildCertificateProperties).
 *
 * A fact the asset does not carry is UNKNOWN. It is never shown as "valid",
 * "200" or "insecure" (RFC-036 E8): that made scanned certificates look
 * healthy and every website look up.
 */

export type CertStatus = 'valid' | 'expiring' | 'expired' | 'unknown'

/** Certificates expiring within this many days are "expiring". */
export const CERT_EXPIRING_DAYS = 30

function nested(asset: Asset): Record<string, unknown> {
  const c = asset.metadata?.certificate
  return c && typeof c === 'object' && !Array.isArray(c) ? (c as Record<string, unknown>) : {}
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v : undefined
}

/** The certificate's not-after date, or null when absent or unparseable. */
export function certNotAfter(asset: Asset): Date | null {
  const raw = str(asset.metadata?.cert_not_after) ?? str(nested(asset).not_after)
  if (!raw) return null
  const d = new Date(raw)
  return Number.isNaN(d.getTime()) ? null : d
}

export function certNotBefore(asset: Asset): Date | null {
  const raw = str(asset.metadata?.cert_not_before) ?? str(nested(asset).not_before)
  if (!raw) return null
  const d = new Date(raw)
  return Number.isNaN(d.getTime()) ? null : d
}

export function certIssuer(asset: Asset): string | undefined {
  const c = nested(asset)
  return str(asset.metadata?.cert_issuer) ?? str(c.issuer_org) ?? str(c.issuer_cn)
}

/** Whole days until expiry (negative once expired), or null when unknown. */
export function certDaysLeft(asset: Asset, now: number = Date.now()): number | null {
  const na = certNotAfter(asset)
  if (!na) return null
  return Math.ceil((na.getTime() - now) / (1000 * 60 * 60 * 24))
}

export function certStatus(asset: Asset, now: number = Date.now()): CertStatus {
  const days = certDaysLeft(asset, now)
  if (days === null) {
    // No date, but the scanner may still have said it is expired.
    return nested(asset).expired === true ? 'expired' : 'unknown'
  }
  if (days < 0) return 'expired'
  if (days <= CERT_EXPIRING_DAYS) return 'expiring'
  return 'valid'
}

/** The website's last HTTP status, or null when no probe recorded one. */
export function httpStatus(asset: Asset): number | null {
  const raw = asset.metadata?.http_status ?? asset.metadata?.status_code
  const n = typeof raw === 'string' ? parseInt(raw, 10) : raw
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : null
}

/**
 * Whether the site is served over TLS: true / false as recorded, or null when
 * nothing recorded it. The URL scheme is deliberately not used: the page's
 * "SSL secure / insecure" counts come from the recorded `ssl` key, and the
 * rows must agree with them.
 */
export function websiteTLS(asset: Asset): boolean | null {
  const m = asset.metadata ?? {}
  if (typeof m.ssl === 'boolean') return m.ssl
  if (typeof m.tls === 'boolean') return m.tls
  return null
}
