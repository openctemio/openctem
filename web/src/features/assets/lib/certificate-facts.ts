import type { Asset } from '../types'

/**
 * Read certificate facts from a certificate asset's properties. HTTP status,
 * TLS on a service and the other web-service facts live in service-facts.ts.
 *
 * Two shapes exist and both must be read:
 *  - the manual form writes flat keys (`cert_not_after`, `cert_issuer`,
 *    `cert_subject`, `cert_sans`, …);
 *  - ingest (scanners, CTIS) writes a nested `certificate` map with
 *    `not_after`, `issuer_cn`/`issuer_org`, `subject_cn`, `sans`, `expired`
 *    (api internal/app/ingest/mappers.go buildCertificateProperties).
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

/** The certificate's subject: the form key, else the ingest CN. */
export function certSubject(asset: Asset): string | undefined {
  return str(asset.metadata?.cert_subject) ?? str(nested(asset).subject_cn)
}

/** Subject alternative names, from the form key or the ingest map. */
export function certSans(asset: Asset): string[] {
  const raw = asset.metadata?.cert_sans ?? nested(asset).sans
  if (Array.isArray(raw)) return raw.map((v) => String(v).trim()).filter(Boolean)
  if (typeof raw === 'string')
    return raw
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
  return []
}

export function certSerial(asset: Asset): string | undefined {
  return str(asset.metadata?.cert_serial_number) ?? str(nested(asset).serial_number)
}

export function certSignatureAlgorithm(asset: Asset): string | undefined {
  return str(asset.metadata?.cert_signature_algorithm) ?? str(nested(asset).signature_algorithm)
}

/** Key size in bits, or null when not recorded. */
export function certKeySize(asset: Asset): number | null {
  const raw = asset.metadata?.cert_key_size ?? nested(asset).key_size
  const n = typeof raw === 'string' ? parseInt(raw, 10) : raw
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : null
}

export function certKeyAlgorithm(asset: Asset): string | undefined {
  return str(nested(asset).key_algorithm)
}

export function certFingerprint(asset: Asset): string | undefined {
  return str(nested(asset).fingerprint)
}

/** Whether the certificate is self-signed, or null when not recorded. */
export function certSelfSigned(asset: Asset): boolean | null {
  const v = nested(asset).self_signed
  return typeof v === 'boolean' ? v : null
}

/**
 * Whether the certificate covers a wildcard name: the recorded flag, else
 * read from the subject and SANs. Null when neither is known.
 */
export function certIsWildcard(asset: Asset): boolean | null {
  const flag = asset.metadata?.cert_is_wildcard
  if (typeof flag === 'boolean') return flag
  const names = [certSubject(asset), ...certSans(asset)].filter(Boolean) as string[]
  if (names.length === 0) return null
  return names.some((n) => n.startsWith('*.'))
}
