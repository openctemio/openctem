import type { Asset } from '../types'
import { propertyValue, type AssetPropertyKey } from '@/features/asset-types/lib/property-schema'

/**
 * Read certificate facts from a certificate asset's properties. HTTP status,
 * TLS on a service and the other web-service facts live in service-facts.ts.
 *
 * Two shapes exist and both are read:
 *  - the flat schema keys of a certificate (api/configs/asset-types.yaml:
 *    `not_after`, `issuer_org`, `issuer_cn`, `subject_cn`, `sans`,
 *    `fingerprint_sha256`, `is_self_signed`, …), named through the
 *    registry's `AssetPropertyKey` so a key outside the schema does not
 *    compile;
 *  - the CTIS technical `certificate` block ingest stores
 *    (api internal/app/ingest/mappers.go buildCertificateProperties), whose
 *    field names are the CTIS ones (`fingerprint`, `self_signed`, `expired`).
 *
 * A fact the asset does not carry is UNKNOWN. It is never shown as "valid",
 * "200" or "insecure" (RFC-036 E8): that made scanned certificates look
 * healthy and every website look up.
 */

export type CertStatus = 'valid' | 'expiring' | 'expired' | 'unknown'

/** Certificates expiring within this many days are "expiring". */
export const CERT_EXPIRING_DAYS = 30

function prop(asset: Asset, key: AssetPropertyKey): unknown {
  return propertyValue(asset.metadata, key)
}

function block(asset: Asset): Record<string, unknown> {
  const c = prop(asset, 'certificate')
  return c && typeof c === 'object' && !Array.isArray(c) ? (c as Record<string, unknown>) : {}
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v : undefined
}

function dateOf(raw: string | undefined): Date | null {
  if (!raw) return null
  const d = new Date(raw)
  return Number.isNaN(d.getTime()) ? null : d
}

/** The certificate's not-after date, or null when absent or unparseable. */
export function certNotAfter(asset: Asset): Date | null {
  return dateOf(str(prop(asset, 'not_after')) ?? str(block(asset).not_after))
}

export function certNotBefore(asset: Asset): Date | null {
  return dateOf(str(prop(asset, 'not_before')) ?? str(block(asset).not_before))
}

export function certIssuer(asset: Asset): string | undefined {
  const c = block(asset)
  return (
    str(prop(asset, 'issuer_org')) ??
    str(prop(asset, 'issuer_cn')) ??
    str(c.issuer_org) ??
    str(c.issuer_cn)
  )
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
    return prop(asset, 'is_expired') === true || block(asset).expired === true
      ? 'expired'
      : 'unknown'
  }
  if (days < 0) return 'expired'
  if (days <= CERT_EXPIRING_DAYS) return 'expiring'
  return 'valid'
}

/** The certificate's subject CN. */
export function certSubject(asset: Asset): string | undefined {
  return str(prop(asset, 'subject_cn')) ?? str(block(asset).subject_cn)
}

/** Subject alternative names. */
export function certSans(asset: Asset): string[] {
  const raw = prop(asset, 'sans') ?? block(asset).sans
  if (Array.isArray(raw)) return raw.map((v) => String(v).trim()).filter(Boolean)
  if (typeof raw === 'string')
    return raw
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
  return []
}

export function certSerial(asset: Asset): string | undefined {
  return str(prop(asset, 'serial_number')) ?? str(block(asset).serial_number)
}

export function certSignatureAlgorithm(asset: Asset): string | undefined {
  return str(prop(asset, 'signature_algorithm')) ?? str(block(asset).signature_algorithm)
}

/** Key size in bits, or null when not recorded. */
export function certKeySize(asset: Asset): number | null {
  const raw = prop(asset, 'key_size') ?? block(asset).key_size
  const n = typeof raw === 'string' ? parseInt(raw, 10) : raw
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : null
}

export function certKeyAlgorithm(asset: Asset): string | undefined {
  return str(prop(asset, 'key_algorithm')) ?? str(block(asset).key_algorithm)
}

export function certFingerprint(asset: Asset): string | undefined {
  return str(prop(asset, 'fingerprint_sha256')) ?? str(block(asset).fingerprint)
}

/** Whether the certificate is self-signed, or null when not recorded. */
export function certSelfSigned(asset: Asset): boolean | null {
  const v = prop(asset, 'is_self_signed') ?? block(asset).self_signed
  return typeof v === 'boolean' ? v : null
}

/**
 * Whether the certificate covers a wildcard name: the recorded flag, else
 * read from the subject and SANs. Null when neither is known.
 */
export function certIsWildcard(asset: Asset): boolean | null {
  const flag = prop(asset, 'is_wildcard')
  if (typeof flag === 'boolean') return flag
  const names = [certSubject(asset), ...certSans(asset)].filter(Boolean) as string[]
  if (names.length === 0) return null
  return names.some((n) => n.startsWith('*.'))
}
