/**
 * Attack surface > Certificates: request URLs, status vocabulary and the CSV
 * of the certificate list. Pure, so the filters a page sends and the file it
 * exports are tested without a network. Every value is scan output.
 */
import { buildCsv } from '@/hooks/use-csv-export'
import type { PillTone } from '@/features/shared'

export const CERTIFICATES_URL = '/api/v1/attack-surface/certificates'

export const CERTIFICATE_STATUSES = ['expired', 'expiring_soon', 'ok', 'unknown'] as const
export type CertificateStatus = (typeof CERTIFICATE_STATUSES)[number]

export function isCertificateStatus(v: string): v is CertificateStatus {
  return (CERTIFICATE_STATUSES as readonly string[]).includes(v)
}

/** One row of GET /attack-surface/certificates. */
export interface CertificateRow {
  asset_id: string
  name: string
  subject_cn: string
  issuer_cn: string
  issuer_org: string
  fingerprint_sha256: string
  signature_algorithm?: string
  not_before?: string
  not_after?: string
  status: CertificateStatus
  days_to_expiry?: number
  is_self_signed: boolean
  is_wildcard: boolean
  first_seen: string
  last_seen: string
}

/** GET /attack-surface/certificates/stats. */
export interface CertificateStats {
  total: number
  expired: number
  expiring_soon: number
  ok: number
  unknown: number
}

export interface CertificateFilters {
  q?: string
  status?: CertificateStatus
}

/** The tone each status renders in: red, amber, green, and muted for unknown. */
export const STATUS_TONE: Record<CertificateStatus, PillTone> = {
  expired: 'destructive',
  expiring_soon: 'warning',
  ok: 'success',
  unknown: 'muted',
}

export const STATUS_LABEL: Record<CertificateStatus, string> = {
  expired: 'Expired',
  expiring_soon: 'Expiring soon',
  ok: 'Valid',
  unknown: 'Unknown',
}

export function certificateFilterParams(f: CertificateFilters): URLSearchParams {
  const p = new URLSearchParams()
  const q = f.q?.trim()
  if (q) p.set('q', q)
  if (f.status) p.set('status', f.status)
  return p
}

export function certificatesUrl(
  f: CertificateFilters,
  page: { page: number; perPage: number }
): string {
  const p = certificateFilterParams(f)
  p.set('page', String(page.page))
  p.set('per_page', String(page.perPage))
  return `${CERTIFICATES_URL}?${p.toString()}`
}

export function certificateStatsUrl(f: CertificateFilters): string {
  const p = certificateFilterParams(f).toString()
  return p ? `${CERTIFICATES_URL}/stats?${p}` : `${CERTIFICATES_URL}/stats`
}

/** CSV of certificate rows; cells go through buildCsv (formula injection safe). */
export function certificatesCsv(
  rows: CertificateRow[],
  headers: [string, string, string, string, string, string, string, string, string],
  statusLabel: (s: CertificateStatus) => string
): string {
  return buildCsv(
    headers,
    rows.map((c) => [
      c.subject_cn || c.name,
      c.fingerprint_sha256,
      c.issuer_cn,
      c.issuer_org,
      c.not_before,
      c.not_after,
      statusLabel(c.status),
      c.first_seen,
      c.last_seen,
    ])
  )
}
