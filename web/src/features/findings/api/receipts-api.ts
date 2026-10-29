/**
 * Receipts of uploads and sensor runs (RFC-122): what each one did to the
 * organization's findings. GET /api/v1/findings/imports (list),
 * /findings/imports/{id} and /findings/{id}/imports (the receipts that acted
 * on one finding). A caller without the organization view sees only the
 * uploads they made; the API decides, the UI only shows what it gets.
 */

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useCurrentTenantId } from '@/context/tenant-provider'
import type { components } from '@/lib/api/generated'

type S = components['schemas']
export type ReceiptResponse = S['internal_infra_http_handler.ReceiptResponse']
export type ReceiptCounts = S['internal_infra_http_handler.ReceiptCounts']
export type FindingReceipt = S['internal_infra_http_handler.FindingReceiptResponse']
export type FindingReceiptsResponse = S['internal_infra_http_handler.FindingReceiptsResponse']

/** Sums over every receipt the filter keeps (not only the page). */
export interface ReceiptTotals {
  receipts: number
  received: number
  created: number
  updated: number
  reactivated: number
  closed: number
  skipped: number
  failed: number
  suppressed: number
}

export interface ReceiptListResponse {
  data?: ReceiptResponse[]
  total?: number
  page?: number
  per_page?: number
  total_pages?: number
  totals?: ReceiptTotals
}

/** The source groups the dashboards count by (a receipt kind's group). */
export const RECEIPT_ORIGINS = ['sensor', 'import', 'connector', 'ci'] as const
export type ReceiptOrigin = (typeof RECEIPT_ORIGINS)[number]

export function isReceiptOrigin(v: unknown): v is ReceiptOrigin {
  return typeof v === 'string' && (RECEIPT_ORIGINS as readonly string[]).includes(v)
}

export type ReceiptSourceKind =
  'upload' | 'scan_run' | 'command' | 'ci_run' | 'connector' | 'sensor'

export interface ReceiptListFilters {
  sourceKind?: ReceiptSourceKind
  sourceRef?: string
  /** Source group (the dashboards' grouping). */
  origin?: ReceiptOrigin
  /** Tool name; "unknown" keeps the receipts that named none. */
  tool?: string
  /** RFC 3339: receipts with activity at or after it. */
  since?: string
  page?: number
  perPage?: number
}

export function receiptListUrl(f: ReceiptListFilters = {}): string {
  const q = new URLSearchParams()
  if (f.sourceKind) q.set('source_kind', f.sourceKind)
  if (f.sourceRef) q.set('source_ref', f.sourceRef)
  if (f.origin) q.set('origin', f.origin)
  if (f.tool) q.set('tool', f.tool)
  if (f.since) q.set('since', f.since)
  if (f.page && f.page > 1) q.set('page', String(f.page))
  if (f.perPage) q.set('per_page', String(f.perPage))
  const qs = q.toString()
  return `/api/v1/findings/imports${qs ? `?${qs}` : ''}`
}

export function findingReceiptsUrl(findingId: string): string {
  return `/api/v1/findings/${encodeURIComponent(findingId)}/imports`
}

const swrConfig = { revalidateOnFocus: false, shouldRetryOnError: false }

/**
 * Lists receipts; pass enabled=false to skip the request, and refreshMs to
 * poll while the thing they describe (a running scan) is still reporting.
 */
export function useReceipts(filters: ReceiptListFilters, enabled = true, refreshMs = 0) {
  const tenantId = useCurrentTenantId()
  const key = tenantId && enabled ? receiptListUrl(filters) : null
  return useSWR<ReceiptListResponse>(key, (url: string) => get<ReceiptListResponse>(url), {
    ...swrConfig,
    refreshInterval: refreshMs,
  })
}

/** The receipts that acted on one finding, newest first. */
export function useFindingReceipts(findingId: string | undefined) {
  const tenantId = useCurrentTenantId()
  const key = tenantId && findingId ? findingReceiptsUrl(findingId) : null
  return useSWR<FindingReceiptsResponse>(
    key,
    (url: string) => get<FindingReceiptsResponse>(url),
    swrConfig
  )
}
