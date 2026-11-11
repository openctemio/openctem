/**
 * Compliance check reads (api docs/architecture/compliance-checks.md,
 * "Reads"): the pass rate per benchmark, a benchmark's controls, a control's
 * assets and the history of the control a finding fails. Every read runs in
 * the caller's data scope on the server; an asset outside it reads as none.
 */

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useCurrentTenantId } from '@/context/tenant-provider'

export type ComplianceResult = 'pass' | 'fail' | 'manual' | 'not_applicable' | 'error'

export interface ComplianceCounts {
  pass: number
  fail: number
  manual: number
  not_applicable: number
  error: number
  /** Failures whose finding is accepted or a false positive (counted in fail too). */
  excepted: number
  /** pass + fail: the denominator of the pass rate. */
  applicable: number
}

export interface ComplianceBenchmark {
  key: string
  name: string
  version?: string
  framework?: string
  assets: number
  failing_assets: number
  counts: ComplianceCounts
  /** pass / (pass + fail) in [0, 1]; null when nothing applies. */
  pass_rate: number | null
  last_checked_at: string
}

export interface ComplianceControl {
  control_id: string
  control_name?: string
  level?: number
  counts: ComplianceCounts
  pass_rate: number | null
  last_checked_at: string
}

export interface ComplianceEvidence {
  actual?: string
  expected?: string
  message?: string
  audit_file?: string
}

export interface ComplianceControlAsset {
  asset_id: string
  asset_name: string
  asset_type: string
  result: ComplianceResult
  benchmark_version?: string
  evidence: ComplianceEvidence
  scanner_severity?: string
  finding_id?: string
  finding_status?: string
  last_checked_at: string
  last_changed_at: string
}

export interface ComplianceHistoryEntry {
  result: ComplianceResult
  previous_result?: ComplianceResult
  evidence: ComplianceEvidence
  benchmark_version?: string
  tool_name?: string
  source: 'ingest' | 'backfill'
  observed_at: string
  recorded_at: string
}

export interface ComplianceHistory {
  control: {
    benchmark_key: string
    benchmark_name: string
    control_id: string
    control_name?: string
    level?: number
    result: ComplianceResult
    last_checked_at: string
  } | null
  data: ComplianceHistoryEntry[]
}

interface Page<T> {
  data: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

const BASE = '/api/v1/findings/compliance/benchmarks'
const swrConfig = { revalidateOnFocus: false, shouldRetryOnError: false, keepPreviousData: true }

export function complianceBenchmarksUrl(assetId?: string): string {
  return assetId ? `${BASE}?asset_id=${encodeURIComponent(assetId)}` : BASE
}

export function complianceControlsUrl(
  key: string,
  opts: { failedOnly?: boolean; q?: string; page?: number; perPage?: number } = {}
): string {
  const p = new URLSearchParams()
  if (opts.failedOnly) p.set('result', 'fail,manual')
  if (opts.q?.trim()) p.set('q', opts.q.trim())
  if (opts.page && opts.page > 1) p.set('page', String(opts.page))
  if (opts.perPage) p.set('per_page', String(opts.perPage))
  const qs = p.toString()
  return `${BASE}/${encodeURIComponent(key)}/controls${qs ? `?${qs}` : ''}`
}

export function complianceControlAssetsUrl(key: string, control: string): string {
  return `${BASE}/${encodeURIComponent(key)}/assets?control=${encodeURIComponent(control)}&per_page=100`
}

export function findingComplianceHistoryUrl(findingId: string): string {
  return `/api/v1/findings/${encodeURIComponent(findingId)}/compliance-history`
}

function useScoped<T>(url: string | null) {
  const tenantId = useCurrentTenantId()
  return useSWR<T>(tenantId && url ? url : null, (u: string) => get<T>(u), swrConfig)
}

/** The pass rate of each benchmark over the caller's assets. */
export function useComplianceBenchmarks(enabled = true) {
  return useScoped<{ data: ComplianceBenchmark[] }>(enabled ? complianceBenchmarksUrl() : null)
}

/** A benchmark's controls, failed first. */
export function useComplianceControls(
  key: string | undefined,
  opts: { failedOnly?: boolean; q?: string; page?: number } = {}
) {
  return useScoped<Page<ComplianceControl>>(
    key ? complianceControlsUrl(key, { ...opts, perPage: 50 }) : null
  )
}

/** One control's state on each of the caller's assets, failed first. */
export function useComplianceControlAssets(key: string | undefined, control: string | undefined) {
  return useScoped<Page<ComplianceControlAsset>>(
    key && control ? complianceControlAssetsUrl(key, control) : null
  )
}

/** The history of the control a compliance finding fails. */
export function useFindingComplianceHistory(findingId: string | undefined) {
  return useScoped<ComplianceHistory>(findingId ? findingComplianceHistoryUrl(findingId) : null)
}
