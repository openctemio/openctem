/**
 * Stop using an import source (api docs/architecture/source-retirement.md):
 * preview, retire, list and use again. The preview and the retirement run
 * the same query on the server; the dialog shows what the server counted.
 * Every route needs findings:sources:retire and full data access; retire and
 * restore ask for re-authentication (the API client shows the prompt).
 */

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { useCurrentTenantId } from '@/context/tenant-provider'

const BASE = '/api/v1/findings/sources/retirements'

/** How a source is named: its kind and keys, or a connector integration. */
export interface SourceSelector {
  kind?: 'sensor_tool' | 'upload' | 'connector'
  sensor_id?: string
  sender?: string
  tool?: string
  integration_id?: string
}

export type RetireMode = 'archive' | 'keep_open'

export interface RetireOptions {
  mode?: RetireMode
  /** Severities to archive; empty means every severity. */
  severities?: string[]
  include_engaged?: boolean
}

export interface RetirePreview {
  total: number
  archive: number
  archive_by_severity: Record<string, number>
  critical_or_kev: number
  with_sla: number
  corroborated: number
  kept_engaged: number
  kept_in_progress: number
  kept_secret: number
  kept_severity_skipped: number
  already_closed: number
}

export type RetirementState = 'applying' | 'active' | 'restoring' | 'restored'

export interface SourceRetirement {
  id: string
  kind: 'sensor_tool' | 'upload' | 'connector'
  sensor_id?: string
  sender?: string
  tool?: string
  integration_id?: string
  label: string
  mode: RetireMode
  severities: string[]
  include_engaged: boolean
  state: RetirementState
  reason: string
  planned_count: number
  archived_count: number
  restored_count: number
  changed_count: number
  retired_by?: string
  retired_at: string
  restored_by?: string
  restore_reason?: string
  restored_at?: string
  already_retired?: boolean
}

export interface RetirePreviewResponse {
  label: string
  preview: RetirePreview
}

export interface RetireResponse {
  retirement: SourceRetirement
  preview: RetirePreview
}

const swrConfig = { revalidateOnFocus: false, shouldRetryOnError: false }

/** A stable key for a source and options (SWR key of the preview). */
function previewKey(source: SourceSelector, options: RetireOptions): string {
  return JSON.stringify({ source, options })
}

/** The server's preview for a source and options; null source = no request. */
export function useRetirePreview(source: SourceSelector | null, options: RetireOptions) {
  const tenantId = useCurrentTenantId()
  const key = tenantId && source ? [`${BASE}/preview`, previewKey(source, options)] : null
  return useSWR<RetirePreviewResponse>(
    key,
    () => post<RetirePreviewResponse>(`${BASE}/preview`, { source, options }),
    swrConfig
  )
}

/** Stop using the source. 409 CONFIRM_CRITICAL_REQUIRED without the confirmation. */
export function retireSource(input: {
  source: SourceSelector
  options: RetireOptions
  reason: string
  confirm_critical: boolean
}): Promise<RetireResponse> {
  return post<RetireResponse>(BASE, input)
}

/** Use the source again: its archived findings are restored. */
export function restoreSource(id: string, reason: string): Promise<SourceRetirement> {
  return post<SourceRetirement>(`${BASE}/${encodeURIComponent(id)}/restore`, { reason })
}

/** True while batches remain (the progress moves). */
export function isRetirementRunning(r?: Pick<SourceRetirement, 'state'>): boolean {
  return r?.state === 'applying' || r?.state === 'restoring'
}

/** The retired sources; refreshes while one is still running. */
export function useSourceRetirements(enabled: boolean, includeRestored = false) {
  const tenantId = useCurrentTenantId()
  const key = tenantId && enabled ? `${BASE}?include_restored=${includeRestored}` : null
  return useSWR<{ items: SourceRetirement[] }>(
    key,
    (url: string) => get<{ items: SourceRetirement[] }>(url),
    {
      ...swrConfig,
      refreshInterval: (data) => (data?.items.some(isRetirementRunning) ? 2000 : 0),
    }
  )
}

/** One retirement; refreshes while it runs (the dialog's progress). */
export function useSourceRetirement(id: string | undefined) {
  const tenantId = useCurrentTenantId()
  const key = tenantId && id ? `${BASE}/${encodeURIComponent(id)}` : null
  return useSWR<SourceRetirement>(key, (url: string) => get<SourceRetirement>(url), {
    ...swrConfig,
    refreshInterval: (data) => (isRetirementRunning(data) ? 1500 : 0),
  })
}

/** The source of a finding sighting, when it can be retired from the finding page. */
export function sightingSource(s: {
  channel?: string
  sensor?: { id?: string }
  sender?: string
  tool?: string
}): SourceSelector | null {
  const tool = s.tool?.trim()
  switch (s.channel) {
    case 'scan':
    case 'task':
    case 'sensor':
      return s.sensor?.id && tool ? { kind: 'sensor_tool', sensor_id: s.sensor.id, tool } : null
    case 'upload':
      return tool ? { kind: 'upload', tool } : null
    case 'connector':
      return s.sender && s.sender !== 'platform' ? { kind: 'connector', sender: s.sender } : null
    default:
      return null
  }
}
