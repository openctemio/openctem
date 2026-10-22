/**
 * Widget results (api docs/architecture/dashboards.md, "Widget data").
 *
 * GET /me/dashboards/{id}/data computes every widget of the caller's own
 * dashboard for the caller's data scope; GET /organization/dashboards/{id}/data
 * computes an organization dashboard for the whole organization (needs
 * dashboards:org:view and the audience). POST /me/dashboards/widget-preview
 * computes one spec for the caller's own scope. The server decides whose
 * numbers they are; nothing here can widen that.
 */

'use client'

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { DashboardKind } from './dashboards.types'
import type { Polarity, ResultShape, VizType } from './widget-spec'

export type WidgetState = 'ready' | 'not_measured' | 'building' | 'unsupported' | 'error'

export interface WidgetPoint {
  t: string
  v: number
}

export interface WidgetValue {
  id: string
  index: number
  widget_type: string
  state: WidgetState
  /** Machine code: no_denominator, too_few_fixed, legacy_tile, facts_building, failed, timeout. */
  reason?: string
  metric?: string
  shape?: ResultShape
  viz?: VizType
  polarity?: Polarity
  target?: { op: '<=' | '>='; value: number }
  target_met?: boolean
  /** The findings list counted with the same filter; absent when the list cannot express it. */
  drill?: string
  window?: {
    from: string
    to: string
    previous_from?: string
    previous_to?: string
    bucket: string
    days: number
  }
  previous_reason?: string
  scalar?: { value: number; previous?: number; delta?: number; series?: WidgetPoint[] }
  ratio?: { num: number; den: number; value_pct: number | null }
  duration?: {
    median_hours: number | null
    p90_hours: number | null
    n: number
    previous_median_hours?: number
    previous_n?: number
    bucketed: boolean
  }
  category?: {
    rows: Array<{
      key: string
      value: number
      previous?: number
      p90?: number
      n?: number
      drill?: string
    }>
    total: number
  }
  series?: {
    bucket: string
    series: Array<{ key: string; points: WidgetPoint[] }>
    totals?: Record<string, number>
    previous_totals?: Record<string, number>
  }
  matrix?: { rows: string[]; cols: string[]; cells: number[][] }
  items?: {
    rows: Array<{
      id: string
      title: string
      severity: string
      priority_class: string
      asset_id?: string
      asset_name?: string
      sla_deadline?: string
      kev: boolean
    }>
  }
}

export interface DashboardData {
  dashboard_id: string
  scope: 'organization' | 'personal'
  /** A personal read narrower than the organization ("Your scope"). */
  restricted: boolean
  /** Null while the organization's first fact build runs. */
  facts_built_at: string | null
  /** When these figures were computed (the stored snapshot's time). */
  computed_at: string
  /** The effective schedule (organization default resolved). */
  refresh_schedule?: 'manual' | '5m' | '15m' | '1h' | '6h' | 'daily'
  /** Absent for a manual or paused schedule. */
  next_refresh_at?: string
  /** Older than twice the schedule, or the last refresh failed: the last good figures. */
  stale: boolean
  last_refresh_error?: string
  widgets: WidgetValue[]
}

export function dashboardDataKey(kind: DashboardKind, id: string): string {
  return kind === 'organization'
    ? `/api/v1/organization/dashboards/${id}/data`
    : `/api/v1/me/dashboards/${id}/data`
}

export function dashboardRefreshPath(kind: DashboardKind, id: string): string {
  return kind === 'organization'
    ? `/api/v1/organization/dashboards/${id}/refresh`
    : `/api/v1/me/dashboards/${id}/refresh`
}

/**
 * Refresh now: recomputes and stores the snapshot. Budgeted on the server
 * (once a minute per person and dashboard, 30 an hour per organization);
 * a 429 carries Retry-After.
 */
export function refreshDashboard(kind: DashboardKind, id: string) {
  return post<DashboardData>(dashboardRefreshPath(kind, id), {})
}

/** Every widget result of one dashboard (the stored snapshot). */
export function useDashboardData(kind: DashboardKind, id: string | null) {
  const { currentTenant } = useTenant()
  return useSWR<DashboardData>(
    currentTenant && id ? dashboardDataKey(kind, id) : null,
    (url: string) => get<DashboardData>(url),
    { revalidateOnFocus: false }
  )
}

/** One typed widget computed for the caller's own scope (gallery, config panel). */
export function previewWidget(widgetType: 'metric' | 'note', config: Record<string, unknown>) {
  return post<WidgetValue>('/api/v1/me/dashboards/widget-preview', {
    widget_type: widgetType,
    config,
  })
}
