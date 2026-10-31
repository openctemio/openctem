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

/** One figure and the list it counts (a priority class, a severity, an outcome). */
export interface FlowFigure {
  key?: string
  value: number
  drill?: string
}

/** What one source (a source group and a tool) sent in the window, and its health. */
export interface IntakeSource {
  origin: 'sensor' | 'import' | 'connector' | 'ci' | ''
  tool: string
  receipts: number
  received: number
  created: number
  still_detected: number
  reopened: number
  closed: number
  suppressed: number
  /** Skipped (out of scope, excluded, invalid) or failed. */
  not_stored: number
  last_at: string
  last_status: string
  last_receipt_id: string
  health: 'ok' | 'stale' | 'failed'
  /** The usual interval between receipts; absent with fewer than three. */
  expected_every_seconds?: number
  /** The receipt list of this source in the window (its totals are these figures). */
  drill: string
}

/** The organization's intake in the window (ingest.intake, and the exposure flow's sources). */
export interface IntakeValue {
  since: string
  sources: IntakeSource[]
  totals: IntakeSource
  /** Received split into parts that sum to it. */
  noise: { received: number; new: number; merged: number; suppressed: number; not_stored: number }
  failing: number
  stale: number
  drill: string
  false_positive: FlowFigure
}

/** The exposure flow (exposure.flow). */
export interface FlowValue {
  since: string
  /** Absent for a read with a data scope (intake_reason organization_only). */
  intake?: IntakeValue
  intake_reason?: 'organization_only' | 'no_receipts'
  actionable: FlowFigure
  classes: FlowFigure[]
  open: FlowFigure
  severity: FlowFigure[]
  past_sla: FlowFigure
  in_progress: FlowFigure
  fixed: FlowFigure
  accepted: FlowFigure
  false_positive: FlowFigure
  stages: NonNullable<WidgetValue['stages']> | null
}

/** A measured figure before and after a lever's list is gone (exact arithmetic). */
export interface LeverEffect {
  metric: string
  before: number
  after: number
  unit: 'count' | 'percent'
}

/** One action that would reduce exposure (exposure.levers). */
export interface LeverValue {
  kind: 'kev_open' | 'sla_breached' | 'one_fix' | 'blind_spot'
  /** Size of the list the lever acts on. */
  count: number
  /** Distinct assets of a one-fix lever. */
  assets?: number
  /** A one-fix lever's fix (a remediation suggestion title). */
  title?: string
  points: number
  effect: LeverEffect
  drill?: string
}

/** One figure of a brief sentence; no drill when no list has exactly that total. */
export interface BriefChipValue {
  key: string
  value: number
  drill?: string
}

/** The weekly brief (brief.weekly): deterministic sentences, no generated text. */
export interface BriefValue {
  since: string
  items: Array<{
    kind: 'change' | 'lever' | 'sla_due' | 'kev' | 'quiet'
    variant?: 'down' | 'up' | 'flat'
    chips: BriefChipValue[]
    lever?: LeverValue
  }>
}

/** One tile of the KPI strip (exposure.kpis); value is null when not measured. */
export interface KpiTileValue {
  key: 'priority_open' | 'kev_open' | 'sla_within' | 'time_to_fix' | 'coverage'
  metric: string
  state: 'ready' | 'not_measured' | 'unsupported'
  reason?: string
  value: number | null
  unit: 'count' | 'percent' | 'hours'
  previous?: number
  polarity: Polarity
  n?: number
  series?: WidgetPoint[]
  drill?: string
}

export interface WidgetValue {
  id: string
  index: number
  widget_type: string
  state: WidgetState
  /** Machine code: no_denominator, too_few_fixed, legacy_tile, forbidden, facts_building, failed, timeout. */
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
  scalar?: {
    value: number
    previous?: number
    delta?: number
    series?: WidgetPoint[]
    /** The population the count is part of (KEV: open findings), and its list. */
    of?: number
    of_drill?: string
  }
  ratio?: {
    num: number
    den: number
    value_pct: number | null
    /** The part not counted, by why (discovery coverage: uncovered assets by cause). */
    causes?: { key: string; value: number; drill?: string }[]
  }
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
    /** The full list's count under the same filter, when the server sends it. */
    total?: number
    rows: Array<{
      id: string
      /** Null or empty when the finding was stored without a title. */
      title: string | null
      severity: string
      priority_class: string
      asset_id?: string
      asset_name?: string
      sla_deadline?: string
      kev: boolean
      /** Exploitation probability, 0 to 1; absent when the feed has no score. */
      epss?: number
    }>
  }
  /** The CTEM loop (ctem.loop). A stage's value is null when not measured. */
  stages?: {
    stages: Array<{
      key: 'scoping' | 'discovery' | 'prioritize' | 'validate' | 'mobilize'
      state: 'good' | 'warn' | 'crit' | 'not_measured'
      reason?: string
      value: number | null
      unit: 'count' | 'percent'
      drill?: string
      flag?: string
      detail?: { key: string; value: number; drill?: string }
    }>
    focus: number | null
  }
  /** The exposure flow (exposure.flow). */
  flow?: FlowValue
  /** The organization's intake (ingest.intake). */
  intake?: IntakeValue
  /** The levers (exposure.levers), best first. */
  levers?: { levers: LeverValue[] }
  /** The weekly brief (brief.weekly). */
  brief?: BriefValue
  /** The KPI strip (exposure.kpis). */
  kpis?: { tiles: KpiTileValue[] }
  /** Attack paths to crown jewels (attack_paths.to_crown_jewels). */
  paths?: {
    reachable: number
    designated: number
    rows: Array<{
      asset_id: string
      name: string
      asset_type: string
      criticality: string
      reachable_from: number
      entry_point: boolean
      depth: number
      score: number
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
    { revalidateOnFocus: false, refreshInterval: dashboardRefreshInterval }
  )
}

/** Poll every 15s while the first fact build runs. */
export const BUILDING_POLL_MS = 15_000
/** Never poll faster than this for a scheduled refresh. */
export const MIN_POLL_MS = 30_000

/**
 * How long until the page should read the figures again: the time to the
 * next scheduled refresh plus 5s (at least 30s); 15s while the first build
 * runs; never for a manual dashboard (no next refresh).
 */
export function dashboardRefreshInterval(
  data: DashboardData | undefined,
  now = Date.now()
): number {
  if (!data) return 0
  if (!data.facts_built_at) return BUILDING_POLL_MS
  if (!data.next_refresh_at) return 0
  const due = Date.parse(data.next_refresh_at)
  if (Number.isNaN(due)) return 0
  return Math.max(MIN_POLL_MS, due - now + 5_000)
}

/** One typed widget computed for the caller's own scope (gallery, config panel). */
export function previewWidget(widgetType: 'metric' | 'note', config: Record<string, unknown>) {
  return post<WidgetValue>('/api/v1/me/dashboards/widget-preview', {
    widget_type: widgetType,
    config,
  })
}
