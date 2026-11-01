/**
 * Customizable dashboards (RFC-021 Phase-1b).
 *
 * Types mirror the api dashboards contract (api docs/architecture/dashboards.md):
 * a dashboard is a name + a JSON widget layout, either personal (`/me/dashboards`,
 * the caller's own) or organization (`/organization/dashboards`).
 */

export type DashboardKind = 'personal' | 'organization'
export type DashboardRefreshSchedule = '' | 'manual' | '5m' | '15m' | '1h' | '6h' | 'daily'

export interface DashboardAudienceEntry {
  type: 'role' | 'group'
  id: string
  name?: string
}

export interface DashboardWidget {
  widget_type: string
  x: number
  y: number
  w: number
  h: number
  config?: Record<string, unknown>
}

export interface Dashboard {
  id: string
  name: string
  description?: string
  /** Layout column structure (1..4 equal columns). Defaults to 2. */
  columns?: number
  is_default: boolean
  layout: DashboardWidget[]
  kind?: DashboardKind
  origin?: 'user' | 'builtin' | 'duplicated' | 'shared'
  /** Empty: the organization default. */
  refresh_schedule?: DashboardRefreshSchedule
  refresh_daily_minute?: number
  next_refresh_at?: string
  paused_at?: string
  /**
   * When the exposure flow panel was offered on this dashboard. null: never
   * offered (an existing dashboard); set on every new one.
   */
  flow_panel_at?: string | null
  /** Organization dashboards only. */
  position?: number
  is_org_default?: boolean
  /** Organization dashboards, returned to managers only. */
  audience?: DashboardAudienceEntry[]
  created_at?: string
  updated_at?: string
}

/** The outcome of offering the exposure flow panel on a dashboard. */
export interface FlowPanelResult {
  /** True only when this call put the panel on the layout. */
  added: boolean
  widget_id?: string
  dashboard: Dashboard
}

export interface DashboardListResponse {
  data: Dashboard[]
}

/** GET /api/v1/me/dashboards/home: both lists, the landing dashboard and its figures. */
export interface DashboardHomeResponse {
  personal: Dashboard[]
  /** Absent when the caller cannot read organization dashboards. */
  organization?: Dashboard[]
  landing: { kind: DashboardKind; id: string } | null
  /** The landing dashboard's /data payload; absent when it could not be read. */
  data?: unknown
}

export interface CreateDashboardInput {
  name: string
  description?: string
  columns?: number
  layout: DashboardWidget[]
}

export interface UpdateDashboardInput {
  name: string
  description?: string
  columns?: number
  layout: DashboardWidget[]
}
