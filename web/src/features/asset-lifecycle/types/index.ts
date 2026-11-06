/**
 * Types for asset lifecycle management — stale detection, snooze,
 * manual-status-override. Shapes mirror the backend struct
 * `AssetLifecycleSettings` and the worker's `LifecycleRunReport`.
 */

export interface AssetLifecycleSettings {
  enabled: boolean
  stale_threshold_days?: number
  grace_period_days?: number
  manual_reactivation_grace_days?: number
  excluded_source_types?: string[]
  pause_on_integration_failure?: boolean
  dry_run_completed_at?: number | null
  /** Asset liveness thresholds; omitted keeps the stored values. */
  liveness?: AssetLivenessSettings
}

/** Asset liveness settings (zero or absent = the default). */
export interface AssetLivenessSettings {
  close_findings_when_gone: boolean
  unreachable_attempts?: number
  unreachable_window_hours?: number
  gone_attempts?: number
  gone_window_hours?: number
  gone_single_observer_window_hours?: number
  max_gone_per_day?: number
}

/** Defaults and floors of the liveness settings (the API enforces them too). */
export const LIVENESS_DEFAULTS = {
  unreachable_attempts: 3,
  unreachable_window_hours: 72,
  gone_window_hours: 72,
  gone_single_observer_window_hours: 168,
  max_gone_per_day: 50,
} as const

export const LIVENESS_BOUNDS = {
  unreachable_attempts: [2, 20],
  unreachable_window_hours: [24, 2160],
  gone_window_hours: [24, 2160],
  gone_single_observer_window_hours: [72, 2160],
  max_gone_per_day: [1, 5000],
} as const

export type LivenessNumberField = keyof typeof LIVENESS_BOUNDS

export const DEFAULT_LIFECYCLE_SETTINGS: AssetLifecycleSettings = {
  enabled: false,
  stale_threshold_days: 14,
  grace_period_days: 3,
  manual_reactivation_grace_days: 30,
  excluded_source_types: ['manual', 'import'],
  pause_on_integration_failure: true,
}

export const MIN_THRESHOLD_DAYS = 3
export const MAX_THRESHOLD_DAYS = 365
export const MIN_GRACE_DAYS = 0
export const MAX_GRACE_DAYS = 90

export const KNOWN_SOURCE_TYPES = [
  'integration',
  'collector',
  'scanner',
  'manual',
  'import',
] as const

export type KnownSourceType = (typeof KNOWN_SOURCE_TYPES)[number]

/**
 * Worker run report returned by the dry-run endpoint. The same shape
 * is persisted in audit events when the feature is running live.
 */
export interface LifecycleRunReport {
  tenant_id: string
  dry_run: boolean
  enabled: boolean
  skipped: boolean
  skip_reason?: string
  started_at: string
  completed_at: string
  stale_threshold_days: number
  grace_period_days: number
  excluded_source_types: string[]
  transitioned_to_stale: number
  affected_asset_ids?: string[]
  /** What the asset liveness pass would do now. */
  liveness?: {
    states: Record<string, number>
    would_close_findings: number
    would_close_critical: number
    would_reopen_findings: number
    open_on_unreachable: number
    open_on_unresolvable: number
    close_findings_when_gone: boolean
    gone_held: number
  }
}

export interface SnoozeRequest {
  days: number
  /**
   * When true and the asset is currently stale/inactive, the snooze
   * also flips the status back to active. Used when the operator is
   * reactivating an asset the worker demoted by mistake.
   */
  reactivate: boolean
}

/**
 * Preset snooze durations surfaced in the UI dropdown. Custom input
 * remains available via the "Custom" entry that opens a day-count
 * field.
 */
export const SNOOZE_PRESETS: { label: string; days: number }[] = [
  { label: '7 days', days: 7 },
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
  { label: '1 year', days: 365 },
]
