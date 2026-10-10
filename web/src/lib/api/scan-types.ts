/**
 * Scan Configuration API Types
 *
 * TypeScript types for Scan Configuration Management
 * Scan configurations bind asset groups with scanners/workflows and schedules.
 */

import type { ScanRun } from './scan-workflow-types'

// Scan types

export const SCAN_TYPES = ['workflow', 'single'] as const
export type ScanType = (typeof SCAN_TYPES)[number]

// Schedule types
export const SCHEDULE_TYPES = [
  'manual',
  'once',
  'daily',
  'weekly',
  'monthly',
  'crontab',
  'rrule',
] as const
export type ScheduleType = (typeof SCHEDULE_TYPES)[number]

// Status types
export const SCAN_CONFIG_STATUSES = ['active', 'paused', 'disabled'] as const
export type ScanConfigStatus = (typeof SCAN_CONFIG_STATUSES)[number]

// Sensor preference types
export const SENSOR_PREFERENCES = ['auto', 'tenant', 'platform'] as const
export type SensorPreference = (typeof SENSOR_PREFERENCES)[number]

// Labels for display
export const SCAN_TYPE_LABELS: Record<ScanType, string> = {
  workflow: 'Workflow',
  single: 'Single check',
}

export const SCHEDULE_TYPE_LABELS: Record<ScheduleType, string> = {
  manual: 'Manual',
  once: 'Once',
  daily: 'Daily',
  weekly: 'Weekly',
  monthly: 'Monthly',
  crontab: 'Custom (Cron)',
  rrule: 'Recurrence rule',
}

export const SCAN_CONFIG_STATUS_LABELS: Record<ScanConfigStatus, string> = {
  active: 'Active',
  paused: 'Paused',
  disabled: 'Disabled',
}

export const SENSOR_PREFERENCE_LABELS: Record<SensorPreference, string> = {
  auto: 'Auto (your sensors first, then platform scanning)',
  tenant: 'Your sensors only',
  platform: 'Platform scanning only',
}

export const SENSOR_PREFERENCE_DESCRIPTIONS: Record<SensorPreference, string> = {
  auto: 'Uses your sensors when they can run the scan, otherwise platform scanning',
  tenant: 'Only uses sensors deployed in your infrastructure',
  platform: "Only uses the platform's shared scanning (public targets)",
}

/**
 * A scanner_config value the API flagged as secret-looking (api RFC-032
 * Phase 0). Only the path and the reason; never the value.
 */
export interface ScannerConfigWarning {
  /** Dotted keys, [n] for list items ("headers.Authorization", "args[2]"). */
  path: string
  reason: 'key_name' | 'known_format' | 'high_entropy' | (string & {})
}

/**
 * How each run resolves the dynamic selectors among a scan's targets
 * (`*.example.com`, CIDRs) from the inventory (RFC-068). All optional:
 * absent = CIDRs swept, active assets only, no freshness window.
 */
export interface ScanTargetOptions {
  /** `sweep` hands a CIDR to the scanner whole; `inventory` scans the known hosts in it. */
  cidr_mode?: 'sweep' | 'inventory'
  /** Only assets seen in the last N days (0-365; 0 or absent = any). */
  seen_within_days?: number
  /** Also take assets marked stale or inactive (archived ones never). */
  include_stale?: boolean
}

/** What one selector added to a run when it started. */
export interface RunTargetExpansion {
  selector: string
  kind: 'wildcard' | 'cidr'
  /** Inventory assets it covered (at most the cap). */
  matched: number
  /** More assets than one selector may add; the most recently seen were taken. */
  capped?: boolean
  /** Up to 10 names, most recently seen first. */
  sample?: string[]
}

/**
 * Scan Configuration entity
 */
export interface ScanConfig {
  id: string
  tenant_id: string
  name: string
  /** An unsaved quick scan: not listed as a configuration until saved. */
  ad_hoc?: boolean
  description?: string
  asset_group_id?: string // Legacy single asset group
  asset_group_ids?: string[] // Multiple asset groups
  targets?: string[] // Direct targets (individual assets or custom)
  /** How the run resolves `*.x` and CIDR targets (RFC-068). */
  target_options?: ScanTargetOptions
  scan_type: ScanType
  scan_workflow_id?: string
  scanner_name?: string
  scanner_config?: Record<string, unknown>
  /** scanner_config values that look like secrets (never blocks a save). */
  scanner_config_warnings?: ScannerConfigWarning[]
  targets_per_job: number
  schedule_type: ScheduleType
  schedule_cron?: string
  /** RFC 5545 rule (RRULE parts) of an rrule schedule, in the scan timezone. */
  schedule_rrule?: string
  schedule_day?: number
  schedule_time?: string
  schedule_timezone: string
  /** The one run of a once schedule (RFC 3339, UTC). */
  schedule_run_at?: string
  next_run_at?: string
  tags?: string[]
  run_on_tenant_runner: boolean
  sensor_preference: SensorPreference
  /** Scan zone the scan is restricted to; absent = Automatic (narrowest zone). RFC-023 D5. */
  scan_zone_id?: string | null
  profile_id?: string
  timeout_seconds: number
  /** Maximum automatic retry attempts (0 = no retry, max 10) */
  max_retries: number
  /** Initial backoff between retries in seconds (10-86400). Actual delay is exponential per attempt. */
  retry_backoff_seconds: number
  status: ScanConfigStatus
  last_run_id?: string
  last_run_at?: string
  last_run_status?: ScanLastRunStatus
  total_runs: number
  successful_runs: number
  failed_runs: number
  /** Runs that kept results but lost some work; neither a success nor a failure. */
  partial_runs?: number
  /** Triggers refused before anything was dispatched (runs with status blocked). */
  blocked_runs?: number
  /** The scan's latest run, with its real state (the list's "Last run" column). */
  last_run?: ScanLastRun
  /** Name of the workflow a workflow scan runs. */
  scan_workflow_name?: string
  created_by?: string
  created_by_name?: string
  created_at: string
  updated_at: string
}

/** A scan's latest run as the scan list carries it (GET /scans). */
export interface ScanLastRun {
  id: string
  status: string
  trigger_type?: string
  created_at: string
  started_at?: string
  completed_at?: string
  /** 0-100 for a live run (finished tasks of all tasks). */
  progress?: number
  /** Why a blocked run was refused, and the message of a blocked or failed run. */
  refusal_code?: string
  error_message?: string
}

/**
 * Scan Configuration with related entities
 */
export interface ScanConfigWithRelations extends ScanConfig {
  asset_group?: {
    id: string
    name: string
  }
  workflow?: {
    id: string
    name: string
  }
}

/**
 * Create scan configuration request
 * Either asset_group_id/asset_group_ids OR targets must be provided (can have any combination)
 */
export interface CreateScanConfigRequest {
  name: string
  description?: string
  asset_group_id?: string // Primary asset group (legacy, optional)
  asset_group_ids?: string[] // Multiple asset groups (NEW)
  targets?: string[] // Direct targets (domains, IPs, URLs)
  /** Inventory assets to scan, named by the API (at most 1000 with targets). */
  asset_ids?: string[]
  /** How each run resolves `*.x` and CIDR targets (RFC-068). */
  target_options?: ScanTargetOptions
  scan_type: ScanType
  scan_workflow_id?: string
  scanner_name?: string
  scanner_config?: Record<string, unknown>
  targets_per_job?: number
  schedule_type?: ScheduleType
  schedule_cron?: string
  /** RFC 5545 rule (RRULE parts) of an rrule schedule, in the scan timezone. */
  schedule_rrule?: string
  schedule_day?: number
  schedule_time?: string
  /** The one run of a once schedule (RFC 3339), a minute to a year ahead. */
  run_at?: string
  timezone?: string
  tags?: string[]
  run_on_tenant_runner?: boolean
  sensor_preference?: SensorPreference
  /** Restrict the scan to one scan zone; omit for Automatic. */
  scan_zone_id?: string | null
  profile_id?: string
  /** Max execution time in seconds (min 30, max 86400, default 3600) */
  timeout_seconds?: number
  /** Maximum automatic retry attempts (0 = no retry, max 10) */
  max_retries?: number
  /** Initial backoff seconds (10-86400, default 60). Exponential per attempt. */
  retry_backoff_seconds?: number
}

/**
 * Update scan configuration request
 */
export interface UpdateScanConfigRequest {
  name?: string
  description?: string
  /** Omitted = unchanged; `{}` resets every option to its default. */
  target_options?: ScanTargetOptions
  scan_workflow_id?: string
  scanner_name?: string
  scanner_config?: Record<string, unknown>
  targets_per_job?: number
  schedule_type?: ScheduleType
  schedule_cron?: string
  /** RFC 5545 rule (RRULE parts) of an rrule schedule, in the scan timezone. */
  schedule_rrule?: string
  schedule_day?: number
  schedule_time?: string
  /** The one run of a once schedule (RFC 3339), a minute to a year ahead. */
  run_at?: string
  timezone?: string
  tags?: string[]
  run_on_tenant_runner?: boolean
  sensor_preference?: SensorPreference
  /** Scan zone; empty string or null = Automatic, omit to leave unchanged */
  scan_zone_id?: string | null
  /** Pass empty string to unlink the profile, omit to leave unchanged */
  profile_id?: string
  /** Max execution time in seconds (min 30, max 86400) */
  timeout_seconds?: number
  /** Maximum automatic retry attempts (0 = disable retry, max 10) */
  max_retries?: number
  /** Initial backoff seconds between retries (10-86400) */
  retry_backoff_seconds?: number
}

/**
 * Trigger scan request
 */
export interface TriggerScanRequest {
  context?: Record<string, unknown>
}

/**
 * Clone config request
 */
export interface CloneScanConfigRequest {
  name: string
}

/**
 * Bulk action request
 */
export interface BulkActionRequest {
  scan_ids: string[]
}

/**
 * Bulk action response
 */
export interface BulkActionResponse {
  successful: string[]
  failed: Array<{
    id: string
    error: string
  }>
  message: string
}

/**
 * Bulk action types
 */
export type BulkAction = 'activate' | 'pause' | 'disable' | 'delete'

/**
 * Scan configuration list filters
 */
export interface ScanConfigListFilters {
  asset_group_id?: string
  scan_workflow_id?: string
  scan_type?: ScanType
  schedule_type?: ScheduleType
  status?: ScanConfigStatus
  tags?: string
  search?: string
  /** Also list one-off (ad-hoc quick) scans; hidden by default. */
  include_ad_hoc?: boolean
  /** One sort key, `-` for descending (name, created_at, last_run_at, next_run_at, total_runs). */
  sort?: string
  page?: number
  per_page?: number
}

/**
 * Scan configuration list response
 */
export interface ScanConfigListResponse {
  data: ScanConfig[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/**
 * Scan configuration stats data
 */
export interface ScanConfigStatsData {
  total: number
  active: number
  paused: number
  disabled: number
  by_schedule_type: Record<ScheduleType, number>
  by_scan_type: Record<ScanType, number>
}

/**
 * A scan run. Scan runs are workflow runs; the one run type lives in
 * workflow-types (statuses typed as the API spells them).
 */
export type { ScanRun } from './scan-workflow-types'

/** A target a run did not scan, with the reason. */
export interface RunUncoveredTarget {
  target: string
  reason: string
}

/** One zone's share of a run. */
export interface RunZoneRoute {
  zone_id: string
  zone_name: string
  targets: number
  jobs: number
  /** Jobs waiting for a healthy sensor of the zone. */
  queued_jobs: number
  /** Sensors the jobs were pinned to. */
  sensor_ids: string[]
}

export interface RunZoneRouting {
  jobs?: number
  targets_per_job?: number
  unzoned_targets: number
  uncovered_targets: number
  /** Workflow runs: the one zone the run is bound to. */
  zone_id?: string
  /** The zone the scan was restricted to (zone picker), when not Automatic. */
  selected_zone_id?: string
  zones?: RunZoneRoute[]
}

/** GET /scan-runs/{id} `dispatch`: present when the trigger recorded one. */
export interface RunDispatch {
  resolved_targets: number
  excluded_targets: number
  warnings?: string[]
  /** First 100. */
  uncovered_targets?: RunUncoveredTarget[]
  zone_routing?: RunZoneRouting
  sensor_routing?: 'tenant' | 'platform'
  /** What each `*.x` or inventory-mode CIDR target added when the run started (RFC-068). */
  target_expansion?: RunTargetExpansion[]
}

/**
 * Status counts for overview dashboard
 */
export interface StatusCounts {
  total: number
  queued: number
  pending: number
  running: number
  completed: number
  failed: number
  canceled: number
  timeout: number
}

/**
 * Overview stats for scan management dashboard
 */
export interface ScanManagementOverview {
  scan_runs: StatusCounts
  scans: StatusCounts
  jobs: StatusCounts
}

/** Status of a scan's last run. */
export type ScanLastRunStatus =
  | 'queued'
  | 'pending'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'canceled'
  | 'timeout'
  | 'blocked'

/**
 * Quality gate evaluation result returned by the backend after a scan run
 * completes if the parent scan was linked to a profile with a quality gate.
 */
export interface QualityGateResult {
  passed: boolean
  reason?: string
  breaches?: Array<{
    metric: string // "critical", "high", "medium", "total"
    limit: number
    actual: number
  }>
  counts?: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
    total: number
  }
}

// ============================================
// SMART FILTERING (Asset-Scanner Compatibility)
// ============================================

/**
 * Skip reason explaining why assets of a certain type were skipped
 */
export interface SkipReason {
  asset_type: string
  count: number
  reason: string
}

/**
 * Result of smart filtering during scan trigger
 * Matches backend FilteringResultResponse
 */
export interface FilteringResult {
  total_assets: number
  scanned_assets: number
  skipped_assets: number
  unclassified_assets: number
  compatibility_percent: number
  scanned_by_type?: Record<string, number>
  skipped_by_type?: Record<string, number>
  skip_reasons?: SkipReason[]
  was_filtered: boolean
  tool_name?: string
  supported_targets?: string[]
}

/**
 * Extended ScanRun with filtering result
 */
export interface ScanRunWithFiltering extends ScanRun {
  filtering_result?: FilteringResult
}
